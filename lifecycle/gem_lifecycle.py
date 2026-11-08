#!/usr/bin/env python3
"""gem_lifecycle — wake/sleep controller and GPU spend caps for the dedicated Fireworks deployment (WU-07).

Runs on awsbox next to LiteLLM (systemd unit: lifecycle/gem-lifecycle.service). Stdlib only.

  gem_lifecycle.py serve    controller loop + HTTP API (default 127.0.0.1:8090)
  gem_lifecycle.py check    startup checks against the live deployment; exit 3 on a hard failure
  gem_lifecycle.py dryrun   replay the WU-07 gate scenarios on a simulated deployment and clock

Policy (decisions of 2026-11-07):
  * Serverless is the default. The B200 wakes only for `gemctl heavy on` or a 429 storm on ds-main.
  * Sleep 180 s after the last request finishes, 45 s after the last Claude Code session ends, and at once
    on `heavy off`. The controller forces this through Fireworks' scale API
    (PATCH /v1/{deployment}:scale). Fireworks' own scale-to-zero window (minimum 5 min) is only the
    backstop for when this process is down.
  * Spend: GPU-seconds = live replicas x accelerators x elapsed time, priced at GEM_GPU_RATE_USD_PER_HOUR.
    The daily ($26) and weekly ($78) caps force the deployment to zero and refuse wakes until the period
    rolls over. Periods follow GEM_CAP_TZ (default America/Chicago); weeks start on Monday.
  * Guard: wakes stay disabled while unused auto-delete is not verifiably off, while the deployment is
    deleting, expiring or failed, or while min replicas is above zero. Sleep and caps keep working.
  * Restarts: the ledger, the last replica count, in-flight requests and sessions are persisted (fsynced). The
    first look after a restart bills the whole unobserved gap at the larger of the saved and current replica
    count. An unreadable ledger refuses wakes until the next weekly rollover instead of restarting at $0.
  * Clocks: accrual inside a process uses the monotonic clock; a wall-clock step moves every timer with it.
  * API roles: GEM_LIFECYCLE_TOKEN (operator, everything), GEM_LIFECYCLE_FEED_TOKEN (LiteLLM callback: /touch,
    /signal/429), GEM_LIFECYCLE_SESSION_TOKEN (Claude Code hooks: /session/*, GET /status).
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import hmac
import io
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None  # type: ignore[assignment]

__version__ = "1.1.0"
API_BASE = "https://api.fireworks.ai"
DEPLOYMENT_RE = re.compile(r"^accounts/[\w.-]+/deployments/[\w.-]+$")
_DUR_PART = re.compile(r"(\d+(?:\.\d+)?)(h|ms|m|s)")
CLOCK_STEP_S = 5.0          # wall and monotonic deltas further apart than this are a clock step
LOOP_SLACK_S = 60.0         # most a slow loop iteration adds to poll_s (GET, scale and recheck timeouts, firectl)
MAX_TRACKED = 1000          # sessions and in-flight requests each; more get 429
ENDED_KEEP = 512            # recently ended call ids remembered (each for 2 x the request lease)
MAX_DELAY_S = 86400.0
ROUTE_ROLES: Dict[Tuple[str, str], Tuple[str, ...]] = {
    ("GET", "/status"): ("operator", "session"),
    ("POST", "/wake"): ("operator",),
    ("POST", "/sleep"): ("operator",),
    ("POST", "/heavy"): ("operator",),
    ("POST", "/check"): ("operator",),
    ("POST", "/session/start"): ("operator", "session"),
    ("POST", "/session/end"): ("operator", "session"),
    ("POST", "/touch"): ("operator", "feed"),
    ("POST", "/signal/429"): ("operator", "feed"),
}


# --------------------------------------------------------------------------- helpers

def parse_duration(value: Any) -> Optional[float]:
    """Seconds from a proto/JSON duration ("300s", "1h", "168h0m0s", 300, {"seconds": 300}); None if unset."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"unparseable duration {value!r}")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        return float(value.get("seconds", 0)) + float(value.get("nanos", 0)) / 1e9
    s = str(value).strip().lower()
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        return float(s)
    parts = _DUR_PART.findall(s)
    if not parts or _DUR_PART.sub("", s):
        raise ValueError(f"unparseable duration {value!r}")
    return sum(float(n) * {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}[u] for n, u in parts)


def _tz(name: str):
    if name.upper() == "UTC" or ZoneInfo is None:
        return dt.timezone.utc
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - unknown zone or no tzdata; validate() refuses to serve with it
        return dt.timezone.utc


if hasattr(time, "CLOCK_BOOTTIME"):
    def boottime() -> float:
        """Monotonic (immune to wall-clock steps) but, unlike CLOCK_MONOTONIC, it keeps counting while the host
        is suspended, and so does Fireworks' meter."""
        return time.clock_gettime(time.CLOCK_BOOTTIME)
else:  # pragma: no cover - not Linux
    boottime = time.monotonic


def tz_known(name: str) -> bool:
    if name.upper() == "UTC":
        return True
    if ZoneInfo is None or not name:
        return False
    try:
        ZoneInfo(name)
        return True
    except Exception:  # noqa: BLE001
        return False


def period_keys(ts: float, tzname: str) -> Tuple[str, str]:
    d = dt.datetime.fromtimestamp(ts, _tz(tzname))
    year, week, _ = d.isocalendar()
    return f"day:{d.date().isoformat()}", f"week:{year}-W{week:02d}"


def next_rollover(ts: float, tzname: str, period: str) -> float:
    tz = _tz(tzname)
    d = dt.datetime.fromtimestamp(ts, tz)
    start = dt.datetime(d.year, d.month, d.day, tzinfo=tz)
    days = 1 if period == "day" else 7 - d.weekday()
    return (start + dt.timedelta(days=days)).timestamp()


def iso(ts: Optional[float]) -> Optional[str]:
    if ts is None or not math.isfinite(ts):
        return None
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_autodelete(obj: Any) -> Tuple[bool, Any]:
    """Find an unused-auto-delete field anywhere in a deployment document (name varies by surface)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            norm = re.sub(r"[^a-z]", "", str(k).lower())
            if "autodelete" in norm:
                return True, v
        for v in obj.values():
            found, val = find_autodelete(v)
            if found:
                return True, val
    elif isinstance(obj, list):
        for v in obj:
            found, val = find_autodelete(v)
            if found:
                return True, val
    return False, None


# --------------------------------------------------------------------------- config

def _plain(raw: Optional[str]) -> str:
    """systemd's EnvironmentFile= keeps an inline "# comment" in the value; numbers and zone names never hold '#'."""
    return (raw or "").split("#", 1)[0].strip()


def _float(env: Dict[str, str], key: str, default: float, errors: List[str]) -> float:
    raw = _plain(env.get(key))
    if raw == "":
        return default
    try:
        val = float(raw)
    except ValueError:
        errors.append(f"{key} must be a number (got {env.get(key)!r})")
        return default
    if not math.isfinite(val):
        errors.append(f"{key} must be a finite number")
        return default
    return val


@dataclasses.dataclass
class Config:
    deployment: str
    api_key: str = ""
    gpu_rate_usd_per_hour: float = 13.0     # ASSUMPTION: B200 on Fireworks after the Sept 2026 increase
    cap_day_usd: float = 26.0
    cap_week_usd: float = 78.0
    idle_sleep_s: float = 180.0
    session_end_sleep_s: float = 45.0
    poll_s: float = 15.0
    wake_reserve_s: float = 300.0           # replica-seconds that must fit under both caps to allow a wake
    wake_timeout_s: float = 900.0           # give up on a cold start that never becomes ready
    storm_count: int = 3                    # ds-main 429s ...
    storm_window_s: float = 120.0           # ... within this window wake the B200
    request_lease_s: float = 660.0          # an in-flight request older than this is treated as finished
    session_ttl_s: float = 12 * 3600.0
    recheck_s: float = 3600.0
    default_gpus: int = 4
    tz: str = "America/Chicago"
    bind: str = "127.0.0.1:8090"
    token: str = ""                         # operator: every endpoint
    feed_token: str = ""                    # LiteLLM callback: /touch, /signal/429
    session_token: str = ""                 # Claude Code hooks: /session/start, /session/end, GET /status
    state_path: Optional[str] = None
    autodelete_verified: bool = False
    autodelete_accept_risk: bool = False
    dry: bool = False
    api_base: str = API_BASE
    env_errors: List[str] = dataclasses.field(default_factory=list, repr=False)

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "Config":
        e = dict(os.environ if env is None else env)
        errors: List[str] = []
        dep = (e.get("GEM_BURST_DEPLOYMENT") or e.get("GEM_BURST_MODEL") or "").strip()
        dep = re.sub(r"^(openai|fireworks_ai)/", "", dep)
        home = os.path.expanduser(e.get("GEM_HOME", "~/.gem"))
        return cls(
            deployment=dep,
            api_key=e.get("FIREWORKS_API_KEY", ""),
            gpu_rate_usd_per_hour=_float(e, "GEM_GPU_RATE_USD_PER_HOUR", 13.0, errors),
            cap_day_usd=_float(e, "GEM_GPU_CAP_DAY_USD", 26.0, errors),
            cap_week_usd=_float(e, "GEM_GPU_CAP_WEEK_USD", 78.0, errors),
            idle_sleep_s=_float(e, "GEM_IDLE_SLEEP_S", 180.0, errors),
            session_end_sleep_s=_float(e, "GEM_SESSION_END_SLEEP_S", 45.0, errors),
            poll_s=_float(e, "GEM_POLL_S", 15.0, errors),
            wake_reserve_s=_float(e, "GEM_WAKE_RESERVE_S", 300.0, errors),
            storm_count=int(_float(e, "GEM_429_WAKE_COUNT", 3, errors)),
            storm_window_s=_float(e, "GEM_429_WINDOW_S", 120.0, errors),
            request_lease_s=_float(e, "GEM_REQUEST_LEASE_S", 660.0, errors),
            default_gpus=int(_float(e, "GEM_GPUS_PER_REPLICA", 4, errors)),
            tz=_plain(e.get("GEM_CAP_TZ")) or "America/Chicago",
            bind=e.get("GEM_LIFECYCLE_BIND", "127.0.0.1:8090"),
            token=e.get("GEM_LIFECYCLE_TOKEN", ""),
            feed_token=e.get("GEM_LIFECYCLE_FEED_TOKEN", ""),
            session_token=e.get("GEM_LIFECYCLE_SESSION_TOKEN", ""),
            state_path=e.get("GEM_LIFECYCLE_STATE") or os.path.join(home, "lifecycle.json"),
            autodelete_verified=e.get("GEM_AUTODELETE_VERIFIED", "") == "1",
            autodelete_accept_risk=e.get("GEM_AUTODELETE_ACCEPT_RISK", "") == "1",
            dry=e.get("GEM_LIFECYCLE_DRY", "") == "1",
            api_base=(e.get("GEM_FIREWORKS_API_BASE") or API_BASE).rstrip("/"),
            env_errors=errors,
        )

    def role_tokens(self) -> Dict[str, str]:
        return {"operator": self.token, "feed": self.feed_token, "session": self.session_token}

    def validate(self) -> List[str]:
        errs = list(self.env_errors)
        if not DEPLOYMENT_RE.match(self.deployment):
            errs.append("GEM_BURST_DEPLOYMENT must look like accounts/<acct>/deployments/<id>")
        for name in ("cap_day_usd", "cap_week_usd", "gpu_rate_usd_per_hour", "poll_s", "idle_sleep_s",
                     "request_lease_s"):
            if getattr(self, name) <= 0:
                errs.append(f"{name} must be positive")
        if self.cap_week_usd < self.cap_day_usd:
            errs.append("weekly cap is below the daily cap")
        if not tz_known(self.tz):
            errs.append(f"GEM_CAP_TZ={self.tz!r} is not a known time zone (install tzdata, or set UTC)")
        if self.api_base != API_BASE and not re.match(r"^http://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", self.api_base):
            errs.append("GEM_FIREWORKS_API_BASE may only point at a loopback test server (the API key goes there)")
        names = {"operator": "GEM_LIFECYCLE_TOKEN", "feed": "GEM_LIFECYCLE_FEED_TOKEN",
                 "session": "GEM_LIFECYCLE_SESSION_TOKEN"}
        seen: Dict[str, str] = {}
        for role, tok in self.role_tokens().items():
            if not tok:
                continue
            if len(tok) < 16 or re.search(r"[\s#]", tok):
                errs.append(f"{names[role]} must be at least 16 characters with no whitespace or '#'")
            if tok in seen:
                errs.append(f"{names[role]} must differ from {names[seen[tok]]} (each role gets its own token)")
            seen.setdefault(tok, role)
        return errs


# --------------------------------------------------------------------------- Fireworks

class FireworksError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class FireworksClient:
    """GET the deployment and set its replica count. Docs: api-reference/get-deployment, scale-deployment."""

    def __init__(self, deployment: str, api_key: str, base: str = API_BASE, timeout: float = 10.0):
        self.deployment, self.api_key, self.base, self.timeout = deployment, api_key, base.rstrip("/"), timeout

    def _req(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self.base}/v1/{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
                     "User-Agent": f"gem-lifecycle/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - fixed https base
                raw = r.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", "replace")
            raise FireworksError(f"{method} {path}: HTTP {exc.code}: {detail}", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise FireworksError(f"{method} {path}: {exc}") from None

    def get(self) -> dict:
        return self._req("GET", self.deployment)

    def scale(self, replicas: int) -> None:
        self._req("PATCH", f"{self.deployment}:scale", {"replicaCount": int(replicas)})


@dataclasses.dataclass(frozen=True)
class Snapshot:
    state: str
    replicas: int
    desired: int
    min_replicas: int
    max_replicas: int
    gpus: int
    scale_to_zero_s: Optional[float]

    @property
    def up(self) -> bool:
        return self.replicas > 0

    @property
    def active(self) -> bool:
        return self.replicas > 0 or self.desired > 0

    @property
    def label(self) -> str:
        if self.up:
            return "ready" if self.state in ("READY", "UPDATING") else self.state.lower()
        return "waking" if self.desired > 0 else "asleep"

    @classmethod
    def from_api(cls, d: dict, default_gpus: int) -> "Snapshot":
        asp = d.get("autoscalingPolicy") or {}
        try:
            window = parse_duration(asp.get("scaleToZeroWindow"))
        except ValueError:
            window = None
        return cls(state=str(d.get("state") or "STATE_UNSPECIFIED"),       # proto3 JSON omits zero values
                   replicas=int(d.get("replicaCount") or 0),
                   desired=int(d.get("desiredReplicaCount") or 0),
                   min_replicas=int(d.get("minReplicaCount") or 0),
                   max_replicas=int(d.get("maxReplicaCount") or 0),
                   gpus=int(d.get("acceleratorCount") or default_gpus),
                   scale_to_zero_s=window)


# --------------------------------------------------------------------------- startup checks

@dataclasses.dataclass
class CheckReport:
    hard: List[str]
    warn: List[str]
    info: Dict[str, Any]

    @property
    def ok(self) -> bool:
        return not self.hard

    def as_dict(self) -> dict:
        return {"ok": self.ok, "hard": self.hard, "warn": self.warn, "info": self.info}


def check_deployment(doc: dict, cfg: Config, firectl_doc: Optional[dict] = None) -> CheckReport:
    hard: List[str] = []
    warn: List[str] = []
    info: Dict[str, Any] = {}
    dep = cfg.deployment
    snap = Snapshot.from_api(doc, cfg.default_gpus)
    info["state"], info["gpus_per_replica"] = snap.state, snap.gpus
    info["usd_per_replica_hour"] = round(snap.gpus * cfg.gpu_rate_usd_per_hour, 2)

    if snap.state in ("DELETING", "DELETED", "FAILED"):
        hard.append(f"deployment state is {snap.state}; recover it with `firectl deployment undelete {dep}` "
                    "or recreate it")
    if doc.get("deleteTime") or doc.get("purgeTime"):
        hard.append(f"deployment is scheduled for deletion (deleteTime={doc.get('deleteTime')}); "
                    f"`firectl deployment undelete {dep}` before the purge time")
    if doc.get("expireTime"):
        hard.append(f"deployment expires at {doc.get('expireTime')}; remove the expiry before relying on it")
    if snap.min_replicas > 0:
        hard.append(f"minReplicaCount is {snap.min_replicas}: the GPU never scales to zero and bills "
                    f"continuously. Run: firectl deployment update {dep} --min-replica-count 0")

    recreate = (f"firectl deployment update cannot change it (create-time setting). Recreate the deployment "
                f"with `firectl deployment create ... --unused-auto-delete-duration 0`, or set "
                f"GEM_AUTODELETE_ACCEPT_RISK=1 and use the B200 at least once a week")
    found, val, source = (*find_autodelete(doc), "deployment API")
    if not found and firectl_doc:
        found, val = find_autodelete(firectl_doc)
        source = "firectl"
    if found:
        try:
            secs = parse_duration(val) or 0.0
        except ValueError:
            secs = -1.0
        if secs != 0.0:
            msg = (f"unused auto-delete is {val!r} ({source}): Fireworks deletes the deployment after that long "
                   f"without traffic. {recreate}")
            (warn if cfg.autodelete_accept_risk else hard).append(msg)
        else:
            info["auto_delete"] = f"disabled ({source})"
    elif cfg.autodelete_verified:
        info["auto_delete"] = "disabled (operator verified: GEM_AUTODELETE_VERIFIED=1)"
    elif cfg.autodelete_accept_risk:
        info["auto_delete"] = "unknown; risk accepted (GEM_AUTODELETE_ACCEPT_RISK=1)"
        warn.append("unused auto-delete can't be read from the Fireworks API; if the deployment was created with the "
                    "default (7 days), a week without B200 traffic deletes it. `firectl deployment undelete` "
                    "recovers a soft-deleted deployment before its purge time")
    else:
        hard.append("cannot confirm unused auto-delete is off: the Fireworks API does not report it. If the "
                    "deployment was created with --unused-auto-delete-duration 0, set GEM_AUTODELETE_VERIFIED=1. "
                    f"Otherwise: {recreate}")

    if snap.scale_to_zero_s is None:
        warn.append("scale-to-zero window not reported; if this controller stops, Fireworks' default (1 h) applies")
    elif snap.scale_to_zero_s > 600:
        idle_cost = snap.scale_to_zero_s / 3600 * snap.gpus * cfg.gpu_rate_usd_per_hour
        warn.append(f"Fireworks scale-to-zero backstop is {snap.scale_to_zero_s / 60:.0f} min (about "
                    f"${idle_cost:.0f} of idle GPU if this controller is down). "
                    f"Run: firectl deployment update {dep} --scale-to-zero-window 5m")
    if snap.max_replicas > 1:
        warn.append(f"maxReplicaCount is {snap.max_replicas}: each extra replica bills "
                    f"${snap.gpus * cfg.gpu_rate_usd_per_hour:.0f}/h against the same caps")
    info["rate_note"] = (f"priced at ${cfg.gpu_rate_usd_per_hour}/GPU-hour (GEM_GPU_RATE_USD_PER_HOUR); "
                         "confirm on fireworks.ai/pricing")
    return CheckReport(hard, warn, info)


def firectl_get(deployment: str, timeout: float = 20.0) -> Optional[dict]:
    exe = shutil.which("firectl")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "get", "deployment", deployment, "-o", "json"], capture_output=True,
                           text=True, timeout=timeout, check=False)
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# --------------------------------------------------------------------------- controller

def _opt_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    f = float(v)
    if not math.isfinite(f):
        raise ValueError(f"non-finite timestamp {v!r}")
    return f


def _recent(d: Any, now: float, ttl: float) -> Dict[str, float]:
    """Persisted {id: timestamp} entries still inside their TTL, newest MAX_TRACKED kept."""
    if d is None:
        return {}
    if not isinstance(d, dict):
        raise ValueError("expected an object of timestamps")
    live = sorted(((str(k), float(v)) for k, v in d.items()), key=lambda kv: kv[1])
    return dict([kv for kv in live if now - kv[1] <= ttl][-MAX_TRACKED:])


class Lifecycle:
    """All policy lives here. Thread-safe; the HTTP layer and the poll loop both call into it.

    `clock` is the wall clock (cap periods, persisted timestamps). `mono` measures elapsed time inside this
    process: by default boottime() for the real clock; a simulated wall clock brings its own as `clock.mono`.
    """

    def __init__(self, cfg: Config, client: Any, clock: Callable[[], float] = time.time,
                 out: Optional[io.TextIOBase] = None, firectl: Callable[[str], Optional[dict]] = firectl_get,
                 mono: Optional[Callable[[], float]] = None):
        if mono is None:                                 # a custom clock without .mono: no step detection
            mono = boottime if clock is time.time else getattr(clock, "mono", clock)
        self.cfg, self.client, self.clock, self.mono = cfg, client, clock, mono
        self.out, self.firectl = out, firectl
        self.lock = threading.RLock()
        self.snapshot: Optional[Snapshot] = None
        self.gpu_seconds: Dict[str, float] = {}
        self.last_tick: Optional[float] = None           # wall time of the last accrual (persisted)
        self.last_traffic: Optional[float] = None
        self.ready_since: Optional[float] = None
        self.wake_at: Optional[float] = None
        self.wake_reason: Optional[str] = None
        self.last_down_at: Optional[float] = None
        self.heavy = False
        self.sleep_at: Optional[float] = None
        self.sleep_reason: Optional[str] = None
        self.sleep_requested_at: Optional[float] = None
        self.sessions: Dict[str, float] = {}
        self.inflight: Dict[str, float] = {}
        self.ended: "collections.OrderedDict[str, float]" = collections.OrderedDict()   # call id -> ended at
        self.storm: Deque[float] = collections.deque()
        self.capped: Optional[str] = None
        self.ledger_lost_until: Optional[float] = None   # set when the persisted ledger could not be read
        self.wake_disabled: Optional[str] = "startup checks have not run"
        self.report: Optional[CheckReport] = None
        self.api_errors = 0
        self.loop_period_s: Optional[float] = None       # last measured interval between ticks (monotonic)
        self.saved_replicas = 0                          # what the previous process last saw (replicas or desired)
        self.saved_gpus = 0
        self.events: Deque[dict] = collections.deque(maxlen=100)
        self.scale_calls: List[Tuple[float, int, str]] = []
        self._first_accrual = True                       # first look since this process started
        self._resume_reason: Optional[str] = None        # wake intent persisted by a previous process
        self._ref: Optional[Tuple[float, float]] = None  # (wall, mono) at the last clock read
        self._tick_mono: Optional[float] = None          # mono at the last accrual
        self._load()

    # ---- clocks
    def _now(self) -> float:
        """Wall time, after moving every timer along with any wall-clock step since the last read."""
        wall, mono = self.clock(), self.mono()
        if self._ref is not None:
            step = (wall - self._ref[0]) - (mono - self._ref[1])
            if abs(step) > CLOCK_STEP_S:
                self._shift(step)
                self._log("clock_step", step_s=round(step, 1),
                          note="wall clock stepped; timers moved with it, metering uses the monotonic clock")
        self._ref = (wall, mono)
        return wall

    def _shift(self, step: float) -> None:
        for name in ("last_tick", "last_traffic", "ready_since", "wake_at", "sleep_at", "sleep_requested_at",
                     "last_down_at"):
            val = getattr(self, name)
            if val is not None:
                setattr(self, name, val + step)
        for table in (self.inflight, self.sessions, self.ended):
            for key in table:
                table[key] += step
        self.storm = collections.deque(t + step for t in self.storm)

    # ---- logging and persistence
    def _log(self, event: str, **fields: Any) -> None:
        rec = {"ts": iso(self.clock()), "event": event, **fields}
        self.events.append(rec)
        stream = self.out if self.out is not None else sys.stdout
        try:
            stream.write(json.dumps(rec, sort_keys=True) + "\n")
            stream.flush()
        except (OSError, ValueError):
            pass

    def _load(self) -> None:
        path = self.cfg.state_path
        if not path or not os.path.exists(path):         # first install: nothing has been metered yet
            return
        now = self.clock()
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
            if not raw.strip():
                raise ValueError("state file is empty")
            st = json.loads(raw)
            if not isinstance(st, dict) or not isinstance(st.get("gpu_seconds"), dict):
                raise ValueError("state file has no spend ledger")
            gpu_seconds = {str(k): float(v) for k, v in st["gpu_seconds"].items()}
            last_tick, last_traffic = _opt_float(st.get("last_tick")), _opt_float(st.get("last_traffic"))
            lost_until = _opt_float(st.get("ledger_lost_until"))
            replicas = max(int(st.get("replicas") or 0), int(st.get("desired") or 0))
            gpus = int(st.get("gpus") or 0)
            inflight = _recent(st.get("inflight"), now, self.cfg.request_lease_s)
            sessions = _recent(st.get("sessions"), now, self.cfg.session_ttl_s)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            aside: Optional[str] = f"{path}.corrupt-{int(now)}"
            try:
                os.replace(path, aside)  # type: ignore[arg-type]
            except OSError:
                aside = None
            self.ledger_lost_until = next_rollover(now, self.cfg.tz, "week")
            self._log("state_unreadable", severity="CRITICAL", detail=str(exc), moved_to=aside,
                      ledger_lost_until=iso(self.ledger_lost_until),
                      note="spend ledger lost: wakes are refused until the weekly rollover; check Fireworks billing")
            self._save()
            return
        self.gpu_seconds, self.last_tick, self.last_traffic = gpu_seconds, last_tick, last_traffic
        self.heavy = bool(st.get("heavy"))
        self._resume_reason = st.get("wake_reason") or ("heavy" if self.heavy else None)
        self.saved_replicas, self.saved_gpus, self.ledger_lost_until = replicas, gpus, lost_until
        self.inflight, self.sessions = inflight, sessions

    def _save(self) -> None:
        path = self.cfg.state_path
        if not path:
            return
        now = self.clock()
        keep = set()
        for back in range(0, 22):
            keep.update(period_keys(now - back * 86400, self.cfg.tz))
        self.gpu_seconds = {k: v for k, v in self.gpu_seconds.items() if k in keep}
        snap = self.snapshot
        st = {"version": 2, "gpu_seconds": self.gpu_seconds, "last_tick": self.last_tick,
              "last_traffic": self.last_traffic, "heavy": self.heavy,
              "wake_reason": self.wake_reason or self._resume_reason,
              "replicas": snap.replicas if snap else self.saved_replicas, "desired": snap.desired if snap else 0,
              "gpus": snap.gpus if snap else self.saved_gpus,
              "inflight": self.inflight, "sessions": self.sessions, "ledger_lost_until": self.ledger_lost_until}
        folder = os.path.dirname(os.path.abspath(path))
        tmp = f"{path}.tmp"
        try:
            os.makedirs(folder, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(st, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())                    # data on disk before the rename publishes it
            os.replace(tmp, path)
            dfd = os.open(folder, os.O_RDONLY)
            try:
                os.fsync(dfd)                            # and the rename itself survives a crash
            finally:
                os.close(dfd)
        except OSError as exc:
            self._log("state_write_failed", detail=str(exc))

    # ---- money
    def _gpus(self) -> int:
        return self.snapshot.gpus if self.snapshot else self.cfg.default_gpus

    def _usd_per_replica_s(self) -> float:
        return self._gpus() * self.cfg.gpu_rate_usd_per_hour / 3600.0

    def spend(self, now: Optional[float] = None) -> Tuple[float, float]:
        day, week = period_keys(self.clock() if now is None else now, self.cfg.tz)
        rate = self.cfg.gpu_rate_usd_per_hour / 3600.0
        return self.gpu_seconds.get(day, 0.0) * rate, self.gpu_seconds.get(week, 0.0) * rate

    def _ledger_lost(self, now: float) -> bool:
        if self.ledger_lost_until is None:
            return False
        if now < self.ledger_lost_until:
            return True
        self._log("ledger_restored", note="weekly rollover passed; the caps meter this week's spend again")
        self.ledger_lost_until = None
        return False

    def headroom(self, now: float) -> Tuple[float, str]:
        if self._ledger_lost(now):
            return 0.0, "ledger"
        day, week = self.spend(now)
        d_left, w_left = self.cfg.cap_day_usd - day, self.cfg.cap_week_usd - week
        return (d_left, "day") if d_left <= w_left else (w_left, "week")

    def _resets_at(self, now: float, period: str) -> Optional[str]:
        if period == "ledger":
            return iso(self.ledger_lost_until)
        return iso(next_rollover(now, self.cfg.tz, period))

    def _cap_hit(self, now: float) -> Optional[str]:
        left, period = self.headroom(now)
        if period == "ledger":
            return period
        replicas = max(1, self.snapshot.replicas if self.snapshot else 1)
        # Two loop periods: the one until the next tick, plus the one the deployment bills while draining. The
        # period is measured, so a loop slowed down by API timeouts gets a wider margin; a longer gap (host
        # suspend, a simulated jump) says nothing about the next tick, so it is bounded.
        measured = min(self.loop_period_s or 0.0, self.cfg.poll_s + LOOP_SLACK_S)
        period_s = max(self.cfg.poll_s, measured)
        margin = 2 * period_s * replicas * self._usd_per_replica_s()
        return period if left <= margin else None

    def _accrue(self, now: float, prev: Optional[Snapshot], cur: Optional[Snapshot]) -> None:
        mono = self._ref[1] if self._ref is not None else self.mono()
        first, self._first_accrual = self._first_accrual, False
        last_mono, self._tick_mono = self._tick_mono, mono
        last_wall, self.last_tick = self.last_tick, now
        seen = [s for s in (prev, cur) if s is not None]
        if first:
            if last_wall is None:                        # first start ever: nothing to bill yet
                return
            gap = max(0.0, now - last_wall)              # wall time no process was watching: bill all of it
            replicas = max([self.saved_replicas] + [s.replicas for s in seen])
            gpus = max([self.saved_gpus] + [s.gpus for s in seen]) or self.cfg.default_gpus
            self._log("restart_gap_billed", seconds=round(gap), replicas=replicas, gpus=gpus,
                      usd=round(gap * replicas * gpus * self.cfg.gpu_rate_usd_per_hour / 3600.0, 2))
        else:
            gap = max(0.0, mono - last_mono) if last_mono is not None else 0.0
            self.loop_period_s = gap
            replicas = max([0] + [s.replicas for s in seen])
            gpus = (cur or prev).gpus if seen else self.cfg.default_gpus  # type: ignore[union-attr]
        if replicas == 0 or gap == 0.0:
            return
        for key in period_keys(now, self.cfg.tz):
            self.gpu_seconds[key] = self.gpu_seconds.get(key, 0.0) + gap * replicas * gpus

    # ---- actions on Fireworks
    def _scale(self, now: float, replicas: int, reason: str) -> bool:
        try:
            if self.cfg.dry:
                self._log("scale_dry_run", replicas=replicas, reason=reason)
            else:
                self.client.scale(replicas)
                self._log("scale", replicas=replicas, reason=reason)
        except FireworksError as exc:
            self._log("scale_error", replicas=replicas, reason=reason, detail=str(exc))
            return False
        self.scale_calls.append((now, replicas, reason))
        if self.snapshot is not None and not self.cfg.dry:   # DRY changed nothing: keep reporting what is there
            self.snapshot = dataclasses.replace(self.snapshot, desired=replicas)
        if replicas == 0:
            self.last_down_at = now
            self.heavy = False
            self.wake_at = self.wake_reason = None
            self.sleep_at = self.sleep_reason = self.sleep_requested_at = None
        return True

    def _down(self, now: float, snap: Snapshot, reason: str) -> bool:
        stale = self.last_down_at is None or now - self.last_down_at > 120
        if snap.desired > 0 or (snap.replicas > 0 and stale):
            return self._scale(now, 0, reason)
        self.heavy = False                               # already draining; clear intents so nothing re-fires
        self.wake_at = self.wake_reason = None
        self.sleep_at = self.sleep_reason = self.sleep_requested_at = None
        return True

    # ---- the loop body
    def tick(self) -> None:
        with self.lock:
            now = self._now()
            prev = self.snapshot
            try:
                cur: Optional[Snapshot] = Snapshot.from_api(self.client.get(), self.cfg.default_gpus)
                self.api_errors = 0
            except FireworksError as exc:
                self.api_errors += 1
                self._log("api_error", detail=str(exc), consecutive=self.api_errors)
                cur = prev                                   # keep metering on the last known replica count
            self._accrue(now, prev, cur)
            if cur is None:
                self._save()
                return
            self.snapshot = cur
            self._expire(now)
            if cur.up and self.ready_since is None:
                self.ready_since = now
                self._log("ready", replicas=cur.replicas, waited_s=round(now - self.wake_at) if self.wake_at else None)
            elif not cur.up:
                self.ready_since = None
            if not cur.active:
                self.heavy = False
                self.wake_at = self.wake_reason = None
            self._enforce(now, cur)
            self._resume_reason = None
            self._save()

    def _enforce(self, now: float, snap: Snapshot) -> None:
        cap = self._cap_hit(now)
        if cap:
            if self.capped != cap:
                day, week = self.spend(now)
                self._log("cap_tripped", period=cap, spend_day_usd=round(day, 2), spend_week_usd=round(week, 2),
                          resets_at=self._resets_at(now, cap))
            self.capped = cap
            if snap.active:
                self._down(now, snap, f"cap_{cap}")
            return
        if self.capped:
            self._log("cap_cleared", period=self.capped)
            self.capped = None

        if self.wake_disabled and snap.active and self.wake_at is None:
            transient = bool(self.report and self.report.info.get("transient"))
            if not (transient and self._resume_reason):
                self._down(now, snap, "guard")               # nobody may wake it while the guard fails
                return
            # Fireworks didn't answer the startup check: a run that was in progress keeps going (resumed below);
            # the loop rechecks until it gets an answer, and a hard failure then stops new wakes again.

        if self.sleep_at is not None and now >= self.sleep_at:
            reason = self.sleep_reason or "scheduled"
            busy = bool(self.inflight) or (self.last_traffic is not None and self.sleep_requested_at is not None
                                           and self.last_traffic > self.sleep_requested_at)
            if reason == "session_end" and busy:
                self._log("sleep_skipped", reason=reason, why="traffic after the session ended (another session)")
                self.sleep_at = self.sleep_reason = self.sleep_requested_at = None
            else:
                self.sleep_at = None
                if snap.active:
                    self._down(now, snap, reason)
                    return

        if snap.desired > 0 and not snap.up and self.wake_at is not None and now - self.wake_at > self.cfg.wake_timeout_s:
            self._log("wake_timeout", waited_s=round(now - self.wake_at))
            self._down(now, snap, "wake_timeout")
            return

        if snap.up and not self.inflight:
            if now - self._idle_since(now) >= self.cfg.idle_sleep_s:
                self._down(now, snap, "idle")
                return

        if snap.active and self.wake_at is None:
            if self._resume_reason:                          # a run that was in progress when we restarted
                self.wake_at, self.wake_reason = now, self._resume_reason
                self._log("resumed", wake_reason=self._resume_reason)
            else:                                            # e.g. a LiteLLM fallback hit the cold B200
                self._log("unrequested_wake", note="Fireworks autoscaler woke it; only heavy runs and 429 "
                          "storms may wake the B200")
                self._down(now, snap, "unrequested")

    def _idle_since(self, now: float) -> float:
        marks = [t for t in (self.last_traffic, self.ready_since) if t is not None]
        return max(marks) if marks else now

    def _expire(self, now: float) -> None:
        lease = self.cfg.request_lease_s
        for cid, started in list(self.inflight.items()):
            if now - started > lease:
                self.inflight.pop(cid, None)
                self._log("lease_expired", call_id=cid)
        for sid, seen in list(self.sessions.items()):
            if now - seen > self.cfg.session_ttl_s:
                self.sessions.pop(sid, None)
        for cid, ended in list(self.ended.items()):
            if now - ended > 2 * lease:
                self.ended.pop(cid, None)
        while self.storm and now - self.storm[0] > self.cfg.storm_window_s:
            self.storm.popleft()

    # ---- checks
    def recheck(self) -> Tuple[int, dict]:
        with self.lock:
            self._now()
            try:
                doc = self.client.get()
            except FireworksError as exc:
                self.report = CheckReport([f"cannot read the deployment: {exc}"], [], {"transient": True})
            else:
                fc = None if find_autodelete(doc)[0] or self.cfg.autodelete_verified else self.firectl(self.cfg.deployment)
                self.report = check_deployment(doc, self.cfg, fc)
                if self.snapshot is None:                   # so /status is meaningful before the first tick
                    self.snapshot = Snapshot.from_api(doc, self.cfg.default_gpus)
            self.wake_disabled = "; ".join(self.report.hard) or None
            for msg in self.report.hard:
                self._log("check_failed", severity="CRITICAL", detail=msg)
            for msg in self.report.warn:
                self._log("check_warning", severity="WARNING", detail=msg)
            if self.report.ok:
                self._log("check_passed", **self.report.info)
            return (200 if self.report.ok else 503), self.report.as_dict()

    # ---- requests
    def wake(self, reason: str) -> Tuple[int, dict]:
        with self.lock:
            self.tick()
            now = self._now()
            if self.wake_disabled:
                self._log("wake_refused", reason=reason, why="guard")
                return 503, {"ok": False, "refused": "guard", "detail": self.wake_disabled}
            left, period = self.headroom(now)
            reserve = self.cfg.wake_reserve_s * self._usd_per_replica_s()
            cap = self._cap_hit(now)
            if cap or left < reserve:
                period = cap or period
                self._log("wake_refused", reason=reason, why=f"cap_{period}", headroom_usd=round(left, 2))
                return 409, {"ok": False, "refused": f"cap_{period}", "headroom_usd": round(max(left, 0), 2),
                             "reserve_usd": round(reserve, 2), "resets_at": self._resets_at(now, period)}
            self.sleep_at = self.sleep_reason = self.sleep_requested_at = None
            snap = self.snapshot
            if snap is not None and snap.desired > 0:        # already up or waking
                self.wake_at = self.wake_at or now
                self.wake_reason = self.wake_reason or reason
                self._save()
                return 200, {"ok": True, "b200": snap.label, "headroom_usd": round(left, 2)}
            if not self._scale(now, 1, f"wake_{reason}"):    # asleep, or still draining from a scale-down
                return 502, {"ok": False, "refused": "scale_error", "detail": self.events[-1].get("detail")}
            self.wake_at, self.wake_reason = now, reason
            self._save()
            return 202, {"ok": True, "b200": "waking", "headroom_usd": round(left, 2),
                         "gpu_minutes_left": round(left / (self._usd_per_replica_s() * 60), 1)}

    def sleep(self, delay_s: float, reason: str) -> Tuple[int, dict]:
        with self.lock:
            if not math.isfinite(delay_s):
                raise ValueError("delay_s must be a finite number")
            delay_s = min(max(delay_s, 0.0), MAX_DELAY_S)
            if delay_s <= 0:
                self.tick()
                now = self._now()
                snap = self.snapshot
                if snap is None:                             # never read the deployment: ask Fireworks anyway
                    done = self._scale(now, 0, reason)
                else:
                    done = self._down(now, snap, reason) if snap.active else True
                self._save()
                if not done:
                    return 502, {"ok": False, "refused": "scale_error", "detail": self.events[-1].get("detail")}
                return 202, {"ok": True, "sleeping": "now"}
            now = self._now()
            self.sleep_at, self.sleep_reason, self.sleep_requested_at = now + delay_s, reason, now
            self._log("sleep_scheduled", reason=reason, at=iso(self.sleep_at))
            return 202, {"ok": True, "sleep_at": iso(self.sleep_at)}

    def set_heavy(self, on: bool) -> Tuple[int, dict]:
        with self.lock:
            if not on:
                self.heavy = False
                return self.sleep(0, "heavy_off")
            code, body = self.wake("heavy")
            if code < 300:
                self.heavy = True
                self._save()
            return code, body

    def session_start(self, session_id: str) -> Tuple[int, dict]:
        with self.lock:
            now = self._now()
            key = session_id or f"anon-{now}"
            if key not in self.sessions and len(self.sessions) >= MAX_TRACKED:
                return 429, {"ok": False, "error": f"too many open sessions ({MAX_TRACKED})"}
            self.sessions[key] = now
            if self.sleep_reason == "session_end":
                self._log("sleep_cancelled", why="new session")
                self.sleep_at = self.sleep_reason = self.sleep_requested_at = None
            self._save()
            return 200, self._brief(now)

    def session_end(self, session_id: str) -> Tuple[int, dict]:
        with self.lock:
            self._now()
            known = self.sessions.pop(session_id, None) is not None
            self._save()
            # Only the end of a session we know about may put the B200 to sleep: an unknown id (lost registry,
            # another client) must not cut short a run that a live session is using.
            if known and not self.sessions and (self.snapshot is None or self.snapshot.active):
                return self.sleep(self.cfg.session_end_sleep_s, "session_end")
            return 200, {"ok": True, "sessions": len(self.sessions), "known": known}

    def touch(self, event: str, call_id: str) -> Tuple[int, dict]:
        with self.lock:
            if event not in ("start", "end"):
                return 400, {"error": "event must be start or end"}
            if not call_id:
                return 400, {"error": "call_id is required"}
            now = self._now()
            lease = self.cfg.request_lease_s
            if event == "start":
                ended = self.ended.get(call_id)
                if ended is not None and now - ended <= 2 * lease:
                    self._log("late_start_ignored", call_id=call_id)   # its end already arrived
                    return 200, {"ok": True, "ignored": "call already ended", "inflight": len(self.inflight)}
                if call_id not in self.inflight and len(self.inflight) >= MAX_TRACKED:
                    return 429, {"ok": False, "error": f"too many in-flight requests ({MAX_TRACKED})"}
                self.inflight[call_id] = now
            else:
                self.inflight.pop(call_id, None)
                self.ended[call_id] = now
                self.ended.move_to_end(call_id)
                while len(self.ended) > ENDED_KEEP:
                    self.ended.popitem(last=False)
            self.last_traffic = now
            self._save()
            return 200, {"ok": True, "inflight": len(self.inflight)}

    def signal_429(self, model_group: str) -> Tuple[int, dict]:
        with self.lock:
            now = self._now()
            self._expire(now)
            self.storm.append(now)
            self._log("rate_limited", model_group=model_group, in_window=len(self.storm))
            if len(self.storm) >= self.cfg.storm_count:
                self.storm.clear()
                return self.wake("429_storm")
            return 202, {"ok": True, "counted": len(self.storm), "needed": self.cfg.storm_count}

    # ---- views
    def _brief(self, now: float) -> dict:
        day, _ = self.spend(now)
        return {"ok": True, "b200": self.snapshot.label if self.snapshot else "unknown",
                "spend_day_usd": round(day, 2), "cap_day_usd": self.cfg.cap_day_usd,
                "wake_disabled": bool(self.wake_disabled), "capped": self.capped}

    def status(self) -> dict:
        with self.lock:
            now = self._now()
            snap = self.snapshot
            day, week = self.spend(now)
            left, period = self.headroom(now)
            idle_for = None
            if snap is not None and snap.up:
                idle_for = round(now - self._idle_since(now))
            return {
                "version": __version__, "deployment": self.cfg.deployment, "dry_run": self.cfg.dry,
                "b200": snap.label if snap else "unknown",
                "burst_ready": bool(snap and snap.up and snap.desired > 0 and snap.state in ("READY", "UPDATING")),
                "replicas": snap.replicas if snap else None, "desired": snap.desired if snap else None,
                "heavy": self.heavy, "wake_reason": self.wake_reason,
                "spend_day_usd": round(day, 2), "spend_week_usd": round(week, 2),
                "cap_day_usd": self.cfg.cap_day_usd, "cap_week_usd": self.cfg.cap_week_usd,
                "headroom_usd": round(max(left, 0.0), 2), "binding_cap": period, "capped": self.capped,
                "resets_at": self._resets_at(now, period), "ledger_lost_until": iso(self.ledger_lost_until),
                "usd_per_hour_running": round(self._gpus() * self.cfg.gpu_rate_usd_per_hour, 2),
                "wake_disabled": self.wake_disabled, "checks": self.report.as_dict() if self.report else None,
                "sleep_at": iso(self.sleep_at), "sleep_reason": self.sleep_reason,
                "idle_for_s": idle_for, "idle_sleep_s": self.cfg.idle_sleep_s,
                "sessions": len(self.sessions), "inflight": len(self.inflight),
                "request_lease_s": self.cfg.request_lease_s,
                "last_traffic": iso(self.last_traffic), "api_errors": self.api_errors,
                "loop_period_s": round(self.loop_period_s, 1) if self.loop_period_s is not None else None,
                "auto_delete": ("verified off" if self.cfg.autodelete_verified else
                                "risk accepted" if self.cfg.autodelete_accept_risk else "unverified"),
                "days_since_b200_traffic": (round((now - self.last_traffic) / 86400, 1)
                                            if self.last_traffic is not None else None),
                "events": list(self.events)[-20:],
            }


# --------------------------------------------------------------------------- HTTP API

def _delay(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("delay_s must be a number")
    secs = float(value)
    if not math.isfinite(secs):
        raise ValueError("delay_s must be a finite number")
    return min(max(secs, 0.0), MAX_DELAY_S)


def _flag(value: Any, name: str) -> bool:
    if value is True or value is False:
        return value
    raise ValueError(f"{name} must be true or false")


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def make_handler(ctl: Lifecycle):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"gem-lifecycle/{__version__}"
        timeout = 5                                      # a client that stalls mid-request loses its connection

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet; the controller logs decisions itself
            return

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _allowed(self, method: str, path: str) -> bool:
            """True if the bearer belongs to a role allowed on this route; otherwise sends 401, 404 or 403."""
            got = self.headers.get("Authorization", "").encode()
            roles = set()
            for role, tok in ctl.cfg.role_tokens().items():   # a role without a token is disabled
                if tok and hmac.compare_digest(got, f"Bearer {tok}".encode()):
                    roles.add(role)
            if not roles:
                self._send(401, {"error": "unauthorized"})
                return False
            allowed = ROUTE_ROLES.get((method, path))
            if allowed is None:
                self._send(404, {"error": "not found"})
                return False
            if not roles.intersection(allowed):
                self._send(403, {"error": f"forbidden for the {'/'.join(sorted(roles))} token"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/health":
                return self._send(200, {"status": "ok", "version": __version__})
            if not self._allowed("GET", path):
                return None
            return self._send(200, ctl.status())

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if not self._allowed("POST", path):
                return None
            try:
                length = (self.headers.get("Content-Length") or "0").strip()
                if not re.fullmatch(r"[0-9]{1,9}", length):
                    raise ValueError("Content-Length must be a non-negative integer")
                n = int(length)
                if n > 4096:
                    raise ValueError("body too large")
                raw = self.rfile.read(n) if n else b""
                b = json.loads(raw, parse_constant=_no_constant) if raw.strip() else {}
                if not isinstance(b, dict):
                    raise ValueError("body must be a JSON object")
                routes: Dict[str, Callable[[], Tuple[int, dict]]] = {
                    "/wake": lambda: ctl.wake(str(b.get("reason", "manual"))[:40]),
                    "/sleep": lambda: ctl.sleep(_delay(b.get("delay_s", 0)), str(b.get("reason", "manual"))[:40]),
                    "/heavy": lambda: ctl.set_heavy(_flag(b.get("on"), "on")),
                    "/session/start": lambda: ctl.session_start(str(b.get("session_id", ""))[:128]),
                    "/session/end": lambda: ctl.session_end(str(b.get("session_id", ""))[:128]),
                    "/touch": lambda: ctl.touch(str(b.get("event", "")), str(b.get("call_id", ""))[:128]),
                    "/signal/429": lambda: ctl.signal_429(str(b.get("model_group", ""))[:40]),
                    "/check": ctl.recheck,
                }
                code, obj = routes[path]()
            except (ValueError, TypeError) as exc:
                return self._send(400, {"error": str(exc)})
            return self._send(code, obj)

    return Handler


def _bind(cfg: Config) -> Tuple[str, int]:
    host, _, port = cfg.bind.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if host not in ("127.0.0.1", "::1", "localhost") and os.environ.get("GEM_LIFECYCLE_ALLOW_REMOTE") != "1":
        raise SystemExit(f"refusing to bind {host}: reach the controller through the SSH/Tailscale tunnel "
                         "(set GEM_LIFECYCLE_ALLOW_REMOTE=1 to override)")
    return host, int(port)


def start_server(ctl: Lifecycle, host: str, port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), make_handler(ctl))
    srv.daemon_threads = True
    return srv


def cmd_serve(cfg: Config) -> int:
    errs = cfg.validate()
    if not cfg.api_key:
        errs.append("FIREWORKS_API_KEY is not set")
    if len(cfg.token) < 16:
        errs.append("GEM_LIFECYCLE_TOKEN (operator) must be set (at least 16 characters)")
    if errs:
        for e in errs:
            sys.stderr.write(f"gem_lifecycle: {e}\n")
        return 1
    ctl = Lifecycle(cfg, FireworksClient(cfg.deployment, cfg.api_key, base=cfg.api_base))
    ctl.recheck()
    host, port = _bind(cfg)
    srv = start_server(ctl, host, port)
    stop = threading.Event()

    def loop() -> None:
        last_check = time.monotonic()
        while not stop.is_set():
            try:
                ctl.tick()
                transient = bool(ctl.report and ctl.report.info.get("transient"))
                if transient or time.monotonic() - last_check >= cfg.recheck_s:
                    ctl.recheck()
                    last_check = time.monotonic()
            except Exception as exc:  # noqa: BLE001 - the loop must survive anything
                ctl._log("tick_error", detail=repr(exc))
            stop.wait(cfg.poll_s)

    def shutdown(*_: Any) -> None:
        stop.set()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    threading.Thread(target=loop, name="gem-lifecycle-loop", daemon=True).start()
    ctl._log("serving", bind=f"{host}:{port}", deployment=cfg.deployment, dry_run=cfg.dry,
             caps={"day": cfg.cap_day_usd, "week": cfg.cap_week_usd},
             roles=[role for role, tok in cfg.role_tokens().items() if tok])
    srv.serve_forever()
    with ctl.lock:
        ctl._save()
    return 0


def cmd_check(cfg: Config) -> int:
    errs = cfg.validate() + ([] if cfg.api_key else ["FIREWORKS_API_KEY is not set"])
    if errs:
        for e in errs:
            sys.stderr.write(f"gem_lifecycle: {e}\n")
        return 1
    ctl = Lifecycle(dataclasses.replace(cfg, state_path=None),
                    FireworksClient(cfg.deployment, cfg.api_key, base=cfg.api_base), out=io.StringIO())
    _, rep = ctl.recheck()
    json.dump(rep, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if rep["ok"] else 3


# --------------------------------------------------------------------------- dry run (simulated world)

class FakeClock:
    """Wall clock plus its own monotonic clock. advance() moves both; step() moves only the wall (an NTP step)."""

    def __init__(self, start: float):
        self.now = float(start)
        self.mono_now = 1000.0

    def __call__(self) -> float:
        return self.now

    def mono(self) -> float:
        return self.mono_now

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.mono_now += seconds

    def step(self, seconds: float) -> None:
        self.now += seconds


class FakeFireworks:
    """A deployment that obeys the documented behaviour: cold start delay, 503 + autoscaler wake when at zero."""

    def __init__(self, clock: Callable[[], float], cold_start_s: float = 120.0, gpus: int = 4, min_replicas: int = 0,
                 extra: Optional[dict] = None, scale_to_zero: str = "300s", drain_s: float = 0.0):
        self.clock, self.cold_start_s, self.gpus, self.min_replicas = clock, cold_start_s, gpus, min_replicas
        self.extra = {"unusedAutoDeleteDuration": "0s"} if extra is None else extra
        self.scale_to_zero, self._drain_s = scale_to_zero, drain_s
        self.replicas = self.desired = 0
        self._up_at: Optional[float] = None
        self._down_at: Optional[float] = None
        self.calls: List[Tuple[float, int]] = []
        self.billed_gpu_s = 0.0
        self._last = clock()

    def _physics(self) -> None:
        now = self.clock()
        self.billed_gpu_s += (now - self._last) * self.replicas * self.gpus
        self._last = now
        if self.desired > self.replicas and self._up_at is not None and now >= self._up_at:
            self.replicas = self.desired
        if self.desired < self.replicas and (self._down_at is None or now >= self._down_at):
            self.replicas = self.desired

    def get(self) -> dict:
        self._physics()
        doc = {"name": "accounts/demo/deployments/b200", "state": "READY", "replicaCount": self.replicas,
               "desiredReplicaCount": self.desired, "minReplicaCount": self.min_replicas, "maxReplicaCount": 1,
               "acceleratorCount": self.gpus, "acceleratorType": "NVIDIA_B200",
               "autoscalingPolicy": {"scaleToZeroWindow": self.scale_to_zero}}
        doc.update(self.extra)
        return doc

    def scale(self, n: int) -> None:
        self._physics()
        self.calls.append((self.clock(), n))
        if n > self.replicas:
            self._up_at = self.clock() + self.cold_start_s
        if n < self.replicas:
            self._down_at = self.clock() + self._drain_s
        self.desired = n

    def request(self) -> int:
        """An inference request arriving at the deployment (e.g. a LiteLLM fallback)."""
        self._physics()
        if self.replicas == 0:
            if self.desired == 0:
                self.desired, self._up_at = 1, self.clock() + self.cold_start_s
            return 503
        return 200


SIM_START = dt.datetime(2026, 11, 9, 15, 0, tzinfo=_tz("America/Chicago")).timestamp()   # a Monday afternoon


def _sim(**cfg_over: Any) -> Tuple[FakeClock, FakeFireworks, Lifecycle]:
    fake_kw = cfg_over.pop("fake", {})
    clock = FakeClock(SIM_START)
    fake = FakeFireworks(clock, **fake_kw)
    cfg = dataclasses.replace(Config(deployment="accounts/demo/deployments/b200", token="t" * 16), **cfg_over)
    ctl = Lifecycle(cfg, fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    return clock, fake, ctl


def _run(clock: FakeClock, ctl: Lifecycle, seconds: float, each: Optional[Callable[[float], None]] = None) -> None:
    end = clock.now + seconds
    while clock.now < end:
        clock.advance(ctl.cfg.poll_s)
        if each:
            each(clock.now)
        ctl.tick()


def _downs(ctl: Lifecycle) -> List[Tuple[float, str]]:
    return [(t, r) for t, n, r in ctl.scale_calls if n == 0]


def _preload(ctl: Lifecycle, day_usd: float = 0.0, week_usd: float = 0.0) -> None:
    day, week = period_keys(ctl.clock(), ctl.cfg.tz)
    rate = ctl.cfg.gpu_rate_usd_per_hour / 3600.0
    ctl.gpu_seconds[day] = day_usd / rate
    ctl.gpu_seconds[week] = max(week_usd, day_usd) / rate


def scenario_idle_sleep() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    code, _ = ctl.set_heavy(True)
    _run(clock, ctl, 150)                                     # cold start (120 s) completes
    t_req = clock.now
    ctl.touch("start", "c1")
    _run(clock, ctl, 60)                                      # a 60 s generation keeps it awake
    ctl.touch("end", "c1")
    t_end = clock.now
    _run(clock, ctl, 400)
    downs = _downs(ctl)
    ok = code == 202 and len(downs) == 1 and downs[0][1] == "idle" and \
        t_end + 180 <= downs[0][0] < t_end + 180 + ctl.cfg.poll_s and fake.replicas == 0
    detail = f"wake 202, ready after cold start, request at +{t_req - SIM_START:.0f}s ended +{t_end - SIM_START:.0f}s; " \
             f"scale-down '{downs[0][1] if downs else None}' at +{(downs[0][0] - t_end) if downs else -1:.0f}s after last request"
    return ok, detail


def scenario_session_end() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    ctl.session_start("A")
    ctl.set_heavy(True)
    _run(clock, ctl, 150)
    ctl.touch("start", "c1")
    _run(clock, ctl, 30)
    ctl.touch("end", "c1")
    _run(clock, ctl, 15)
    t_end = clock.now
    ctl.session_end("A")
    _run(clock, ctl, 120)
    downs = _downs(ctl)
    ok = len(downs) == 1 and downs[0][1] == "session_end" and t_end + 45 <= downs[0][0] < t_end + 45 + ctl.cfg.poll_s
    return ok, f"SessionEnd at +{t_end - SIM_START:.0f}s -> scale-down '{downs[0][1] if downs else None}' " \
               f"{(downs[0][0] - t_end) if downs else -1:.0f}s later"


def scenario_session_end_cancelled() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    ctl.session_start("A")
    ctl.set_heavy(True)
    _run(clock, ctl, 150)
    ctl.touch("start", "c1")
    ctl.touch("end", "c1")
    t_end = clock.now
    ctl.session_end("A")
    _run(clock, ctl, 15)
    ctl.session_start("B")                                    # a new session inside the 45 s window
    _run(clock, ctl, 60)
    early = [d for d in _downs(ctl) if d[0] < t_end + 120]
    _run(clock, ctl, 300)
    downs = _downs(ctl)
    ok = not early and len(downs) == 1 and downs[0][1] == "idle"
    return ok, f"session B started 15s after A ended: no scale-down at +45s; later scale-down '{downs[0][1] if downs else None}'"


def scenario_daily_cap() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    _preload(ctl, day_usd=20.0, week_usd=20.0)
    code, _ = ctl.set_heavy(True)

    def busy(now: float) -> None:                             # continuous traffic: only the cap can stop it
        ctl.touch("start", f"c{int(now)}")
        ctl.touch("end", f"c{int(now)}")

    _run(clock, ctl, 1800, each=busy)
    day, _ = ctl.spend()
    downs = _downs(ctl)
    refused, body = ctl.set_heavy(True)
    billed = 20.0 + fake.billed_gpu_s * ctl.cfg.gpu_rate_usd_per_hour / 3600.0
    ok = code == 202 and downs and downs[0][1] == "cap_day" and day <= ctl.cfg.cap_day_usd and \
        billed <= day and refused == 409 and body.get("refused") == "cap_day" and fake.replicas == 0
    return ok, f"started at $20 of $26; scale-down '{downs[0][1] if downs else None}' with ${day:.2f} metered " \
               f"(${billed:.2f} billed); next wake -> {refused} {body.get('refused')} (resets {body.get('resets_at')})"


def scenario_weekly_cap() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    _preload(ctl, day_usd=0.0, week_usd=76.0)
    code1, body1 = ctl.set_heavy(True)                        # $2 left this week < $4.33 reserve
    _preload(ctl, day_usd=0.0, week_usd=70.0)
    code2, _ = ctl.set_heavy(True)

    def busy(now: float) -> None:
        ctl.touch("start", f"c{int(now)}")
        ctl.touch("end", f"c{int(now)}")

    _run(clock, ctl, 1800, each=busy)
    _, week = ctl.spend()
    downs = _downs(ctl)
    billed = 70.0 + fake.billed_gpu_s * ctl.cfg.gpu_rate_usd_per_hour / 3600.0
    ok = code1 == 409 and body1.get("refused") == "cap_week" and code2 == 202 and downs and \
        downs[0][1] == "cap_week" and week <= ctl.cfg.cap_week_usd and billed <= week
    return ok, f"$76 of $78 -> wake {code1} {body1.get('refused')}; $70 -> wake {code2}, " \
               f"scale-down '{downs[0][1] if downs else None}' with ${week:.2f} metered (${billed:.2f} billed) this week"


def scenario_capped_rewake() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    _preload(ctl, day_usd=26.0, week_usd=26.0)
    ctl.tick()
    before = fake.billed_gpu_s
    status = fake.request()                                   # a stray fallback request reaches the cold B200
    _run(clock, ctl, 300)
    downs = _downs(ctl)
    ok = status == 503 and downs and downs[0][1] == "cap_day" and fake.billed_gpu_s == before and fake.replicas == 0
    return ok, f"capped; Fireworks autoscaler woke it on a stray request -> controller scaled it back " \
               f"in {(downs[0][0] - SIM_START) if downs else -1:.0f}s, billed GPU-seconds +{fake.billed_gpu_s - before:.0f}"


def scenario_stray_wake() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    ctl.tick()
    before = fake.billed_gpu_s
    status = fake.request()                                   # one fallback request, no heavy run, no storm
    _run(clock, ctl, 300)
    downs = _downs(ctl)
    ok = status == 503 and downs and downs[0][1] == "unrequested" and fake.billed_gpu_s == before
    return ok, f"one stray fallback request woke the cold B200 -> undone '{downs[0][1] if downs else None}' " \
               f"within {ctl.cfg.poll_s:.0f}s, billed GPU-seconds +{fake.billed_gpu_s - before:.0f}"


def scenario_429_storm() -> Tuple[bool, str]:
    clock, fake, ctl = _sim()
    a = [ctl.signal_429("ds-main")[0] for _ in range(2)]
    clock.advance(150)                                        # window expires
    b = ctl.signal_429("ds-main")[0]
    clock.advance(10)
    c = [ctl.signal_429("ds-main")[0] for _ in range(2)]
    ok = a == [202, 202] and b == 202 and c == [202, 202] and fake.desired == 1
    return ok, f"2 x 429 -> no wake; 150 s later 3 x 429 within 10 s -> wake (desired={fake.desired})"


def scenario_autodelete_guard() -> Tuple[bool, str]:
    results = {}
    for label, extra, verified, min_r in (("7d auto-delete", {"unusedAutoDeleteDuration": "604800s"}, False, 0),
                                          ("field missing", {}, False, 0),
                                          ("field missing + operator verified", {}, True, 0),
                                          ("auto-delete 0s", {"unusedAutoDeleteDuration": "0s"}, False, 0),
                                          ("min replicas 1", {"unusedAutoDeleteDuration": "0s"}, False, 1)):
        _, fake, ctl = _sim(autodelete_verified=verified, fake={"extra": extra, "min_replicas": min_r})
        code, _ = ctl.wake("heavy")
        results[label] = code
    want = {"7d auto-delete": 503, "field missing": 503, "field missing + operator verified": 202,
            "auto-delete 0s": 202, "min replicas 1": 503}
    return results == want, ", ".join(f"{k} -> {v}" for k, v in results.items())


def _restarted(prev: Lifecycle, client: Any, clock: FakeClock) -> Lifecycle:
    ctl = Lifecycle(prev.cfg, client, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    return ctl


def scenario_restart_gap() -> Tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        clock, fake, a = _sim(state_path=os.path.join(tmp, "lifecycle.json"), fake={"cold_start_s": 0})
        a.set_heavy(True)
        _run(clock, a, 60)
        clock.advance(1800)                                   # controller down 30 min while the GPU bills ...
        fake.scale(0)                                         # ... until Fireworks' own backstop drains it
        clock.advance(60)
        b = _restarted(a, fake, clock)
        b.tick()
        billed = fake.billed_gpu_s * b.cfg.gpu_rate_usd_per_hour / 3600.0
        day, _ = b.spend()
        gap = [e for e in b.events if e["event"] == "restart_gap_billed"]
        code, body = b.set_heavy(True)
        ok = bool(gap) and gap[0]["seconds"] == 1860 and day >= billed and b.capped == "day" and code == 409
    return ok, f"30 min outage with the GPU up, drained before the restart: gap {gap[0]['seconds'] if gap else '?'}s " \
               f"billed ${gap[0]['usd'] if gap else '?'}; metered ${day:.2f} >= billed ${billed:.2f}; " \
               f"daily cap tripped, next wake -> {code} {body.get('refused')}"


def scenario_ledger_lost() -> Tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "lifecycle.json")
        clock, fake, a = _sim(state_path=path)
        _preload(a, day_usd=25.9, week_usd=77.9)
        a._save()
        open(path, "w").close()                               # zero-length ledger after a crash
        b = _restarted(a, fake, clock)
        code1, body1 = b.set_heavy(True)
        st = b.status()
        c = _restarted(b, fake, clock)                        # the refusal itself survives another restart
        code2, _ = c.set_heavy(True)
        clock.advance(next_rollover(clock.now, c.cfg.tz, "week") - clock.now + 60)
        code3, _ = c.set_heavy(True)
        ok = code1 == 409 and body1.get("refused") == "cap_ledger" and st["ledger_lost_until"] == body1["resets_at"] \
            and st["capped"] == "ledger" and code2 == 409 and code3 == 202
    return ok, f"empty ledger -> wake {code1} {body1.get('refused')} until {body1.get('resets_at')}; " \
               f"after another restart {code2}; after the weekly rollover {code3}"


def scenario_wake_during_drain() -> Tuple[bool, str]:
    clock, fake, ctl = _sim(fake={"cold_start_s": 0, "drain_s": 40})
    ctl.set_heavy(True)
    _run(clock, ctl, 15)
    ctl.set_heavy(False)                                      # heavy off ...
    clock.advance(5)
    code, _ = ctl.set_heavy(True)                             # ... and on again while the replica drains
    ready = ctl.status()["burst_ready"]
    _run(clock, ctl, 60)
    ok = code == 202 and fake.desired == 1 and fake.replicas == 1 and ctl.heavy and \
        ctl.scale_calls[-1][1] == 1
    return ok, f"heavy on 5 s into a 40 s drain -> {code}, scale to 1 sent; 60 s later replicas={fake.replicas} " \
               f"desired={fake.desired} (burst_ready right after the call: {ready})"


SCENARIOS: List[Tuple[str, Callable[[], Tuple[bool, str]]]] = [
    ("idle 180 s -> sleep", scenario_idle_sleep),
    ("SessionEnd -> sleep at +45 s", scenario_session_end),
    ("new session cancels the +45 s sleep", scenario_session_end_cancelled),
    ("daily cap trips and refuses wakes", scenario_daily_cap),
    ("weekly cap trips and refuses wakes", scenario_weekly_cap),
    ("capped: autoscaler re-wake is undone before billing", scenario_capped_rewake),
    ("uncapped stray wake (single fallback) is undone", scenario_stray_wake),
    ("429 storm wakes the B200", scenario_429_storm),
    ("auto-delete / min-replica guard blocks wakes", scenario_autodelete_guard),
    ("restart bills the whole unobserved gap", scenario_restart_gap),
    ("damaged ledger refuses wakes until the weekly rollover", scenario_ledger_lost),
    ("heavy on during a drain scales back up", scenario_wake_during_drain),
]


def cmd_dryrun(_: Config) -> int:
    passed = 0
    for name, fn in SCENARIOS:
        ok, detail = fn()
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    print(f"{passed}/{len(SCENARIOS)} scenarios passed (simulated deployment, 4 GPUs x $13/GPU-hour, "
          f"caps $26/day and $78/week)")
    return 0 if passed == len(SCENARIOS) else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="gem_lifecycle", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["serve", "check", "dryrun", "version"])
    a = ap.parse_args(argv)
    if a.command == "version":
        print(__version__)
        return 0
    cfg = Config.from_env()
    return {"serve": cmd_serve, "check": cmd_check, "dryrun": cmd_dryrun}[a.command](cfg)


if __name__ == "__main__":
    sys.exit(main())
