"""Tests for the B200 lifecycle controller (WU-07) and everything that talks to it."""
import asyncio
import dataclasses
import importlib
import io
import json
import os
import subprocess
import sys
import threading
import time

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "lifecycle"))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)

import gem_lifecycle as gl  # noqa: E402

PY = sys.executable
GEMCTL = os.path.join(ROOT, "gemctl.py")
START = os.path.join(ROOT, "hooks", "gem_session_start.py")
END = os.path.join(ROOT, "hooks", "gem_session_end.py")
INSTALL = os.path.join(ROOT, "install_hooks.py")
TOKEN = "test-token-0123456789"


# ---------------------------------------------------------------- gate scenarios (the WU-07 gate)

@pytest.mark.parametrize("name,fn", gl.SCENARIOS, ids=[n for n, _ in gl.SCENARIOS])
def test_gate_scenario(name, fn):
    ok, detail = fn()
    assert ok, detail


def test_dryrun_cli_reports_all_scenarios():
    r = subprocess.run([PY, "-I", os.path.join(ROOT, "lifecycle", "gem_lifecycle.py"), "dryrun"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"{len(gl.SCENARIOS)}/{len(gl.SCENARIOS)} scenarios passed" in r.stdout


# ---------------------------------------------------------------- units

@pytest.mark.parametrize("raw,secs", [("300s", 300), ("5m", 300), ("1h", 3600), ("168h0m0s", 604800),
                                      ("0s", 0), ("0", 0), (0, 0), ({"seconds": 90}, 90), ("1.5s", 1.5),
                                      (None, None), ("", None)])
def test_parse_duration(raw, secs):
    assert gl.parse_duration(raw) == secs


@pytest.mark.parametrize("raw", ["7 days", "abc", "5x", True])
def test_parse_duration_rejects(raw):
    with pytest.raises(ValueError):
        gl.parse_duration(raw)


def test_periods_follow_local_midnight_and_monday():
    sunday_late = gl.SIM_START - 15 * 3600 - 60          # Sun 2026-11-08 23:59 Chicago
    assert gl.period_keys(sunday_late, "America/Chicago") == ("day:2026-11-08", "week:2026-W45")
    assert gl.period_keys(gl.SIM_START, "America/Chicago") == ("day:2026-11-09", "week:2026-W46")
    assert gl.iso(gl.next_rollover(gl.SIM_START, "America/Chicago", "day")) == "2026-11-10T06:00:00Z"
    assert gl.iso(gl.next_rollover(gl.SIM_START, "America/Chicago", "week")) == "2026-11-16T06:00:00Z"


def test_config_from_env_strips_litellm_prefix_and_validates():
    cfg = gl.Config.from_env({"GEM_BURST_MODEL": "openai/accounts/YOUR_ACCOUNT/deployments/YOUR_DEPLOYMENT",
                              "GEM_GPU_CAP_DAY_USD": "26", "GEM_GPU_CAP_WEEK_USD": "20"})
    assert cfg.deployment == "accounts/YOUR_ACCOUNT/deployments/YOUR_DEPLOYMENT"
    assert "weekly cap is below the daily cap" in cfg.validate()
    assert gl.Config.from_env({"GEM_BURST_DEPLOYMENT": "YOUR_DEPLOYMENT"}).validate()[0].startswith("GEM_BURST_DEPLOYMENT")


def _doc(**over):
    d = {"state": "READY", "minReplicaCount": 0, "maxReplicaCount": 1, "acceleratorCount": 4,
         "autoscalingPolicy": {"scaleToZeroWindow": "300s"}, "unusedAutoDeleteDuration": "0s"}
    d.update(over)
    return d


def _cfg(**over):
    return dataclasses.replace(gl.Config(deployment="accounts/demo/deployments/b200", token=TOKEN), **over)


def test_check_flags_long_backstop_and_extra_replicas_as_warnings():
    rep = gl.check_deployment(_doc(autoscalingPolicy={"scaleToZeroWindow": "3600s"}, maxReplicaCount=3), _cfg())
    assert rep.ok and len(rep.warn) == 2
    assert "--scale-to-zero-window 5m" in rep.warn[0] and "$52" in rep.warn[0]


@pytest.mark.parametrize("over,needle", [({"state": "DELETING"}, "undelete"),
                                         ({"deleteTime": "2026-11-20T00:00:00Z"}, "scheduled for deletion"),
                                         ({"expireTime": "2026-12-01T00:00:00Z"}, "expires"),
                                         ({"unusedAutoDeleteDuration": "forever"}, "unused auto-delete"),
                                         ({"minReplicaCount": 2}, "bills continuously")])
def test_check_hard_failures(over, needle):
    rep = gl.check_deployment(_doc(**over), _cfg())
    assert not rep.ok and any(needle in h for h in rep.hard)


def test_check_reads_autodelete_from_firectl_when_api_lacks_it():
    doc = _doc()
    doc.pop("unusedAutoDeleteDuration")
    assert gl.check_deployment(doc, _cfg(), {"deployment": {"unused_auto_delete_duration": "0s"}}).ok
    assert not gl.check_deployment(doc, _cfg(), {"unusedAutoDeleteDuration": "168h0m0s"}).ok


# ---------------------------------------------------------------- persistence and failure handling

def test_ledger_survives_restart_and_bills_unseen_gap_conservatively(tmp_path):
    state = str(tmp_path / "lifecycle.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    cfg = _cfg(state_path=state)
    a = gl.Lifecycle(cfg, fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    a.recheck()
    a.wake("heavy")
    for _ in range(4):
        clock.advance(15)
        a.tick()
    spent = a.spend()[0]
    assert spent > 0
    clock.advance(7200)                                   # controller down for 2 h while the GPU stays up
    b = gl.Lifecycle(cfg, fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    assert b.spend()[0] == pytest.approx(spent)
    b.tick()
    gap_usd = cfg.max_gap_s * 4 * cfg.gpu_rate_usd_per_hour / 3600
    assert b.spend()[0] == pytest.approx(spent + gap_usd)
    assert b.unmetered_gap_s == pytest.approx(3600) and any(e["event"] == "unmetered_gap" for e in b.events)


def test_corrupt_state_is_moved_aside(tmp_path):
    state = tmp_path / "lifecycle.json"
    state.write_text("{not json")
    ctl = gl.Lifecycle(_cfg(state_path=str(state)), gl.FakeFireworks(gl.FakeClock(gl.SIM_START)),
                       clock=gl.FakeClock(gl.SIM_START), out=io.StringIO())
    assert not state.exists() and any(p.name.startswith("lifecycle.json.corrupt-") for p in tmp_path.iterdir())
    assert ctl.events[-1]["event"] == "state_unreadable"


class FlakyFireworks(gl.FakeFireworks):
    fail = False

    def get(self):
        if self.fail:
            raise gl.FireworksError("GET: HTTP 502", 502)
        return super().get()


def test_api_outage_keeps_metering_last_known_replicas():
    clock = gl.FakeClock(gl.SIM_START)
    fake = FlakyFireworks(clock, cold_start_s=0)
    ctl = gl.Lifecycle(_cfg(), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    ctl.wake("heavy")
    clock.advance(15)
    ctl.tick()
    before = ctl.spend()[0]
    fake.fail = True
    clock.advance(60)
    ctl.tick()
    assert ctl.api_errors == 1 and ctl.spend()[0] == pytest.approx(before + 60 * 4 * 13 / 3600)


def test_dry_mode_never_calls_scale():
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock)
    ctl = gl.Lifecycle(_cfg(dry=True), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    code, _ = ctl.wake("heavy")
    assert code == 202 and fake.calls == [] and ctl.events[-1]["event"] == "scale_dry_run"


def test_scale_error_is_reported_not_raised():
    class Broken(gl.FakeFireworks):
        def scale(self, n):
            raise gl.FireworksError("PATCH :scale: HTTP 403: permission denied", 403)

    clock = gl.FakeClock(gl.SIM_START)
    ctl = gl.Lifecycle(_cfg(), Broken(clock), clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    code, body = ctl.wake("heavy")
    assert code == 502 and "403" in body["detail"]


def test_session_end_sleep_skipped_when_another_session_is_still_sending():
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    ctl = gl.Lifecycle(_cfg(), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    ctl.wake("heavy")
    clock.advance(15)
    ctl.tick()
    ctl.session_end("unknown-after-restart")              # registry was lost; a live session keeps sending
    clock.advance(20)
    ctl.touch("start", "c1")
    ctl.touch("end", "c1")
    clock.advance(30)
    ctl.tick()
    assert not [c for c in ctl.scale_calls if c[1] == 0]
    assert any(e["event"] == "sleep_skipped" for e in ctl.events)


def test_inflight_request_is_never_cut_by_idle_rule():
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    ctl = gl.Lifecycle(_cfg(), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    ctl.wake("heavy")
    ctl.touch("start", "long")
    for _ in range(40):                                   # a 10-minute generation
        clock.advance(15)
        ctl.tick()
    assert fake.replicas == 1 and not [c for c in ctl.scale_calls if c[1] == 0]
    ctl.touch("end", "long")
    for _ in range(14):
        clock.advance(15)
        ctl.tick()
    assert fake.replicas == 0 and ctl.scale_calls[-1][2] == "idle"


# ---------------------------------------------------------------- HTTP API + real-clock harness

class LiveController:
    """Controller on a real port with a fast simulated deployment and a background ticker."""

    def __init__(self, cold_start_s=0.3, **cfg_over):
        self.fake = gl.FakeFireworks(time.time, cold_start_s=cold_start_s)
        self.ctl = gl.Lifecycle(_cfg(poll_s=0.05, **cfg_over), self.fake, out=io.StringIO(), firectl=lambda _d: None)
        self.ctl.recheck()
        self.srv = gl.start_server(self.ctl, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.stop = threading.Event()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        threading.Thread(target=self._tick, daemon=True).start()

    def _tick(self):
        while not self.stop.wait(0.05):
            self.ctl.tick()

    def close(self):
        self.stop.set()
        self.srv.shutdown()

    def env(self):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("GEM_", "AUTODEV_"))}
        e.update(GEM_LIFECYCLE_URL=self.url, GEM_LIFECYCLE_TOKEN=TOKEN)
        return e


@pytest.fixture
def live():
    lc = LiveController()
    yield lc
    lc.close()


def _http(url, method="GET", body=None, token=TOKEN, raw=None):
    import urllib.error
    import urllib.request
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_http_auth_and_routes(live):
    assert _http(live.url + "/health", token=None) == (200, {"status": "ok", "version": gl.__version__})
    assert _http(live.url + "/status", token=None)[0] == 401
    assert _http(live.url + "/status", token="wrong-token-0000000")[0] == 401
    assert _http(live.url + "/wake", "POST", {}, token=None)[0] == 401
    code, st = _http(live.url + "/status")
    assert code == 200 and st["b200"] == "asleep" and st["cap_day_usd"] == 26.0
    assert _http(live.url + "/nope", "POST", {})[0] == 404
    assert _http(live.url + "/sleep", "POST", raw=b"{bad")[0] == 400
    assert _http(live.url + "/sleep", "POST", raw=b"x" * 5000)[0] == 400
    assert _http(live.url + "/touch", "POST", {"event": "sideways"})[0] == 400
    assert _http(live.url + "/wake", "POST", {"reason": "manual"})[0] == 202


def test_bind_refuses_public_interfaces(monkeypatch):
    monkeypatch.delenv("GEM_LIFECYCLE_ALLOW_REMOTE", raising=False)
    with pytest.raises(SystemExit):
        gl._bind(_cfg(bind="0.0.0.0:8090"))
    assert gl._bind(_cfg(bind="127.0.0.1:8090")) == ("127.0.0.1", 8090)


def _gemctl(args, env):
    return subprocess.run([PY, GEMCTL, *args], capture_output=True, text=True, env=env, timeout=60)


def test_gemctl_heavy_on_waits_until_ready_then_off(live):
    r = _gemctl(["heavy", "on", "--poll", "0.1", "--wait", "20", "--export"], live.env())
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "export ANTHROPIC_MODEL=ds-burst" and "/model ds-burst" in r.stderr
    assert live.fake.replicas == 1 and live.ctl.heavy
    r = _gemctl(["heavy", "off"], live.env())
    assert r.returncode == 0 and "/model ds-main" in r.stderr
    deadline = time.time() + 5
    while live.fake.replicas and time.time() < deadline:
        time.sleep(0.05)
    assert live.fake.replicas == 0
    st = json.loads(_gemctl(["heavy", "status"], live.env()).stdout)
    assert st["b200"] == "asleep" and st["heavy"] is False


def test_gemctl_heavy_on_refused_by_cap(live):
    gl._preload(live.ctl, day_usd=25.0, week_usd=25.0)
    r = _gemctl(["heavy", "on"], live.env())
    assert r.returncode == 2 and "today's GPU cap" in r.stderr and live.fake.calls == []


def test_gemctl_heavy_on_reports_still_warming():
    lc = LiveController(cold_start_s=30)
    try:
        r = _gemctl(["heavy", "on", "--poll", "0.1", "--wait", "1"], lc.env())
        assert r.returncode == 3 and "still waking" in r.stderr
    finally:
        lc.close()


def test_gemctl_heavy_unreachable_controller():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GEM_")}
    env.update(GEM_LIFECYCLE_URL="http://127.0.0.1:9", GEM_LIFECYCLE_TOKEN=TOKEN)
    r = _gemctl(["heavy", "status"], env)
    assert r.returncode == 1 and "unreachable" in r.stderr and "8090" in r.stderr


# ---------------------------------------------------------------- Claude Code session hooks

def test_session_hooks_register_and_schedule_sleep(live):
    live.ctl.wake("heavy")
    r = subprocess.run([PY, START], input=json.dumps({"session_id": "s-1", "source": "startup"}),
                       capture_output=True, text=True, env=live.env(), timeout=30)
    assert r.returncode == 0 and "B200 burst" in r.stdout and "of $26.0" in r.stdout
    assert "s-1" in live.ctl.sessions
    r = subprocess.run([PY, END], input=json.dumps({"session_id": "s-1", "reason": "exit"}),
                       capture_output=True, text=True, env=live.env(), timeout=30)
    assert r.returncode == 0 and r.stdout == ""
    assert live.ctl.sessions == {} and live.ctl.sleep_reason == "session_end"


def test_session_hooks_are_silent_without_controller():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GEM_", "AUTODEV_"))}
    r = subprocess.run([PY, START], input="{}", capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0 and "B200" not in r.stdout
    env.update(GEM_LIFECYCLE_URL="http://127.0.0.1:9", GEM_LIFECYCLE_TOKEN=TOKEN)
    r = subprocess.run([PY, START], input="{}", capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0 and "controller unreachable" in r.stdout
    r = subprocess.run([PY, END], input="{}", capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0 and r.stdout == ""


def test_installer_adds_session_end_and_copies_client(tmp_path):
    settings, home = tmp_path / "settings.json", tmp_path / "gemhome"
    r = subprocess.run([PY, INSTALL, "--settings", str(settings), "--gem-home", str(home)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    hooks = json.loads(settings.read_text())["hooks"]
    assert set(hooks) == {"PreToolUse", "SessionStart", "SessionEnd"}
    assert "gem_session_end.py" in hooks["SessionEnd"][0]["hooks"][0]["command"]
    assert (home / "lib" / "gem_lifecycle_client.py").exists() and (home / "hooks" / "gem_session_end.py").exists()
    subprocess.run([PY, INSTALL, "--settings", str(settings), "--gem-home", str(home)], check=True,
                   capture_output=True, timeout=30)
    assert len(json.loads(settings.read_text())["hooks"]["SessionEnd"]) == 1        # idempotent
    subprocess.run([PY, INSTALL, "--remove", "--settings", str(settings), "--gem-home", str(home)], check=True,
                   capture_output=True, timeout=30)
    assert "hooks" not in json.loads(settings.read_text())


# ---------------------------------------------------------------- LiteLLM callback

def _load_callback(monkeypatch, live):
    monkeypatch.setenv("GEM_LIFECYCLE_URL", live.url)
    monkeypatch.setenv("GEM_LIFECYCLE_TOKEN", TOKEN)
    monkeypatch.setenv("GEM_LIFECYCLE_SYNC", "1")
    import gem_lifecycle_callback
    return importlib.reload(gem_lifecycle_callback)


def test_callback_unit_paths(monkeypatch, live):
    cb = _load_callback(monkeypatch, live)
    h = cb.proxy_handler_instance
    burst = {"litellm_call_id": "c-9", "litellm_params": {"litellm_metadata": {"model_group": "ds-burst"}}}
    h.log_pre_api_call("x", [], burst)
    assert "c-9" in live.ctl.inflight
    asyncio.run(h.async_log_success_event(burst, None, None, None))
    assert "c-9" not in live.ctl.inflight and live.ctl.last_traffic

    class RateLimited(Exception):
        status_code = 429

    main = {"litellm_params": {"metadata": {"model_group": "ds-main"}}, "exception": RateLimited()}
    for _ in range(3):
        asyncio.run(h.async_log_failure_event(main, None, None, None))
    assert live.fake.desired == 1                           # 429 storm woke the B200
    other = {"litellm_params": {"metadata": {"model_group": "ds-main"}}, "exception": Exception("boom")}
    asyncio.run(h.async_log_failure_event(other, None, None, None))   # non-429 is ignored, never raises


def test_callback_with_real_litellm_router(monkeypatch, live):
    litellm = pytest.importorskip("litellm")
    cb = _load_callback(monkeypatch, live)
    seen = []
    orig = live.ctl.touch
    monkeypatch.setattr(live.ctl, "touch", lambda e, c: (seen.append((e, c)), orig(e, c))[1])
    router = litellm.Router(model_list=[
        {"model_name": "ds-burst", "litellm_params": {"model": "openai/accounts/demo/deployments/b200",
                                                       "api_key": "x", "mock_response": "hi"}},
        {"model_name": "ds-main", "litellm_params": {"model": "openai/accounts/fireworks/models/m",
                                                      "api_key": "x", "mock_response": "litellm.RateLimitError"}},
    ], num_retries=0)
    old = list(litellm.callbacks)
    litellm.callbacks = [cb.proxy_handler_instance]
    try:
        async def go():
            await router.acompletion(model="ds-burst", messages=[{"role": "user", "content": "hi"}])
            for _ in range(3):
                with pytest.raises(Exception):
                    await router.acompletion(model="ds-main", messages=[{"role": "user", "content": "hi"}])
            await asyncio.sleep(0.5)                        # success/failure loggers run as tasks
        asyncio.run(go())
    finally:
        litellm.callbacks = old
    touches = [e for e in live.ctl.events if e["event"] == "rate_limited"]
    assert [e for e, _ in seen] == ["start", "end"], seen    # ds-burst only; ds-main never touches
    assert seen[0][1] and seen[0][1] == seen[1][1]            # same litellm_call_id on both
    assert not live.ctl.inflight
    assert len(touches) >= 3 and live.fake.desired == 1


# ---------------------------------------------------------------- Fireworks wire format

def test_fireworks_client_wire_format():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    seen = []

    class FW(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers.get("Authorization"), None))
            if self.path == "/v1/accounts/demo/deployments/b200":
                return self._reply(200, {"state": "READY", "replicaCount": 1, "acceleratorCount": 4})
            return self._reply(404, {"error": {"message": "not found"}})

        def do_PATCH(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n))
            seen.append(("PATCH", self.path, self.headers.get("Authorization"), body))
            if body.get("replicaCount") == 99:
                return self._reply(403, {"error": {"message": "quota"}})
            return self._reply(200, {})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), FW)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        c = gl.FireworksClient("accounts/demo/deployments/b200", "fw-key", base=base)
        snap = gl.Snapshot.from_api(c.get(), 4)
        assert snap.up and snap.label == "ready" and snap.desired == 0     # proto3 omits zero fields
        c.scale(0)
        assert seen[-1] == ("PATCH", "/v1/accounts/demo/deployments/b200:scale", "Bearer fw-key", {"replicaCount": 0})
        with pytest.raises(gl.FireworksError) as e:
            c.scale(99)
        assert e.value.status == 403 and "quota" in str(e.value) and "fw-key" not in str(e.value)
        with pytest.raises(gl.FireworksError) as e:
            gl.FireworksClient("accounts/demo/deployments/nope", "k", base=base).get()
        assert e.value.status == 404
        with pytest.raises(gl.FireworksError):
            gl.FireworksClient("accounts/demo/deployments/b200", "k", base="http://127.0.0.1:9", timeout=1).get()
    finally:
        srv.shutdown()


def test_restart_mid_run_resumes_instead_of_killing(tmp_path):
    state = str(tmp_path / "lifecycle.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = gl.Lifecycle(_cfg(state_path=state), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    a.recheck()
    a.set_heavy(True)
    clock.advance(15)
    a.tick()
    a.touch("start", "c1")
    a.touch("end", "c1")
    clock.advance(30)                                         # restart during the heavy run
    b = gl.Lifecycle(_cfg(state_path=state), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    b.recheck()
    b.tick()
    assert fake.replicas == 1 and b.wake_reason == "heavy" and any(e["event"] == "resumed" for e in b.events)
    for _ in range(14):
        clock.advance(15)
        b.tick()
    assert fake.replicas == 0 and b.scale_calls[-1][2] == "idle"


def test_status_before_first_tick_with_gpu_up():
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    fake.scale(1)
    clock.advance(1)
    ctl = gl.Lifecycle(_cfg(), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    st = ctl.status()
    assert st["b200"] == "ready" and st["idle_for_s"] == 0


def test_transient_check_failure_is_marked_for_retry():
    class Down(gl.FakeFireworks):
        def get(self):
            raise gl.FireworksError("GET: timed out")

    ctl = gl.Lifecycle(_cfg(), Down(gl.FakeClock(gl.SIM_START)), clock=gl.FakeClock(gl.SIM_START),
                       out=io.StringIO(), firectl=lambda _d: None)
    code, rep = ctl.recheck()
    assert code == 503 and rep["info"]["transient"] is True and ctl.wake_disabled


def test_accept_risk_turns_unknown_autodelete_into_a_warning():
    doc = _doc()
    doc.pop("unusedAutoDeleteDuration")
    rep = gl.check_deployment(doc, _cfg(autodelete_accept_risk=True))
    assert rep.ok and any("can't be read from the Fireworks API" in w for w in rep.warn)
    rep = gl.check_deployment(_doc(unusedAutoDeleteDuration="168h"), _cfg(autodelete_accept_risk=True))
    assert rep.ok and any("cannot change it" in w for w in rep.warn)


def test_autodelete_hint_does_not_suggest_an_update_flag_that_does_not_exist():
    doc = _doc()
    doc.pop("unusedAutoDeleteDuration")
    hard = " ".join(gl.check_deployment(doc, _cfg()).hard)
    assert "deployment update cannot change it" in hard and "deployment create" in hard
    assert "update accounts/demo/deployments/b200 --unused-auto-delete-duration" not in hard


def test_api_base_override_is_loopback_only():
    assert not _cfg(api_base="http://127.0.0.1:9999").validate()
    assert any("loopback" in e for e in _cfg(api_base="https://evil.example").validate())
    assert gl.Config.from_env({"GEM_BURST_DEPLOYMENT": "accounts/a/deployments/b"}).api_base == gl.API_BASE


def test_status_reports_autodelete_mode_and_idle_days():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = gl.Lifecycle(_cfg(autodelete_accept_risk=True), gl.FakeFireworks(clock, extra={}), clock=clock,
                       out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    ctl.touch("end", "c1")
    clock.advance(3 * 86400)
    st = ctl.status()
    assert st["auto_delete"] == "risk accepted" and st["days_since_b200_traffic"] == 3.0 and not st["wake_disabled"]
