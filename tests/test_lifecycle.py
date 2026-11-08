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
TOKEN = "test-token-0123456789"                 # operator
FEED = "feed-token-0123456789"
SESSION = "session-token-0123456789"


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
    cfg = gl.Config.from_env({"GEM_BURST_MODEL": "openai/accounts/example/deployments/b200",
                              "GEM_GPU_CAP_DAY_USD": "26", "GEM_GPU_CAP_WEEK_USD": "20"})
    assert cfg.deployment == "accounts/example/deployments/b200"
    assert "weekly cap is below the daily cap" in cfg.validate()
    assert gl.Config.from_env({"GEM_BURST_DEPLOYMENT": "b200"}).validate()[0].startswith("GEM_BURST_DEPLOYMENT")


def _doc(**over):
    d = {"state": "READY", "minReplicaCount": 0, "maxReplicaCount": 1, "acceleratorCount": 4,
         "autoscalingPolicy": {"scaleToZeroWindow": "300s"}, "unusedAutoDeleteDuration": "0s"}
    d.update(over)
    return d


def _cfg(**over):
    base = gl.Config(deployment="accounts/demo/deployments/b200", token=TOKEN, feed_token=FEED, session_token=SESSION)
    return dataclasses.replace(base, **over)


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

def _mk(clock, fake, **over):
    ctl = gl.Lifecycle(_cfg(**over), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    return ctl


def _usd(gpu_s):
    return gpu_s * 13 / 3600


def test_restart_bills_the_whole_gap_at_the_saved_replica_count(tmp_path):
    state = str(tmp_path / "lifecycle.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = _mk(clock, fake, state_path=state)
    a.wake("heavy")
    for _ in range(4):
        clock.advance(15)
        a.tick()
    spent = a.spend()[0]
    assert spent > 0 and json.load(open(state))["replicas"] == 1
    clock.advance(7200)                                   # controller down for 2 h while the GPU stays up
    b = gl.Lifecycle(a.cfg, fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    assert b.spend()[0] == pytest.approx(spent)
    b.tick()
    assert b.spend()[0] == pytest.approx(spent + _usd(7200 * 4))          # all of it, no max_gap_s cap
    ev = [e for e in b.events if e["event"] == "restart_gap_billed"]
    assert ev and ev[0]["seconds"] == 7200 and ev[0]["usd"] == pytest.approx(104.0)
    assert "unmetered_gap_s" not in b.status() and not hasattr(b, "unmetered_gap_s")


def test_restart_bills_the_gap_even_when_fireworks_drained_it_meanwhile(tmp_path):
    state = str(tmp_path / "s.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = _mk(clock, fake, state_path=state)
    a.set_heavy(True)
    for _ in range(4):
        clock.advance(15)
        a.tick()
    clock.advance(1800)                                   # down 30 min with the GPU billing ...
    fake.scale(0)                                         # ... then Fireworks' backstop drains it
    clock.advance(60)
    b = _mk(clock, fake, state_path=state)
    b.tick()
    assert b.spend()[0] >= _usd(fake.billed_gpu_s)        # was ~$26 short before the fix
    assert [e for e in b.events if e["event"] == "restart_gap_billed"][0]["replicas"] == 1


def test_save_fsyncs_file_then_directory(tmp_path, monkeypatch):
    seen = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(gl.os, "fsync", lambda fd: (seen.append(("fsync", "dir" if __import__("stat").S_ISDIR(
        os.fstat(fd).st_mode) else "file")), real_fsync(fd))[1])
    monkeypatch.setattr(gl.os, "replace", lambda a, b: (seen.append(("replace",)), real_replace(a, b))[1])
    ctl = gl.Lifecycle(_cfg(state_path=str(tmp_path / "s.json")), gl.FakeFireworks(gl.FakeClock(gl.SIM_START)),
                       clock=gl.FakeClock(gl.SIM_START), out=io.StringIO())
    ctl._save()
    assert seen == [("fsync", "file"), ("replace",), ("fsync", "dir")]


@pytest.mark.parametrize("content", ["", "{not json", "[]", '{"version": 2}', '{"gpu_seconds": {"day:x": "lots"}}'])
def test_damaged_ledger_refuses_wakes_until_the_weekly_rollover(tmp_path, content):
    state = tmp_path / "lifecycle.json"
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = _mk(clock, fake, state_path=str(state))
    gl._preload(a, 25.9, 77.9)
    a._save()
    state.write_text(content)                             # e.g. zero-length after a crash before fsync
    b = _mk(clock, fake, state_path=str(state))
    assert any(p.name.startswith("lifecycle.json.corrupt-") for p in tmp_path.iterdir())
    assert any(e["event"] == "state_unreadable" for e in b.events)
    code, body = b.wake("heavy")
    rollover = gl.next_rollover(clock.now, "America/Chicago", "week")
    assert code == 409 and body["refused"] == "cap_ledger" and body["resets_at"] == gl.iso(rollover)
    st = b.status()
    assert st["ledger_lost_until"] == gl.iso(rollover) and st["capped"] == "ledger" and st["binding_cap"] == "ledger"
    assert fake.calls == []
    c = _mk(clock, fake, state_path=str(state))           # persisted: another restart still refuses
    assert c.wake("heavy")[0] == 409
    clock.advance(rollover - clock.now + 1)
    assert c.wake("heavy")[0] == 202 and c.status()["ledger_lost_until"] is None


def test_damaged_ledger_scales_down_a_running_gpu(tmp_path):
    state = tmp_path / "s.json"
    state.write_text("")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    fake.scale(1)
    ctl = _mk(clock, fake, state_path=str(state))
    clock.advance(15)
    ctl.tick()
    assert fake.desired == 0 and ctl.scale_calls[-1][2] == "cap_ledger"


def test_missing_ledger_is_a_first_install_at_zero(tmp_path):
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock), state_path=str(tmp_path / "new" / "lifecycle.json"))
    assert ctl.ledger_lost_until is None and ctl.wake("heavy")[0] == 202


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
    ctl.session_start("A")
    ctl.wake("heavy")
    clock.advance(15)
    ctl.tick()
    ctl.session_end("A")                                  # A ends, but an unregistered client keeps sending
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

    def env(self, role="operator"):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("GEM_", "AUTODEV_"))}
        e.update(GEM_LIFECYCLE_URL=self.url, GEM_HOME=os.path.join(ROOT, "no-such-gem-home"))
        e[{"operator": "GEM_LIFECYCLE_TOKEN", "session": "GEM_LIFECYCLE_SESSION_TOKEN"}[role]] = \
            {"operator": TOKEN, "session": SESSION}[role]
        return e


@pytest.fixture
def live():
    lc = LiveController()
    yield lc
    lc.close()


def _http(url, method="GET", body=None, token=TOKEN, raw=None, timeout=5.0):
    import urllib.error
    import urllib.request
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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
                       capture_output=True, text=True, env=live.env("session"), timeout=30)
    assert r.returncode == 0 and "B200 burst" in r.stdout and "of $26.0" in r.stdout
    assert "s-1" in live.ctl.sessions
    r = subprocess.run([PY, END], input=json.dumps({"session_id": "s-1", "reason": "exit"}),
                       capture_output=True, text=True, env=live.env("session"), timeout=30)
    assert r.returncode == 0 and r.stdout == ""
    assert live.ctl.sessions == {} and live.ctl.sleep_reason == "session_end"


def test_session_hooks_are_silent_without_controller():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GEM_", "AUTODEV_"))}
    r = subprocess.run([PY, START], input="{}", capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0 and "B200" not in r.stdout
    env.update(GEM_LIFECYCLE_URL="http://127.0.0.1:9", GEM_LIFECYCLE_SESSION_TOKEN=SESSION)
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
    monkeypatch.delenv("GEM_LIFECYCLE_TOKEN", raising=False)
    monkeypatch.setenv("GEM_LIFECYCLE_FEED_TOKEN", FEED)
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


# ---------------------------------------------------------------- review hardening (WU-07h)

# Finding 1: systemd keeps inline comments in EnvironmentFile values.

def test_config_tolerates_inline_comments_that_systemd_keeps():
    cfg = gl.Config.from_env({
        "GEM_BURST_DEPLOYMENT": "accounts/a/deployments/b",
        "GEM_GPU_RATE_USD_PER_HOUR": "13.0          # ASSUMPTION: confirm on fireworks.ai/pricing",
        "GEM_CAP_TZ": "America/Chicago              # days and Monday-start weeks roll over in this zone",
        "GEM_IDLE_SLEEP_S": "180\t# after the last request", "GEM_429_WAKE_COUNT": "3 # n"})
    assert (cfg.gpu_rate_usd_per_hour, cfg.tz, cfg.idle_sleep_s, cfg.storm_count) == (13.0, "America/Chicago", 180.0, 3)
    assert cfg.validate() == []


def test_validate_rejects_unknown_time_zone_and_bad_numbers():
    errs = gl.Config.from_env({"GEM_BURST_DEPLOYMENT": "accounts/a/deployments/b", "GEM_CAP_TZ": "America/Chicgo",
                               "GEM_POLL_S": "fast"}).validate()
    assert any("GEM_CAP_TZ" in e for e in errs) and any("GEM_POLL_S" in e for e in errs)
    assert gl.Config.from_env({"GEM_BURST_DEPLOYMENT": "accounts/a/deployments/b", "GEM_CAP_TZ": "UTC"}).validate() == []


def test_serve_reports_a_bad_value_instead_of_crashing():
    env = {"PATH": os.environ["PATH"], "GEM_BURST_DEPLOYMENT": "accounts/a/deployments/b", "FIREWORKS_API_KEY": "k",
           "GEM_LIFECYCLE_TOKEN": TOKEN, "GEM_POLL_S": "fast"}
    r = subprocess.run([PY, "-I", os.path.join(ROOT, "lifecycle", "gem_lifecycle.py"), "serve"], env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "GEM_POLL_S must be a number" in r.stderr and "Traceback" not in r.stderr


# Finding 5: a wake during a drain was reported as ready and then lost.

class SlowDrain(gl.FakeFireworks):
    def scale(self, n):
        super().scale(n)
        if n == 0:
            self._slow_down_at = self.clock() + 40

    def _physics(self):
        now = self.clock()
        self.billed_gpu_s += (now - self._last) * self.replicas * self.gpus
        self._last = now
        if self.desired > self.replicas and self._up_at is not None and now >= self._up_at:
            self.replicas = self.desired
        if self.desired < self.replicas and now >= getattr(self, "_slow_down_at", 0):
            self.replicas = self.desired


def test_wake_during_drain_scales_back_up():
    clock = gl.FakeClock(gl.SIM_START)
    fake = SlowDrain(clock, cold_start_s=0)
    ctl = _mk(clock, fake)
    ctl.set_heavy(True)
    clock.advance(15)
    ctl.tick()
    ctl.set_heavy(False)
    clock.advance(5)
    assert ctl.status()["burst_ready"] is False            # draining: replicas 1, desired 0
    code, _ = ctl.set_heavy(True)
    assert code == 202 and fake.desired == 1 and ctl.scale_calls[-1][1] == 1
    for _ in range(4):
        clock.advance(15)
        ctl.tick()
    assert fake.replicas == 1 and ctl.heavy and ctl.status()["burst_ready"] is True


# Finding 6: restarts dropped in-flight requests and sessions; a transient startup check killed a resumed run.

def test_restart_mid_request_keeps_the_gpu_for_the_running_generation(tmp_path):
    state = str(tmp_path / "s.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = _mk(clock, fake, state_path=state)
    a.set_heavy(True)
    clock.advance(15)
    a.tick()
    a.touch("start", "long")                              # an 8-minute generation starts
    clock.advance(60)
    b = _mk(clock, fake, state_path=state)                # e.g. deploy_awsbox.sh --live restarts the unit
    assert "long" in b.inflight
    for _ in range(16):
        clock.advance(15)
        b.tick()
    assert fake.replicas == 1 and not [c for c in b.scale_calls if c[1] == 0]


def test_restart_keeps_sessions_so_an_unrelated_session_end_does_not_sleep(tmp_path):
    state = str(tmp_path / "s.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = _mk(clock, fake, state_path=state)
    a.session_start("A")
    a.session_start("B")
    a.set_heavy(True)
    clock.advance(15)
    a.tick()
    a.touch("start", "c")
    a.touch("end", "c")
    clock.advance(5)
    b = _mk(clock, fake, state_path=state)
    b.tick()
    assert set(b.sessions) == {"A", "B"}
    b.session_end("B")                                    # B was a ds-main-only session; A is still reading
    for _ in range(4):
        clock.advance(15)
        b.tick()
    assert fake.replicas == 1 and b.sleep_at is None


def test_unknown_session_end_schedules_nothing():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock, cold_start_s=0))
    ctl.set_heavy(True)
    code, body = ctl.session_end("never-registered")
    assert code == 200 and body["known"] is False and ctl.sleep_at is None


def test_persisted_leases_and_sessions_expire_on_reload(tmp_path):
    state = str(tmp_path / "s.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock)
    a = _mk(clock, fake, state_path=state)
    a.touch("start", "old")
    a.session_start("old-session")
    clock.advance(700)                                    # beyond the 660 s lease
    a.touch("start", "new")
    clock.advance(13 * 3600)                              # beyond the 12 h session TTL
    a.session_start("new-session")
    b = _mk(clock, fake, state_path=state)
    assert set(b.sessions) == {"new-session"} and set(b.inflight) == set()
    clock.advance(1)
    b.touch("start", "fresh")
    c = _mk(clock, fake, state_path=state)
    assert set(c.inflight) == {"fresh"}


class FlakyOnce(gl.FakeFireworks):
    n = 0

    def get(self):
        self.n += 1
        if self.n == 1:
            raise gl.FireworksError("GET: timed out")
        return super().get()


def _running_heavy(tmp_path):
    state = str(tmp_path / "s.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = _mk(clock, fake, state_path=state)
    a.set_heavy(True)
    clock.advance(15)
    a.tick()
    a.touch("start", "c")
    a.touch("end", "c")
    clock.advance(10)
    return state, clock


def test_transient_startup_check_does_not_kill_a_resumed_run(tmp_path):
    state, clock = _running_heavy(tmp_path)
    flaky = FlakyOnce(clock, cold_start_s=0)
    flaky.replicas = flaky.desired = 1
    b = _mk(clock, flaky, state_path=state)               # the startup GET times out
    assert b.report.info.get("transient") and b.wake_disabled
    clock.advance(1)
    b.tick()
    assert flaky.desired == 1 and b.wake_reason == "heavy" and not [c for c in b.scale_calls if c[1] == 0]
    assert any(e["event"] == "resumed" for e in b.events)


def test_hard_startup_check_failure_still_stops_a_resumed_run(tmp_path):
    state, clock = _running_heavy(tmp_path)
    bad = gl.FakeFireworks(clock, cold_start_s=0, extra={"unusedAutoDeleteDuration": "604800s"})
    bad.replicas = bad.desired = 1
    b = _mk(clock, bad, state_path=state)
    clock.advance(1)
    b.tick()
    assert bad.desired == 0 and b.scale_calls[-1][2] == "guard"


# Finding 7: a start that arrives after its end held the GPU for the whole lease.

def test_touch_requires_a_call_id():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock))
    assert ctl.touch("start", "")[0] == 400 and ctl.touch("end", "")[0] == 400
    assert ctl.inflight == {} and ctl.last_traffic is None


def test_late_start_after_its_end_is_ignored():
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    ctl = _mk(clock, fake)
    ctl.set_heavy(True)
    clock.advance(15)
    ctl.tick()
    ctl.touch("end", "x")                                  # two daemon threads, delivered out of order
    code, body = ctl.touch("start", "x")
    assert code == 200 and body.get("ignored") and ctl.inflight == {}
    t0 = clock.now
    while fake.replicas and clock.now - t0 < 3600:
        clock.advance(15)
        ctl.tick()
    assert clock.now - t0 < 200                            # was ~1095 s with a 900 s lease


def test_recently_ended_ids_are_bounded_and_expire():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock))
    for i in range(600):
        ctl.touch("end", f"c{i}")
    assert len(ctl.ended) == gl.ENDED_KEEP and "c0" not in ctl.ended and "c599" in ctl.ended
    assert ctl.touch("start", "c0")[1].get("ignored") is None          # forgotten, so it counts again
    clock.advance(2 * ctl.cfg.request_lease_s + 1)
    ctl.tick()
    assert not ctl.ended


def test_request_lease_is_configurable():
    assert gl.Config.from_env({}).request_lease_s == 660.0
    assert gl.Config.from_env({"GEM_REQUEST_LEASE_S": "120"}).request_lease_s == 120.0
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock), request_lease_s=120.0)
    ctl.touch("start", "c")
    clock.advance(121)
    ctl.tick()
    assert ctl.inflight == {} and any(e["event"] == "lease_expired" for e in ctl.events)


# Finding 8: HTTP input handling.

def _raw(url, request: bytes, wait=3.0):
    import socket
    host, port = url.rsplit(":", 1)
    with socket.create_connection((host.split("//")[1], int(port)), timeout=wait) as s:
        s.sendall(request)
        try:
            return s.recv(200)
        except socket.timeout:
            return b"<no response>"


def test_http_rejects_bad_numbers_flags_and_lengths(live):
    for raw in (b'{"delay_s": NaN}', b'{"delay_s": Infinity}', b'{"delay_s": -Infinity}', b'{"delay_s": true}'):
        assert _http(live.url + "/sleep", "POST", raw=raw)[0] == 400, raw
    assert _http(live.url + "/status")[0] == 200 and live.ctl.sleep_at is None
    code, body = _http(live.url + "/sleep", "POST", {"delay_s": 1e12})
    assert code == 202 and live.ctl.sleep_at - time.time() <= gl.MAX_DELAY_S + 5
    assert _http(live.url + "/sleep", "POST", {"delay_s": -5})[1] == {"ok": True, "sleeping": "now"}
    for on in ("false", "true", 1, 0, None):
        assert _http(live.url + "/heavy", "POST", {"on": on})[0] == 400, on
    assert live.fake.desired == 0
    auth = f"Authorization: Bearer {TOKEN}\r\n".encode()
    for length in (b"-1", b"abc", b"1e3"):
        resp = _raw(live.url, b"POST /touch HTTP/1.1\r\nHost: x\r\n" + auth + b"Content-Length: " + length +
                    b"\r\n\r\n" + b"A" * 1000)
        assert resp.startswith(b"HTTP/1.0 400"), (length, resp)


def test_http_client_timeout_releases_stalled_connections(live):
    handler = live.srv.RequestHandlerClass
    assert handler.timeout == 5
    handler.timeout = 0.3
    import socket
    host, port = live.url.split("//")[1].split(":")
    with socket.create_connection((host, int(port)), timeout=3) as s:
        s.sendall(b"GET /status HTTP/1.1\r\n")          # never finishes the request
        start = time.time()
        assert s.recv(100) == b"" and time.time() - start < 2.5


def test_sessions_and_inflight_are_capped(monkeypatch):
    monkeypatch.setattr(gl, "MAX_TRACKED", 3)
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock))
    assert [ctl.session_start(f"s{i}")[0] for i in range(4)] == [200, 200, 200, 429]
    assert ctl.session_start("s0")[0] == 200                # refreshing a known session is fine
    assert [ctl.touch("start", f"c{i}")[0] for i in range(4)] == [200, 200, 200, 429]
    ctl.touch("end", "c0")
    assert ctl.touch("start", "c9")[0] == 200


# Finding 9: wall-clock steps.

def _idle_run_after_step(step_s):
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    ctl = _mk(clock, fake)
    ctl.set_heavy(True)
    clock.advance(15)
    ctl.tick()
    ctl.touch("start", "x")
    ctl.touch("end", "x")
    before = sum(v for k, v in ctl.gpu_seconds.items() if k.startswith("day:"))
    clock.now += step_s                                    # NTP step: wall moves, the monotonic clock does not
    elapsed = 0
    while fake.desired and elapsed < 7200:
        clock.advance(15)
        elapsed += 15
        ctl.tick()
    metered = sum(v for k, v in ctl.gpu_seconds.items() if k.startswith("day:")) - before
    return ctl, elapsed, metered


@pytest.mark.parametrize("step_s", [-3600, 3600])
def test_clock_step_neither_moves_the_idle_sleep_nor_bills_the_step(step_s):
    ctl, elapsed, metered = _idle_run_after_step(step_s)
    assert 180 <= elapsed <= 195                           # idle sleep 180 s after the last request, real time
    assert metered == pytest.approx(elapsed * 4)           # GPU-seconds for the real time only, 4 GPUs
    assert [e for e in ctl.events if e["event"] == "clock_step"][0]["step_s"] == step_s


def test_clock_step_moves_every_timer():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock))
    ctl.session_start("s")
    ctl.touch("start", "c")
    ctl.touch("end", "d")
    ctl.signal_429("ds-main")
    ctl.sleep(45, "manual")
    snap = (dict(ctl.sessions), dict(ctl.inflight), dict(ctl.ended), list(ctl.storm), ctl.sleep_at, ctl.last_traffic)
    clock.now -= 3600
    ctl.status()
    assert dict(ctl.sessions) == {k: v - 3600 for k, v in snap[0].items()}
    assert dict(ctl.inflight) == {k: v - 3600 for k, v in snap[1].items()}
    assert dict(ctl.ended) == {k: v - 3600 for k, v in snap[2].items()}
    assert list(ctl.storm) == [t - 3600 for t in snap[3]]
    assert (ctl.sleep_at, ctl.last_traffic) == (snap[4] - 3600, snap[5] - 3600)


# Finding 10: one token per role.

def test_role_tokens_limit_each_caller_to_its_endpoints(live):
    calls = {"status": ("GET", "/status", None), "wake": ("POST", "/wake", {}),
             "sleep": ("POST", "/sleep", {"delay_s": 600}), "heavy": ("POST", "/heavy", {"on": False}),
             "check": ("POST", "/check", {}), "s_start": ("POST", "/session/start", {"session_id": "s"}),
             "s_end": ("POST", "/session/end", {"session_id": "s"}),
             "touch": ("POST", "/touch", {"event": "end", "call_id": "c"}),
             "429": ("POST", "/signal/429", {"model_group": "ds-main"})}
    allowed = {TOKEN: set(calls), FEED: {"touch", "429"}, SESSION: {"status", "s_start", "s_end"}}
    for tok, ok in allowed.items():
        for name, (method, path, body) in calls.items():
            code = _http(live.url + path, method, body, token=tok)[0]
            assert (code not in (401, 403)) == (name in ok), (tok, name, code)
            if name not in ok:
                assert code == 403, (tok, name, code)
    assert _http(live.url + "/touch", "POST", {"event": "end", "call_id": "c"}, token="x" * 24)[0] == 401
    assert live.fake.desired == 0                          # nobody but the operator woke it


def test_a_missing_role_token_disables_that_role():
    lc = LiveController(feed_token="", session_token="")
    try:
        assert _http(lc.url + "/touch", "POST", {"event": "end", "call_id": "c"}, token=FEED)[0] == 401
        assert _http(lc.url + "/status", token=SESSION)[0] == 401
        assert _http(lc.url + "/status", token="")[0] == 401
        assert _http(lc.url + "/status")[0] == 200
    finally:
        lc.close()
    env = {"PATH": os.environ["PATH"], "GEM_BURST_DEPLOYMENT": "accounts/a/deployments/b", "FIREWORKS_API_KEY": "k",
           "GEM_LIFECYCLE_FEED_TOKEN": FEED}
    r = subprocess.run([PY, "-I", os.path.join(ROOT, "lifecycle", "gem_lifecycle.py"), "serve"], env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "GEM_LIFECYCLE_TOKEN (operator) must be set" in r.stderr


def test_role_tokens_must_be_distinct():
    assert any("must differ" in e for e in _cfg(session_token=TOKEN).validate())
    assert any("at least 16" in e for e in _cfg(feed_token="short").validate())
    assert _cfg().validate() == []


def test_callback_uses_the_feed_token_with_operator_fallback(monkeypatch, live):
    cb = _load_callback(monkeypatch, live)
    monkeypatch.setenv("GEM_LIFECYCLE_TOKEN", TOKEN)
    assert cb._token() == FEED
    monkeypatch.delenv("GEM_LIFECYCLE_FEED_TOKEN")
    assert cb._token() == TOKEN


def test_session_hooks_never_use_the_operator_token(live):
    r = subprocess.run([PY, START], input=json.dumps({"session_id": "s-op"}), capture_output=True, text=True,
                       env=live.env("operator"), timeout=30)
    assert r.returncode == 0 and "B200" not in r.stdout and live.ctl.sessions == {}


def _gem_home(tmp_path, mode=0o600, content=TOKEN):
    home = tmp_path / "gemhome"
    home.mkdir()
    if mode is not None:
        f = home / "operator.token"
        f.write_text(content + "\n")
        os.chmod(f, mode)
    return home


def test_gemctl_heavy_reads_the_operator_token_file(live, tmp_path):
    env = live.env("session")
    env["GEM_HOME"] = str(_gem_home(tmp_path))
    r = _gemctl(["heavy", "status"], env)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["b200"] == "asleep"


@pytest.mark.parametrize("mode,needle", [(0o644, "chmod 600"), (None, "operator.token")])
def test_gemctl_heavy_refuses_a_loose_or_missing_token_file(live, tmp_path, mode, needle):
    env = live.env("session")
    env["GEM_HOME"] = str(_gem_home(tmp_path, mode=mode))
    r = _gemctl(["heavy", "on"], env)
    assert r.returncode == 1 and needle in r.stderr and live.fake.calls == []


def test_claude_gem_env_exports_only_the_session_token(tmp_path):
    home = _gem_home(tmp_path)
    (home / "lib").mkdir()
    (home / "lib" / "gemctl.py").write_text("import os\nprint('gemctl sees', os.environ.get('GEM_LIFECYCLE_TOKEN'))\n")
    script = ('export GEM_LIFECYCLE_TOKEN=leaked-operator LITELLM_VIRTUAL_KEY=v AUTODEV_API_BEARER_TOKEN=a '
              f'GEM_LIFECYCLE_SESSION_TOKEN={SESSION} GEM_HOME="{home}"; '
              f'source "{os.path.join(ROOT, "gateway", "claude-gem.env")}"; '
              'gem heavy status; env | grep "^GEM_LIFECYCLE" | sort')
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert f"gemctl sees {TOKEN}" in r.stdout                           # read from the file at call time
    exported = [line for line in r.stdout.splitlines() if line.startswith("GEM_LIFECYCLE")]
    assert exported == [f"GEM_LIFECYCLE_SESSION_TOKEN={SESSION}", "GEM_LIFECYCLE_URL=http://127.0.0.1:8090"]


def test_installer_never_creates_the_operator_token(tmp_path):
    settings, home = tmp_path / "settings.json", tmp_path / "gemhome"
    r = subprocess.run([PY, INSTALL, "--settings", str(settings), "--gem-home", str(home)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert not (home / "operator.token").exists() and str(home / "operator.token") in r.stdout


# Also fixed: heavy off reports a failed scale call; the cap margin follows the measured loop period.

def test_heavy_off_reports_a_failed_scale_call():
    class NoScaleDown(gl.FakeFireworks):
        def scale(self, n):
            if n == 0:
                raise gl.FireworksError("PATCH :scale: HTTP 503", 503)
            super().scale(n)

    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, NoScaleDown(clock, cold_start_s=0))
    ctl.set_heavy(True)
    clock.advance(15)
    ctl.tick()
    code, body = ctl.set_heavy(False)
    assert code == 502 and "503" in body["detail"]


def test_cap_margin_follows_the_measured_loop_period():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = _mk(clock, gl.FakeFireworks(clock))
    gl._preload(ctl, day_usd=25.2, week_usd=25.2)         # $0.80 left; one 15 s poll margin is $0.43
    for _ in range(3):
        clock.advance(15)
        ctl.tick()
    assert ctl.capped is None
    clock.advance(40)                                     # a loop iteration slowed down by API timeouts
    ctl.tick()
    assert ctl.loop_period_s == 40 and ctl.capped == "day"
    clock.advance(15)
    ctl.tick()
    assert ctl.capped is None
    clock.advance(6 * 86400)                              # a long gap is bounded, not taken as the loop period
    gl._preload(ctl, day_usd=23.0, week_usd=23.0)         # $3 left > the bounded (15+60 s) margin of $2.17
    ctl.tick()
    assert ctl.capped is None


# The state lock is never held across Fireworks I/O: the LiteLLM callback's 1 s posts must not be dropped.

class SlowFireworks(gl.FakeFireworks):
    """Real-clock deployment whose GET and/or scale block, counting how many calls overlap."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.get_delay = self.scale_delay = 0.0
        self.in_call = threading.Event()
        self.active = self.max_active = 0
        self._count = threading.Lock()

    def _slow(self, delay, fn, *args):
        with self._count:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        self.in_call.set()
        try:
            time.sleep(delay)
            return fn(*args)
        finally:
            with self._count:
                self.active -= 1

    def get(self):
        return self._slow(self.get_delay, super().get)

    def scale(self, n):
        return self._slow(self.scale_delay, super().scale, n)


def _served(ctl):
    srv = gl.start_server(ctl, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_touch_during_a_slow_fireworks_get_is_answered_and_keeps_the_gpu_up():
    fake = SlowFireworks(time.time, cold_start_s=0)
    ctl = gl.Lifecycle(_cfg(idle_sleep_s=1.0), fake, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    assert ctl.wake("heavy")[0] == 202
    ctl.tick()
    assert fake.replicas == 1
    time.sleep(1.2)                                       # idle by the rule: the next tick would sleep it
    srv, url = _served(ctl)
    try:
        fake.get_delay = 3.0
        fake.in_call.clear()
        ticker = threading.Thread(target=ctl.tick)
        ticker.start()
        assert fake.in_call.wait(2)                       # the tick is now inside the 3 s GET
        t0 = time.monotonic()
        code, body = _http(url + "/touch", "POST", {"event": "start", "call_id": "c1"}, token=FEED, timeout=1.0)
        took = time.monotonic() - t0
        assert code == 200 and took < 1.0 and "c1" in ctl.inflight, (code, took)
        assert _http(url + "/status", token=SESSION, timeout=1.0)[0] == 200
        assert ticker.is_alive()                          # answered while the GET was still in flight
        ticker.join(10)
        assert not [c for c in ctl.scale_calls if c[1] == 0] and fake.desired == 1   # in flight: not idle
    finally:
        srv.shutdown()


def test_touch_during_a_slow_scale_call_is_answered():
    fake = SlowFireworks(time.time, cold_start_s=0)
    ctl = gl.Lifecycle(_cfg(), fake, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    srv, url = _served(ctl)
    try:
        fake.scale_delay = 3.0
        fake.in_call.clear()
        result = {}
        waker = threading.Thread(target=lambda: result.update(code=ctl.set_heavy(True)[0]))
        waker.start()
        deadline = time.monotonic() + 2
        while fake.active == 0 or not ctl.snapshot:       # wait until the PATCH itself is in flight
            assert time.monotonic() < deadline
            time.sleep(0.01)
        t0 = time.monotonic()
        code, _ = _http(url + "/touch", "POST", {"event": "start", "call_id": "c2"}, token=FEED, timeout=1.0)
        assert code == 200 and time.monotonic() - t0 < 1.0 and "c2" in ctl.inflight
        waker.join(10)
        assert result["code"] == 202 and ctl.heavy and fake.calls[-1][1] == 1
    finally:
        srv.shutdown()


def test_concurrent_ticks_and_wakes_neither_interleave_nor_double_scale():
    fake = SlowFireworks(time.time, cold_start_s=30)
    ctl = gl.Lifecycle(_cfg(), fake, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    fake.get_delay = fake.scale_delay = 0.2
    codes = []
    threads = [threading.Thread(target=lambda: codes.append(ctl.set_heavy(True)[0])) for _ in range(3)]
    threads += [threading.Thread(target=ctl.tick) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert fake.max_active == 1                           # one Fireworks call at a time
    assert [n for _, n in fake.calls] == [1]              # exactly one scale-up for three wakes
    assert sorted(codes) == [200, 200, 202] and ctl.heavy


# ---------------------------------------------------------------- re-review regressions (R1, R2)

def test_litellm_retry_with_the_same_call_id_counts_as_in_flight_again():
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    ctl = gl.Lifecycle(_cfg(), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.recheck()
    ctl.wake("heavy")
    ctl.touch("start", "call-1")
    ctl.touch("end", "call-1")                      # attempt 1 failed (e.g. a 500)
    code, body = ctl.touch("start", "call-1")       # LiteLLM retries with the same id
    assert code == 200 and "ignored" not in body and "call-1" in ctl.inflight
    for _ in range(40):                             # a 10-minute generation on the retry
        clock.advance(15)
        ctl.tick()
    assert fake.replicas == 1 and not [c for c in ctl.scale_calls if c[1] == 0]


def test_end_before_start_still_ignores_the_late_start():
    clock = gl.FakeClock(gl.SIM_START)
    ctl = gl.Lifecycle(_cfg(), gl.FakeFireworks(clock), clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    ctl.touch("end", "c9")
    code, body = ctl.touch("start", "c9")
    assert body.get("ignored") == "call already ended" and "c9" not in ctl.inflight


def test_restart_after_scaling_to_zero_bills_only_the_drain(tmp_path):
    state = str(tmp_path / "lifecycle.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = gl.Lifecycle(_cfg(state_path=state), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    a.recheck()
    a.set_heavy(True)
    clock.advance(15)
    a.tick()
    a.set_heavy(False)                              # uninstall path: desired 0, a replica may still be draining
    before = a.spend()[1]
    clock.advance(3 * 86400)                        # controller gone for three days; deployment drained
    fake.replicas = 0
    b = gl.Lifecycle(_cfg(state_path=state), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    b.recheck()
    b.tick()
    drain_usd = gl.DRAIN_BOUND_S * 4 * 13 / 3600
    assert b.spend()[1] <= before + drain_usd + 0.01
    assert any(e["event"] == "restart_gap_bounded" for e in b.events)
    assert b.wake("heavy")[0] == 202                # not locked out for the week


def test_restart_while_deployment_is_still_up_bills_the_whole_gap(tmp_path):
    state = str(tmp_path / "lifecycle.json")
    clock = gl.FakeClock(gl.SIM_START)
    fake = gl.FakeFireworks(clock, cold_start_s=0)
    a = gl.Lifecycle(_cfg(state_path=state), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    a.recheck()
    a.set_heavy(False)                              # saved desired 0 ...
    fake.scale(1)                                   # ... but something woke it while no controller ran
    clock.advance(1800)
    b = gl.Lifecycle(_cfg(state_path=state), fake, clock=clock, out=io.StringIO(), firectl=lambda _d: None)
    b.recheck()
    b.tick()
    assert not any(e["event"] == "restart_gap_bounded" for e in b.events)
    assert b.spend()[0] >= 1800 * 4 * 13 / 3600 - 0.01
