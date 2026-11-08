"""End-to-end test of lifecycle/deploy_awsbox.sh in a scratch root (WU-07 deploy).

A fake Fireworks API checks the bearer and records scale calls; a stand-in systemctl starts the controller exactly
as the rendered unit says (User=, Group=, EnvironmentFile=, ExecStart=), reading the env file with systemd's rules
rather than a shell's, so an inline "# comment" ends up in the value just as it does under real systemd.
Needs root, runuser and useradd.
"""
import inspect
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "lifecycle"))
import gem_lifecycle as gl  # noqa: E402

SCRIPT = os.path.join(ROOT, "lifecycle", "deploy_awsbox.sh")
EXAMPLE = os.path.join(ROOT, "lifecycle", "lifecycle.env.example")
KEY = "fw_TESTKEY_0123456789abcdef"
DEP = "accounts/demo/deployments/b200"

needs_root = pytest.mark.skipif(
    os.geteuid() != 0 or not shutil.which("runuser") or not shutil.which("useradd"),
    reason="deploy e2e needs root, runuser and useradd")

def systemd_env(path):
    """systemd.exec(5), EnvironmentFile=: lines starting with "#" or ";" are comments; everything else after the
    first "=" is the value with only leading/trailing whitespace dropped. A "#" later on the line is in the value."""
    env = {}
    for raw in open(path, encoding="utf-8").read().split("\n"):
        line = raw.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        key, val = line.split("=", 1)
        env[key.strip()] = val.strip()
    return env


STUB = r'''#!/usr/bin/env python3
"""Stand-in for systemctl: runs the unit the way systemd would (User=, Group=, EnvironmentFile=, ExecStart=)."""
import grp, os, pwd, shlex, signal, subprocess, sys, time
''' + inspect.getsource(systemd_env) + r'''
prefix = os.environ["GEM_DEPLOY_PREFIX"]
run = os.path.join(prefix, "run"); os.makedirs(run, exist_ok=True)
pidf, logf = os.path.join(run, "pid"), os.path.join(run, "service.log")
args = [a for a in sys.argv[1:] if not a.startswith("-")]
cmd = args[0] if args else ""
unit = os.path.join(prefix, "etc/systemd/system", args[1] if len(args) > 1 else "gem-lifecycle.service")

def stop():
    try:
        pid = int(open(pidf).read())
        os.killpg(pid, signal.SIGTERM)
        for _ in range(50):
            os.killpg(pid, 0); time.sleep(0.1)
    except (OSError, ValueError):
        pass
    if os.path.exists(pidf): os.remove(pidf)

def start():
    kv = {}
    for line in open(unit):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); kv[k] = v
    pw = pwd.getpwnam(kv["User"])
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name,
           "SHELL": pw.pw_shell}
    env.update(systemd_env(kv["EnvironmentFile"]))
    p = subprocess.Popen(shlex.split(kv["ExecStart"]), env=env, cwd="/", user=pw.pw_uid,
                         group=grp.getgrnam(kv.get("Group", kv["User"])).gr_gid, extra_groups=[],
                         stdout=open(logf, "a"), stderr=subprocess.STDOUT, start_new_session=True)
    open(pidf, "w").write(str(p.pid))

if cmd in ("daemon-reload", "list-units"): pass
elif cmd == "enable": open(os.path.join(run, "enabled"), "w").close()
elif cmd == "disable":
    if "--now" in sys.argv: stop()
    if os.path.exists(os.path.join(run, "enabled")): os.remove(os.path.join(run, "enabled"))
elif cmd == "restart": stop(); start()
elif cmd == "status": sys.stdout.write(open(logf).read()[-3000:] if os.path.exists(logf) else "no log\n")
else: sys.exit(f"stub systemctl: unsupported {sys.argv[1:]}")
'''


class FakeFireworks:
    def __init__(self):
        self.calls = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authed(self):
                return self.headers.get("Authorization") == f"Bearer {KEY}"

            def do_GET(self):
                if not self._authed():
                    return self._reply(401, {"error": {"message": "invalid api key"}})
                return self._reply(200, {"state": "READY", "minReplicaCount": 0, "maxReplicaCount": 1,
                                         "acceleratorCount": 4, "replicaCount": outer.replicas,
                                         "desiredReplicaCount": outer.replicas,
                                         "autoscalingPolicy": {"scaleToZeroWindow": "3600s"}})

            def do_PATCH(self):
                if not self._authed():
                    return self._reply(401, {"error": {"message": "invalid api key"}})
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                outer.calls.append((self.path, body))
                outer.replicas = body.get("replicaCount", 0)
                return self._reply(200, {})

        self.replicas = 0
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def box():
    """Scratch root + a copy of the package whose env example points at the fake API (first-install path)."""
    fw = FakeFireworks()
    prefix = tempfile.mkdtemp(prefix="gemroot-", dir="/tmp")
    os.chmod(prefix, 0o755)
    pkg = os.path.join(prefix, "pkg")
    shutil.copytree(ROOT, pkg, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    port = _free_port()
    with open(os.path.join(pkg, "lifecycle", "lifecycle.env.example"), "a") as fh:
        fh.write(f"GEM_FIREWORKS_API_BASE={fw.url}\nGEM_LIFECYCLE_BIND=127.0.0.1:{port}\nGEM_POLL_S=0.2\n")
    stub = os.path.join(prefix, "systemctl")
    with open(stub, "w") as fh:
        fh.write(STUB)
    os.chmod(stub, 0o755)
    keyfile = os.path.join(prefix, "key.txt")
    with open(keyfile, "w") as fh:
        fh.write(KEY + "\n")
    os.chmod(keyfile, 0o600)
    b = type("Box", (), {})()
    b.fw, b.prefix, b.pkg, b.port, b.keyfile = fw, prefix, pkg, port, keyfile
    b.root = os.path.join(prefix, "root")
    b.env = os.path.join(b.root, "etc/gem/lifecycle.env")
    b.script = os.path.join(pkg, "lifecycle", "deploy_awsbox.sh")

    def run(*args, stdin=subprocess.DEVNULL):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GEM_")}
        env.update(GEM_DEPLOY_PREFIX=b.root, GEM_SYSTEMCTL=stub)
        return subprocess.run(["bash", b.script, "--deployment", DEP, *args], env=env, stdin=stdin,
                              capture_output=True, text=True, timeout=120)

    def envmap():
        return systemd_env(b.env)

    def http(method, path, body=None, token="GEM_LIFECYCLE_TOKEN"):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {envmap()[token]}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def pid():
        p = os.path.join(b.root, "run", "pid")
        return open(p).read().strip() if os.path.exists(p) else None

    b.run, b.envmap, b.http, b.pid = run, envmap, http, pid
    yield b
    subprocess.run([stub, "disable", "--now", "gem-lifecycle.service"],
                   env={**os.environ, "GEM_DEPLOY_PREFIX": b.root}, capture_output=True)
    fw.close()
    shutil.rmtree(prefix, ignore_errors=True)


def test_example_env_loads_like_systemd_into_valid_config():
    env = systemd_env(EXAMPLE)
    inline = {k: v for k, v in env.items() if "#" in v or any(c.isspace() for c in v)}
    assert not inline, f"systemd would pass these values with the comment included: {inline}"
    cfg = gl.Config.from_env(env)
    assert cfg.validate() == []
    assert (cfg.gpu_rate_usd_per_hour, cfg.cap_day_usd, cfg.cap_week_usd, cfg.tz, cfg.request_lease_s) == \
        (13.0, 26.0, 78.0, "America/Chicago", 660.0)
    assert {"GEM_LIFECYCLE_TOKEN", "GEM_LIFECYCLE_FEED_TOKEN", "GEM_LIFECYCLE_SESSION_TOKEN"} <= set(env)


def test_script_passes_shellcheck():
    sc = shutil.which("shellcheck")
    if not sc:
        pytest.skip("shellcheck not installed")
    r = subprocess.run([sc, "-S", "style", SCRIPT], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


@needs_root
def test_install_upgrade_wake_uninstall(box):
    r = box.run("--api-key-file", box.keyfile, "--accept-autodelete-risk", "--yes")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    env = box.envmap()
    assert KEY not in out and env["GEM_LIFECYCLE_TOKEN"] not in out        # secrets never printed
    tokens = [env[k] for k in ("GEM_LIFECYCLE_TOKEN", "GEM_LIFECYCLE_FEED_TOKEN", "GEM_LIFECYCLE_SESSION_TOKEN")]
    assert env["FIREWORKS_API_KEY"] == KEY and all(len(t) >= 40 for t in tokens) and len(set(tokens)) == 3
    assert not any(t in out for t in tokens)
    assert env["GEM_LIFECYCLE_DRY"] == "1" and env["GEM_AUTODELETE_ACCEPT_RISK"] == "1"
    n = len(gl.SCENARIOS)
    assert f"{n}/{n} scenarios passed" in out and "mode: DRY" in out and "wakes enabled" in out
    assert "backstop is 60 min" in out and "--scale-to-zero-window 5m" in out
    st = os.stat(box.env)
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_uid == 0
    import grp
    assert grp.getgrgid(st.st_gid).gr_name == "gem"
    unit = open(os.path.join(box.root, "etc/systemd/system/gem-lifecycle.service")).read()
    assert f"EnvironmentFile={box.env}" in unit and f"{box.root}/opt/gem/gem_lifecycle.py serve" in unit
    code, s = box.http("GET", "/status")
    assert code == 200 and s["dry_run"] is True and s["auto_delete"] == "risk accepted"
    assert box.http("GET", "/status", token="GEM_LIFECYCLE_SESSION_TOKEN")[0] == 200
    assert box.http("POST", "/heavy", {"on": True}, token="GEM_LIFECYCLE_SESSION_TOKEN")[0] == 403
    assert box.http("POST", "/heavy", {"on": True}, token="GEM_LIFECYCLE_FEED_TOKEN")[0] == 403
    assert box.http("POST", "/touch", {"event": "end", "call_id": "c1"}, token="GEM_LIFECYCLE_FEED_TOKEN")[0] == 200
    code, _ = box.http("POST", "/heavy", {"on": True})
    assert code == 202 and box.fw.calls == []                               # DRY: decided, not sent

    first_pid, before = box.pid(), box.envmap()
    r = box.run("--live", "--yes")                                           # upgrade in place
    assert r.returncode == 0, r.stdout + r.stderr
    assert "mode: LIVE" in r.stdout and "API key kept" in r.stdout
    assert all(f"{role} token kept" in r.stdout for role in ("operator", "feed", "session"))
    assert all(box.envmap()[k] == before[k] for k in before if k.endswith("_TOKEN")) and box.pid() != first_pid
    code, s = box.http("GET", "/status")
    assert s["dry_run"] is False
    code, _ = box.http("POST", "/heavy", {"on": True})
    assert code == 202 and box.fw.calls[-1] == (f"/v1/{DEP}:scale", {"replicaCount": 1})
    code, _ = box.http("POST", "/heavy", {"on": False})
    assert code == 202 and box.fw.calls[-1] == (f"/v1/{DEP}:scale", {"replicaCount": 0})
    assert os.path.exists(os.path.join(box.root, "var/lib/gem/lifecycle.json"))   # ledger written by gem

    r = box.run("--uninstall")
    assert r.returncode == 0 and box.pid() is None, r.stdout + r.stderr
    assert "B200 scaled to zero" in r.stdout
    assert not os.path.exists(os.path.join(box.root, "etc/systemd/system/gem-lifecycle.service"))
    assert os.path.exists(box.env)                                           # config kept without --purge
    r = box.run("--uninstall", "--purge")                                    # controller gone: can't confirm
    assert r.returncode == 1 and os.path.exists(box.env)
    assert "firectl deployment scale b200 --replica-count 0" in r.stderr and "--force" in r.stderr
    r = box.run("--uninstall", "--purge", "--force")
    assert r.returncode == 0 and not os.path.exists(box.env)


@needs_root
def test_bad_api_key_stops_before_the_service_starts(box):
    with open(box.keyfile, "w") as fh:
        fh.write("fw_wrong_key\n")
    r = box.run("--api-key-file", box.keyfile, "--autodelete-off", "--yes")
    assert r.returncode == 1 and "Fireworks API refused the read" in r.stderr
    assert "HTTP 401" in r.stdout and box.pid() is None


@needs_root
def test_non_interactive_without_key_explains_what_to_do(box):
    r = box.run("--yes")
    assert r.returncode == 1 and "--api-key-file" in r.stderr


@needs_root
def test_unconfirmed_autodelete_keeps_wakes_off(box):
    r = box.run("--api-key-file", box.keyfile, "--yes")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "auto-delete: unconfirmed" in out and "wakes disabled" in out
    code, body = box.http("POST", "/heavy", {"on": True})
    assert code == 503 and body["refused"] == "guard"


@needs_root
def test_uninstall_scales_the_b200_down_first(box):
    r = box.run("--api-key-file", box.keyfile, "--accept-autodelete-risk", "--live", "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    code, _ = box.http("POST", "/heavy", {"on": True})
    assert code == 202 and box.fw.replicas == 1
    r = box.run("--uninstall", "--purge")
    assert r.returncode == 0, r.stdout + r.stderr
    assert box.fw.replicas == 0 and box.fw.calls[-1] == (f"/v1/{DEP}:scale", {"replicaCount": 0})
    assert box.pid() is None and not os.path.exists(box.env)


@needs_root
def test_inline_comments_are_moved_and_other_bad_values_refused(box):
    r = box.run("--api-key-file", box.keyfile, "--accept-autodelete-risk", "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    with open(box.env, "a") as fh:                       # a hand edit in the style of the old example file
        fh.write("GEM_IDLE_SLEEP_S=180          # after the last request\n")
    r = box.run("--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "moved 1 inline comment" in r.stdout and box.envmap()["GEM_IDLE_SLEEP_S"] == "180"
    assert "# after the last request" in open(box.env).read()
    with open(box.env, "a") as fh:
        fh.write("GEM_NOTE=two words\n")
    r = box.run("--yes")
    assert r.returncode == 1 and "GEM_NOTE" in r.stderr and "whitespace" in r.stderr
    assert "two words" not in r.stderr                    # values (they may be secrets) are never echoed
