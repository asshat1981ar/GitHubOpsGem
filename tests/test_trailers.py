"""Tests for Gem-Gate commit trailers + git-notes attestation verify (WU-09b).

Real git in temp repos; a fake ForgeCore on 127.0.0.1 that signs and verifies with an in-test HMAC key,
so a tampered attestation fails /verify exactly as the real kernel's would.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
import gem_trailers as gt  # noqa: E402
import mcp_reference_monitor as gem  # noqa: E402

GEMCTL = os.path.join(ROOT, "gemctl.py")
PRETOOL = os.path.join(ROOT, "hooks", "gem_pretool.py")
PY = sys.executable
TOKEN = "test-bearer"
HMAC_KEY = b"in-test-hmac-key-not-a-secret"
REPO = "acme/widgets"
ORIGIN = "https://github.com/acme/widgets.git"


# ---------------------------------------------------------------- fake ForgeCore (HMAC)

def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sign(body):
    return hmac.new(HMAC_KEY, _canon(body), hashlib.sha256).hexdigest()


class _ForgeCore(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        st = self.server.state
        if self.headers.get("authorization") != f"Bearer {TOKEN}":
            return self._reply(401, {"error": "unauthorized"})
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if self.path == "/api/v1/gate/attest":
            ref = re.sub(r"^(refs/heads/|heads/)", "", body["target_ref"])
            kernel = [f"kernel: direct write to protected ref '{ref}' is forbidden"] \
                if body["tool"] in {"git_push", "git_force_push", "push_files"} and ref in {"main", "master"} else []
            client = list(body.get("violations") or [])
            dec = "BLOCK" if kernel else ("PASS" if not client else ("WARN" if body["mode"] == "warn" else "BLOCK"))
            dec = st.get("force_decision") or dec
            t = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=st.get("offset_s", 0))
            att = {"version": "gem-gate/1", "repository": body["repository"], "tool": body["tool"],
                   "target_ref": ref, "mode": body["mode"], "session_id": body["session_id"], "decision": dec,
                   "client_violations": client, "kernel_violations": kernel,
                   "payload_sha256": body.get("payload_sha256"),
                   "facts_sha256": hashlib.sha256(_canon(body.get("facts") or {})).hexdigest(),
                   "issued_at": t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z",   # nanosecond precision, like chrono
                   "key_id": "test-key-0001"}
            att["attestation_id"] = hashlib.sha256(_canon(att)).hexdigest()[:32]
            att["signature"] = _sign(att)
            st["issued"].add(att["attestation_id"])
            return self._reply(201, att)
        if self.path == "/api/v1/gate/verify":
            st["verify_calls"] += 1
            att = body.get("attestation")
            if not isinstance(att, dict):
                return self._reply(400, {"error": "body must be {\"attestation\": {...}}"})
            unsigned = {k: v for k, v in att.items() if k != "signature"}
            base = {k: v for k, v in unsigned.items() if k != "attestation_id"}
            valid = (isinstance(att.get("signature"), str) and hmac.compare_digest(att["signature"], _sign(unsigned))
                     and unsigned.get("attestation_id") == hashlib.sha256(_canon(base)).hexdigest()[:32])
            return self._reply(200, {"valid": valid, "recorded": valid and att["attestation_id"] in st["issued"]})
        return self._reply(404, {"error": "not found"})


@pytest.fixture()
def forgecore():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ForgeCore)
    srv.state = {"issued": set(), "verify_calls": 0}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def dead_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def attest(srv, ref="feat/x", repository=REPO, tool="git_push", mode="warn", violations=(), **state):
    """Obtain a genuinely signed attestation from the fake kernel through gemcore's own client."""
    srv.state.update(state)
    try:
        return gem.ForgeCoreAttestor(srv.url, TOKEN).attest({
            "repository": repository, "tool": tool, "target_ref": ref, "mode": mode, "session_id": "s-test",
            "violations": list(violations), "payload_sha256": None, "facts": {}})
    finally:
        for k in state:
            srv.state.pop(k, None)


def store(home, att):
    d = os.path.join(str(home), "attestations")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, att["attestation_id"] + ".json"), "w") as fh:
        json.dump(att, fh)


# ---------------------------------------------------------------- environment + git helpers

@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """No inherited git/gem config: an empty global gitconfig, no system config, a private GEM_HOME."""
    for k in list(os.environ):
        if k.startswith(("GIT_", "GEM_", "AUTODEV_")):
            monkeypatch.delenv(k)
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    home = tmp_path / "gemhome"
    monkeypatch.setenv("GEM_HOME", str(home))
    return home


def git(repo, *args, check=True, env=None):
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=e, timeout=60)
    if check:
        assert r.returncode == 0, (args, r.stderr)
    return r


def run(argv, cwd=None, env=None, stdin=""):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([PY, *argv], input=stdin, capture_output=True, text=True, env=e, cwd=cwd, timeout=60)


def make_repo(path, origin=ORIGIN):
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", "Gem Test")
    git(path, "config", "user.email", "gem-test@example.invalid")
    git(path, "config", "commit.gpgsign", "false")
    if origin:
        git(path, "remote", "add", "origin", origin)
    (path / "README").write_text("base\n")
    git(path, "add", "README")
    git(path, "commit", "-q", "-m", "base")
    git(path, "checkout", "-q", "-b", "feat/x")
    return path


def commit(repo, name, msg=None, env=None, check=True, extra=()):
    (repo / name).write_text(name + "\n")
    git(repo, "add", name)
    return git(repo, "commit", "-q", "-m", msg or f"add {name}", *extra, env=env, check=check)


def message(repo, rev="HEAD"):
    return git(repo, "log", "-1", "--format=%B", rev).stdout


def gate_lines(text):
    return [ln for ln in text.splitlines() if ln.lower().startswith("gem-gate:")]


def pretool(repo, command, srv_url, mode="WARN"):
    payload = {"session_id": "sess-1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": command}, "cwd": str(repo)}
    r = run([PRETOOL], cwd=str(repo), stdin=json.dumps(payload),
            env={"GEM_ENFORCEMENT": mode, "AUTODEV_URL": srv_url, "AUTODEV_API_BEARER_TOKEN": TOKEN})
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout) if r.stdout.strip() else {}


def last_event(home):
    return json.loads((home / "events.jsonl").read_text().splitlines()[-1])


def install(repo):
    r = run([GEMCTL, "trailer", "install-hook", "--repo", str(repo)])
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def gemctl(repo, *args, env=None):
    return run([GEMCTL, "trailer", *args], cwd=str(repo), env=env)


def fc_env(url):
    return {"AUTODEV_URL": url, "AUTODEV_API_BEARER_TOKEN": TOKEN}


# ---------------------------------------------------------------- 1. hook storage

def test_hook_stores_full_attestation_owner_only(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    assert pretool(repo, "git push -u origin feat/x", forgecore.url) == {}   # PASS stays silent
    ev = last_event(isolated)
    path = ev["attestation_path"]
    assert ev["decision"] == "PASS" and path == str(isolated / "attestations" / (ev["attestation_id"] + ".json"))
    att = json.loads(open(path).read())
    assert att["repository"] == REPO and att["target_ref"] == "feat/x" and att["signature"] and att["key_id"]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    assert not [f for f in os.listdir(os.path.dirname(path)) if f.startswith(".tmp-")]
    assert gem.ForgeCoreAttestor(forgecore.url, TOKEN).verify({"attestation": att}) == {"valid": True, "recorded": True}


def test_hook_storage_failure_never_changes_decision(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    isolated.mkdir()
    (isolated / "attestations").write_text("not a directory")   # makedirs will fail
    assert pretool(repo, "git push origin feat/x", forgecore.url, mode="ENFORCE") == {}
    ev = last_event(isolated)
    assert ev["decision"] == "PASS" and ev["attestation_id"] and ev["attestation_path"] is None
    out = pretool(repo, "git push origin main", forgecore.url, mode="ENFORCE")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert last_event(isolated)["attestation_path"] is None


# ---------------------------------------------------------------- 2. trailer add

def test_trailer_added_once_and_idempotent(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    pretool(repo, "git push -u origin feat/x", forgecore.url)
    att_id = last_event(isolated)["attestation_id"]
    install(repo)
    commit(repo, "a.txt")
    assert gate_lines(message(repo)) == [f"Gem-Gate: {att_id}"]
    git(repo, "commit", "-q", "--amend", "--no-edit")                     # hook runs again on the same message
    assert gate_lines(message(repo)) == [f"Gem-Gate: {att_id}"]
    msg = tmp_path / "MSG"
    msg.write_text("subject\n\nbody\n\ngem-gate: forged-by-hand\n# a comment line\n")
    for _ in range(2):
        assert gemctl(repo, "add", str(msg)).returncode == 0
    assert gate_lines(msg.read_text()) == [f"Gem-Gate: {att_id}"]
    assert msg.read_text().rstrip().endswith("# a comment line")         # trailer goes above comments


def test_no_trailer_without_fresh_matching_attestation(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    install(repo)
    r = commit(repo, "a.txt")
    assert gate_lines(message(repo)) == [] and "gem-gate: no Gem-Gate trailer" in r.stderr
    assert len([ln for ln in r.stderr.splitlines() if ln.startswith("gem-gate:")]) == 1
    store(isolated, attest(forgecore, offset_s=-(gt.DEFAULT_MAX_AGE_S + 60)))   # stale
    store(isolated, attest(forgecore, ref="feat/other"))                      # other branch
    store(isolated, attest(forgecore, repository="acme/other"))               # other repository
    store(isolated, attest(forgecore, repository="unknown/unknown"))
    commit(repo, "b.txt")
    assert gate_lines(message(repo)) == []
    assert gt.latest_attestation(REPO, "feat/x") is None
    fresh = attest(forgecore)
    store(isolated, fresh)
    assert gt.latest_attestation("ACME/Widgets", "refs/heads/feat/x")["attestation_id"] == fresh["attestation_id"]
    assert gt.latest_attestation("unknown/unknown", "feat/x") is None


def test_required_blocks_commit_without_attestation(isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    install(repo)
    before = git(repo, "rev-parse", "HEAD").stdout
    r = commit(repo, "a.txt", env={"GEM_TRAILER_REQUIRED": "1"}, check=False)
    assert r.returncode != 0 and "GEM_TRAILER_REQUIRED=1" in r.stderr
    assert git(repo, "rev-parse", "HEAD").stdout == before


def test_block_attestation_is_never_used(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    older_pass = attest(forgecore, offset_s=-60)
    newer_block = attest(forgecore, force_decision="BLOCK")
    store(isolated, older_pass)
    store(isolated, newer_block)
    assert newer_block["decision"] == "BLOCK"
    assert gt.latest_attestation(REPO, "feat/x")["attestation_id"] == older_pass["attestation_id"]
    install(repo)
    commit(repo, "a.txt")
    assert gate_lines(message(repo)) == [f"Gem-Gate: {older_pass['attestation_id']}"]
    os.remove(isolated / "attestations" / (older_pass["attestation_id"] + ".json"))
    assert gt.latest_attestation(REPO, "feat/x") is None
    # a kernel BLOCK from the real hook path (push to main) is stored but never picked for main
    git(repo, "checkout", "-q", "main")
    out = pretool(repo, "git push origin main", forgecore.url)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny" and last_event(isolated)["attestation_path"]
    assert gt.latest_attestation(REPO, "main") is None


def test_newest_usable_attestation_wins(forgecore, isolated):
    a = attest(forgecore, offset_s=-120)
    b = attest(forgecore, mode="warn", violations=["Force push rewrites shared history."], offset_s=-10)
    store(isolated, a)
    store(isolated, b)
    assert b["decision"] == "WARN"
    assert gt.latest_attestation(REPO, "feat/x")["attestation_id"] == b["attestation_id"]
    assert gt.latest_attestation(REPO, "feat/x", max_age_s=60)["attestation_id"] == b["attestation_id"]
    assert gt.latest_attestation(REPO, "feat/x", max_age_s=5) is None


# ---------------------------------------------------------------- 3. notes

def test_notes_round_trip_and_ci_verify_without_local_store(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo", origin=None)
    bare = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(bare))
    git(repo, "remote", "add", "origin", str(bare))
    env = {"GEM_REPOSITORY": REPO}
    att = attest(forgecore)
    store(isolated, att)
    install(repo)
    commit(repo, "a.txt", env=env)
    assert gate_lines(message(repo)) == [f"Gem-Gate: {att['attestation_id']}"]
    r = gemctl(repo, "note", env=env)
    assert r.returncode == 0 and "git push origin refs/notes/gem-gate" in r.stderr
    assert json.loads(gt.read_note("HEAD", cwd=str(repo))) == att
    # low-level attach_note replaces, never stacks
    sha = gt.attach_note("HEAD", att, cwd=str(repo))
    assert sha == git(repo, "rev-parse", "HEAD").stdout.strip()
    assert json.loads(git(repo, "notes", "--ref", gt.NOTES_REF, "show", "HEAD").stdout) == att
    # CI: fresh clone, notes fetched explicitly, empty local store
    git(repo, "push", "-q", "origin", "main", "feat/x", gt.NOTES_REF)
    clone = tmp_path / "ci"
    git(tmp_path, "clone", "-q", str(bare), str(clone))
    git(clone, "fetch", "-q", "origin", f"{gt.NOTES_REF}:{gt.NOTES_REF}")
    r = run([GEMCTL, "trailer", "verify", "origin/main..origin/feat/x"], cwd=str(clone),
            env={**env, **fc_env(forgecore.url), "GEM_HOME": str(tmp_path / "empty-home")})
    report = json.loads(r.stdout)
    assert r.returncode == 0 and report["ok"] and [c["status"] for c in report["commits"]] == ["verified"]
    assert report["commits"][0]["recorded"] is True


def test_note_refuses_bad_trailer_and_missing_store(isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    commit(repo, "a.txt", msg="x\n\nGem-Gate: ../../../etc/passwd")
    r = gemctl(repo, "note")
    assert r.returncode == 1 and "32 hex" in r.stderr
    commit(repo, "b.txt", msg="y\n\nGem-Gate: " + "c" * 32)
    r = gemctl(repo, "note")
    assert r.returncode == 1 and "not in" in r.stderr
    commit(repo, "c.txt", msg="no trailer")
    assert gemctl(repo, "note").returncode == 1
    assert gt.read_note("HEAD", cwd=str(repo)) is None


# ---------------------------------------------------------------- 4. verify_range

def test_verify_range_good_tampered_missing(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    pretool(repo, "git push -u origin feat/x", forgecore.url)
    install(repo)
    commit(repo, "good.txt")
    assert gemctl(repo, "note").returncode == 0
    commit(repo, "tampered.txt")
    assert gemctl(repo, "note").returncode == 0
    forged = json.loads(gt.read_note("HEAD", cwd=str(repo)))
    forged["target_ref"] = "main"                                           # same id, altered body
    gt.attach_note("HEAD", forged, cwd=str(repo))
    commit(repo, "untrailered.txt", extra=("--no-verify",))                 # bypasses commit-msg
    good, tampered, bare = git(repo, "rev-list", "--reverse", "main..feat/x").stdout.split()

    report = gt.verify_range("main..feat/x", gem.ForgeCoreAttestor(forgecore.url, TOKEN), cwd=str(repo))
    assert [(c["commit"], c["status"]) for c in report["commits"]] == [
        (good, "verified"), (tampered, "invalid_signature"), (bare, "missing_trailer")]
    assert report["repository"] == REPO and not report["ok"] and gt.exit_code(report) == 2
    assert report["summary"]["verified"] == 1 and report["commits"][0]["decision"] == "PASS"

    r = gemctl(repo, "verify", "main..feat/x", env=fc_env(forgecore.url))
    assert r.returncode == 2 and [c["status"] for c in json.loads(r.stdout)["commits"]] == \
        ["verified", "invalid_signature", "missing_trailer"]
    only_good = gemctl(repo, "verify", f"main..{good}", env=fc_env(forgecore.url))
    assert only_good.returncode == 0 and json.loads(only_good.stdout)["ok"]


def test_verify_forgecore_down_is_unavailable(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    store(isolated, attest(forgecore))
    install(repo)
    for name in ("a.txt", "b.txt"):
        commit(repo, name)
        assert gemctl(repo, "note").returncode == 0
    r = gemctl(repo, "verify", "main..feat/x", env=fc_env(dead_url()))
    report = json.loads(r.stdout)
    assert r.returncode == 1 and [c["status"] for c in report["commits"]] == ["forgecore_unavailable"] * 2
    assert "unreachable" in report["commits"][0]["reason"]
    unconfigured = gemctl(repo, "verify", "main..feat/x")
    assert unconfigured.returncode == 1 and "not configured" in unconfigured.stderr
    assert {c["status"] for c in json.loads(unconfigured.stdout)["commits"]} == {"forgecore_unavailable"}


def test_verify_mismatch_blocked_and_missing_note(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    fc = gem.ForgeCoreAttestor(forgecore.url, TOKEN)
    ok, other = attest(forgecore), attest(forgecore, offset_s=-5)
    blocked = attest(forgecore, force_decision="BLOCK")
    foreign = attest(forgecore, repository="evil/fork")
    commit(repo, "1.txt", msg=f"id differs\n\nGem-Gate: {ok['attestation_id']}")
    gt.attach_note("HEAD", other, cwd=str(repo))
    commit(repo, "2.txt", msg=f"other repo\n\nGem-Gate: {foreign['attestation_id']}")
    gt.attach_note("HEAD", foreign, cwd=str(repo))
    commit(repo, "3.txt", msg=f"blocked\n\nGem-Gate: {blocked['attestation_id']}")
    gt.attach_note("HEAD", blocked, cwd=str(repo))
    commit(repo, "4.txt", msg=f"no note\n\nGem-Gate: {ok['attestation_id']}")
    calls = forgecore.state["verify_calls"]
    report = gt.verify_range("main..feat/x", fc, cwd=str(repo))
    assert [c["status"] for c in report["commits"]] == ["mismatch", "mismatch", "blocked", "missing_note"]
    assert forgecore.state["verify_calls"] == calls                         # local checks fail before ForgeCore
    assert gt.exit_code(report) == 2
    assert gt.exit_code({"commits": [{"status": "verified"}, {"status": "missing_note"}]}) == 1
    assert gt.exit_code({"commits": []}) == 0
    with pytest.raises(gt.TrailerError):
        gt.verify_range("--all", fc, cwd=str(repo))


def test_verify_caches_shared_attestation(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    store(isolated, attest(forgecore))
    install(repo)
    for name in ("a.txt", "b.txt", "c.txt"):
        commit(repo, name)
        assert gemctl(repo, "note").returncode == 0
    calls = forgecore.state["verify_calls"]
    report = gt.verify_range("main..feat/x", gem.ForgeCoreAttestor(forgecore.url, TOKEN), cwd=str(repo))
    assert report["ok"] and forgecore.state["verify_calls"] == calls + 1


# ---------------------------------------------------------------- 5. install-hook

def test_install_hook_fresh_then_update(isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    first = install(repo)
    hook = repo / ".git" / "hooks" / "commit-msg"
    assert first["action"] == "installed" and first["hook"] == str(hook) and first["chained"] is None
    assert os.access(hook, os.X_OK) and gt.HOOK_MARKER in hook.read_text()
    assert install(repo)["action"] == "updated"
    assert not (repo / ".git" / "hooks" / "commit-msg.gem-chained").exists()


def test_install_hook_chains_existing_hook(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    mine = '#!/bin/sh\ngit interpret-trailers --in-place --trailer "X-Mine: yes" "$1"\n'
    (hooks / "commit-msg").write_text(mine)
    os.chmod(hooks / "commit-msg", 0o755)
    res = install(repo)
    assert res["action"] == "chained" and (hooks / "commit-msg.gem-chained").read_text() == mine
    assert install(repo)["action"] == "updated"                              # idempotent, no double chain
    assert (hooks / "commit-msg.gem-chained").read_text() == mine
    att = attest(forgecore)
    store(isolated, att)
    commit(repo, "a.txt")
    msg = message(repo)
    assert "X-Mine: yes" in msg and gate_lines(msg) == [f"Gem-Gate: {att['attestation_id']}"]
    # a failing user hook still aborts the commit
    (hooks / "commit-msg.gem-chained").write_text("#!/bin/sh\nexit 7\n")
    assert commit(repo, "b.txt", check=False).returncode != 0


def test_install_hook_refuses_when_chain_slot_taken(isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "commit-msg").write_text("#!/bin/sh\necho user hook\n")
    (hooks / "commit-msg.gem-chained").write_text("#!/bin/sh\necho older\n")
    r = run([GEMCTL, "trailer", "install-hook", "--repo", str(repo)])
    assert r.returncode == 1 and "refusing" in r.stderr
    assert (hooks / "commit-msg").read_text() == "#!/bin/sh\necho user hook\n"
    assert (hooks / "commit-msg.gem-chained").read_text() == "#!/bin/sh\necho older\n"


def test_install_hook_honors_core_hooks_path(forgecore, isolated, tmp_path):
    repo = make_repo(tmp_path / "repo")
    git(repo, "config", "core.hooksPath", ".githooks")
    sub = repo / "pkg"
    sub.mkdir()
    res = install(sub)                                                       # from a subdirectory
    assert res["hook"] == str(repo / ".githooks" / "commit-msg")
    att = attest(forgecore)
    store(isolated, att)
    commit(repo, "a.txt")
    assert gate_lines(message(repo)) == [f"Gem-Gate: {att['attestation_id']}"]


# ---------------------------------------------------------------- 6. helpers + help text

def test_parsers():
    assert gt.parse_repo_slug("git@github.com:acme/widgets.git") == REPO
    assert gt.parse_repo_slug("https://github.com/acme/widgets") == REPO
    assert gt.parse_repo_slug("ssh://git@github.com:22/acme/widgets.git/") == REPO
    assert gt.parse_repo_slug("") is None
    t = gt.parse_rfc3339("2026-11-07T20:57:00.123456789Z")
    assert t == gt.parse_rfc3339("2026-11-07T21:57:00.123456+01:00") == gt.parse_rfc3339("2026-11-07T20:57:00.123456Z")
    assert gt.parse_rfc3339("2026-11-07 20:57:00Z") is not None and gt.parse_rfc3339("yesterday") is None


def test_push_guidance_in_help_and_docstring():
    r = run([GEMCTL, "trailer", "--help"])
    assert r.returncode == 0 and "git push origin refs/notes/gem-gate" in r.stdout
    assert "git push origin refs/notes/gem-gate" in run([GEMCTL, "--help"]).stdout
    assert "git push origin refs/notes/gem-gate" in gt.__doc__
