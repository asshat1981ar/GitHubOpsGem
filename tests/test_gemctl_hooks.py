"""Tests for gemctl (WU-04), the Claude Code hooks (WU-08) and the installer."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GEMCTL = os.path.join(ROOT, "gemctl.py")
PRETOOL = os.path.join(ROOT, "hooks", "gem_pretool.py")
SESSION = os.path.join(ROOT, "hooks", "gem_session_start.py")
INSTALL = os.path.join(ROOT, "install_hooks.py")
PY = sys.executable


def run(argv, stdin="", env_extra=None, cwd=None):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GEM_", "AUTODEV_"))}
    env.update(env_extra or {})
    return subprocess.run([PY, *argv], input=stdin, capture_output=True, text=True, env=env, cwd=cwd, timeout=60)


# ---------------------------------------------------------------- gemctl

def test_gemctl_version():
    r = run([GEMCTL, "version"])
    assert r.returncode == 0 and r.stdout.strip().startswith("5.")


def test_gemctl_scan_diff_flags_unpinned_action(tmp_path):
    patch = "@@ -1,1 +1,1 @@\n+      - uses: actions/checkout@v4\n"
    r = run([GEMCTL, "scan-diff", "--path", ".github/workflows/ci.yml", "--fail-on-critical"], stdin=patch)
    out = json.loads(r.stdout)
    assert r.returncode == 2 and out["critical"] == 1 and out["findings"][0]["category"] == "UNPINNED_ACTION_SHA"


def test_gemctl_gate_exit_codes():
    block = run([GEMCTL, "gate", "--tool", "push_files", "--branch", "refs/heads/main", "--mode", "enforce"])
    warn = run([GEMCTL, "gate", "--tool", "push_files", "--branch", "main", "--mode", "warn"])
    ok = run([GEMCTL, "gate", "--tool", "push_files", "--branch", "feat/x", "--mode", "enforce"])
    assert block.returncode == 2 and json.loads(block.stdout)["decision"] == "BLOCK"
    assert warn.returncode == 0 and json.loads(warn.stdout)["decision"] == "WARN"
    assert ok.returncode == 0 and json.loads(ok.stdout)["decision"] == "PASS"


def test_gemctl_gate_xml_and_payload_secret(tmp_path):
    payload = tmp_path / "p.txt"
    payload.write_text("token = sk-ant-api03-" + "Z" * 40)
    r = run([GEMCTL, "gate", "--tool", "push_files", "--branch", "feat/x", "--payload", str(payload),
             "--mode", "enforce", "--xml"])
    assert r.returncode == 2 and "<gate_decision mode=\"ENFORCE\">BLOCK" in r.stdout and "ANTHROPIC_KEY" in r.stdout


def test_gemctl_debt_and_strip_and_ci_window():
    d = json.loads(run([GEMCTL, "debt"], stdin="@@ -1 +1,2 @@\n+except Exception:\n+    pass\n").stdout)
    assert d["psc_score"] > 0 and "FAST_INTEGRATION_DEBT" in d["detected_debts"]
    s = run([GEMCTL, "strip"], stdin="<think>secret</think>visible")
    assert s.stdout == "visible" and "stripped_blocks=1" in s.stderr
    log = "\n".join(["noise"] * 500 + ["error[E0425]: root"] + ["noise"] * 500)
    w = run([GEMCTL, "ci-window"], stdin=log)
    assert "root" in w.stdout and len(w.stdout.splitlines()) <= 220


def test_gemctl_verify_needs_forgecore_env():
    r = run([GEMCTL, "verify"], stdin="{}")
    assert r.returncode == 1 and "AUTODEV_URL" in r.stderr


# ---------------------------------------------------------------- hooks

def hook(tool_name, tool_input, mode="WARN", cwd=None, gem_home=None, extra=None):
    payload = {"session_id": "sess-1", "hook_event_name": "PreToolUse", "tool_name": tool_name,
               "tool_input": tool_input, "cwd": cwd or ROOT}
    env = {"GEM_ENFORCEMENT": mode, "GEM_HOME": str(gem_home or "/tmp/gem-test-home"),
           "GEM_REPOSITORY": "asshat1981ar/autodev"}
    env.update(extra or {})
    r = run([PRETOOL], stdin=json.dumps(payload), env_extra=env, cwd=cwd)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout) if r.stdout.strip() else {}


def decision(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecision")


def test_non_write_tools_are_silent(tmp_path):
    assert hook("Read", {"file_path": "/x"}, gem_home=tmp_path) == {}
    assert hook("Bash", {"command": "git status && ls"}, gem_home=tmp_path) == {}
    assert not (tmp_path / "events.jsonl").exists()


@pytest.mark.parametrize("cmd", [
    "git push origin main", "git push origin HEAD:refs/heads/main", "cd repo && git push --force origin release/1.0",
    "git push origin :main", "git push origin --delete master", "GIT_TRACE=1 git push upstream trunk",
    "git -C sub push origin main",
])
def test_protected_pushes_denied_in_enforce(cmd, tmp_path):
    out = hook("Bash", {"command": cmd}, mode="ENFORCE", gem_home=tmp_path)
    assert decision(out) == "deny", cmd


def test_protected_push_warns_in_warn_mode_without_forgecore(tmp_path):
    out = hook("Bash", {"command": "git push origin main"}, mode="WARN", gem_home=tmp_path)
    assert decision(out) is None and "WARN" in out["systemMessage"]
    assert "additionalContext" in out["hookSpecificOutput"]


def test_feature_push_passes_silently_and_never_emits_allow(tmp_path):
    out = hook("Bash", {"command": "git push -u origin feat/gem-gate"}, mode="ENFORCE", gem_home=tmp_path)
    assert out == {}
    ev = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[-1])
    assert ev["decision"] == "PASS" and ev["target"] == "feat/gem-gate" and ev["rules"] == []


def test_force_push_to_feature_branch_is_flagged(tmp_path):
    out = hook("Bash", {"command": "git push --force-with-lease origin feat/x"}, mode="WARN", gem_home=tmp_path)
    assert "Force push" in out["systemMessage"]


def test_bare_git_push_resolves_current_branch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    out = hook("Bash", {"command": "git push"}, mode="ENFORCE", cwd=str(repo), gem_home=tmp_path)
    assert decision(out) == "deny" and "main" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_mcp_push_files_secret_and_branch(tmp_path):
    files = [{"path": "a.py", "content": "KEY = 'fw_" + "A" * 30 + "'"}]
    out = hook("mcp__github__push_files", {"owner": "o", "repo": "r", "branch": "feat/x", "files": files},
               mode="ENFORCE", gem_home=tmp_path)
    assert decision(out) == "deny" and "FIREWORKS_KEY" in out["hookSpecificOutput"]["permissionDecisionReason"]
    clean = hook("mcp__github__push_files", {"owner": "o", "repo": "r", "branch": "feat/x",
                                             "files": [{"path": "a.py", "content": "x = 1"}]},
                 mode="ENFORCE", gem_home=tmp_path)
    assert clean == {}


def test_agent_merge_needs_human_in_enforce(tmp_path):
    out = hook("mcp__github__merge_pull_request", {"owner": "o", "repo": "r", "pullNumber": 7},
               mode="ENFORCE", gem_home=tmp_path)
    assert decision(out) == "deny"
    ev = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[-1])
    assert "MERGE_NO_EVIDENCE" in ev["rules"]


def test_malformed_payload_fails_closed_only_for_writes(tmp_path):
    env = {"GEM_ENFORCEMENT": "ENFORCE", "GEM_HOME": str(tmp_path)}
    bad_write = run([PRETOOL], stdin='{"tool_name": "Bash", "tool_input": {"command": "git push origin main"', env_extra=env)
    bad_other = run([PRETOOL], stdin="not json at all", env_extra=env)
    assert '"deny"' in bad_write.stdout and bad_other.stdout == ""


def test_session_start_reports_mode(tmp_path):
    r = run([SESSION], env_extra={"GEM_ENFORCEMENT": "WARN", "GEM_ENFORCE_AFTER": "2099-01-01"})
    assert r.returncode == 0 and "mode WARN until 2099-01-01, then ENFORCE" in r.stdout and "local only" in r.stdout


# ---------------------------------------------------------------- hooks + ForgeCore

class _Kernel(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        ref = body["target_ref"].replace("refs/heads/", "")
        kernel = ["kernel: direct write to protected ref '%s' is forbidden" % ref] \
            if body["tool"] in {"git_push", "git_force_push", "push_files"} and ref in {"main", "master"} else []
        dec = "BLOCK" if kernel else ("PASS" if not body["violations"] else ("WARN" if body["mode"] == "warn" else "BLOCK"))
        out = json.dumps({"attestation_id": "b" * 32, "decision": dec, "kernel_violations": kernel,
                          "key_id": "k" * 16, "signature": "e" * 64}).encode()
        self.send_response(201); self.end_headers(); self.wfile.write(out)

    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}')


@pytest.fixture()
def kernel_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Kernel)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_kernel_blocks_protected_push_even_in_warn_week(kernel_url, tmp_path):
    out = hook("Bash", {"command": "git push origin main"}, mode="WARN", gem_home=tmp_path,
               extra={"AUTODEV_URL": kernel_url, "AUTODEV_API_BEARER_TOKEN": "t"})
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert decision(out) == "deny" and "signed by ForgeCore" in reason
    ev = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[-1])
    assert ev["attestation_id"] == "b" * 32 and "KERNEL_PROTECTED_REF" in ev["rules"]


def test_session_start_sees_forgecore(kernel_url):
    r = run([SESSION], env_extra={"GEM_ENFORCEMENT": "ENFORCE", "AUTODEV_URL": kernel_url})
    assert "ForgeCore reachable" in r.stdout


# ---------------------------------------------------------------- installer

def test_installer_is_idempotent_and_preserves_settings(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "ds-main", "hooks": {"PreToolUse": [
        {"matcher": "Write", "hooks": [{"type": "command", "command": "echo mine"}]}]}}))
    home = tmp_path / "gemhome"
    for _ in range(2):
        r = run([INSTALL, "--settings", str(settings), "--gem-home", str(home)])
        assert r.returncode == 0, r.stderr
    s = json.loads(settings.read_text())
    pre = s["hooks"]["PreToolUse"]
    assert s["model"] == "ds-main" and len(pre) == 2 and pre[0]["hooks"][0]["command"] == "echo mine"
    assert (home / "lib" / "mcp_reference_monitor.py").exists() and (home / "hooks" / "gem_pretool.py").exists()
    assert list(tmp_path.glob("settings.json.bak-*"))
    run([INSTALL, "--settings", str(settings), "--gem-home", str(home), "--remove"])
    s = json.loads(settings.read_text())
    assert len(s["hooks"]["PreToolUse"]) == 1 and "SessionStart" not in s["hooks"]


def test_installed_hook_runs_from_gem_home(tmp_path):
    home = tmp_path / "gemhome"
    run([INSTALL, "--settings", str(tmp_path / "s.json"), "--gem-home", str(home)])
    payload = {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "git push origin main"}, "cwd": str(tmp_path)}
    r = run([str(home / "hooks" / "gem_pretool.py")], stdin=json.dumps(payload),
            env_extra={"GEM_HOME": str(home), "GEM_ENFORCEMENT": "ENFORCE"}, cwd=str(tmp_path))
    assert '"deny"' in r.stdout


# ---- WU-07 review #10: the model may read B200 status but never operate the controller
@pytest.mark.parametrize("command", [
    "gem heavy on", "gemctl heavy off", "python3 ~/.gem/lib/gemctl.py heavy on --export",
    "cat ~/.gem/operator.token", "echo $GEM_LIFECYCLE_TOKEN", "env | grep GEM_LIFECYCLE_FEED_TOKEN",
    "curl -X POST http://127.0.0.1:8090/wake -d '{}'", "curl localhost:8090/heavy", "curl '[::1]:8090/touch'",
    "python3 -c 'import gem_lifecycle_client as c; c.call(\"POST\",\"/heavy\",{\"on\":True})'",
    "sudo cat /etc/gem/lifecycle.env",
])
def test_bash_cannot_operate_the_b200(command, tmp_path):
    for mode in ("WARN", "ENFORCE"):
        out = hook("Bash", {"command": command}, mode=mode, gem_home=tmp_path)
        assert decision(out) == "deny", (mode, command, out)
        assert "gem heavy on" in out["hookSpecificOutput"]["permissionDecisionReason"]
    events = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert events[-1]["rules"] == ["LIFECYCLE_OPERATOR"] and events[-1]["decision"] == "BLOCK"


@pytest.mark.parametrize("command", ["gem heavy status", "gemctl heavy status",
                                     "curl -s http://127.0.0.1:8090/status", "echo $GEM_LIFECYCLE_SESSION_TOKEN | wc -c",
                                     "git status", "ls ~/.gem"])
def test_read_only_lifecycle_and_unrelated_commands_pass(command, tmp_path):
    assert decision(hook("Bash", {"command": command}, mode="ENFORCE", gem_home=tmp_path)) is None


@pytest.mark.parametrize("tool,ti", [("Read", {"file_path": "/data/data/com.termux/files/home/.gem/operator.token"}),
                                     ("Grep", {"pattern": "TOKEN", "path": "/etc/gem/lifecycle.env"}),
                                     ("Edit", {"file_path": "/root/.gem/operator.token", "old_string": "a", "new_string": "b"})])
def test_file_tools_cannot_touch_operator_credentials(tool, ti, tmp_path):
    assert decision(hook(tool, ti, mode="WARN", gem_home=tmp_path)) == "deny"
