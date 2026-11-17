"""PreToolUse hook classifier: writes that used to slip past hooks/gem_pretool.py (found by the independent review
of the attestor change) and the deny wording when no ForgeCore is configured."""
import importlib.util
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
_spec = importlib.util.spec_from_file_location("gem_pretool", os.path.join(ROOT, "hooks", "gem_pretool.py"))
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)
import mcp_reference_monitor as gem  # noqa: E402


def writes(cmd):
    return [(w["tool"], w["branch"]) for w in hook.classify_bash(cmd, "/tmp")]


# ---------------------------------------------------------------- shell forms that must be seen

@pytest.mark.parametrize("cmd", [
    "echo hi\ngit push origin main",
    "sleep 1 & git push origin main",
    "echo $(git push origin main)",
    "echo `git push origin main`",
    'bash -c "git push origin main"',
    "sh -c 'git push origin main'",
    "bash -lc 'git push origin main'",
    "eval 'git push origin main'",
    "sudo git push origin main",
    "env FOO=1 git push origin main",
    "command git push origin main",
    "nohup git push origin main",
    'bash -c "echo ok; bash -c \'git push origin main\'"',
])
def test_hidden_push_to_main_is_classified(cmd):
    assert ("git_push", "main") in writes(cmd), cmd


def test_force_push_inside_bash_c_keeps_force_flag():
    assert ("git_force_push", "release/1") in writes("bash -c 'git push --force origin release/1'")


def test_xargs_git_push_is_classified():
    assert any(t.startswith("git_") for t, _ in writes("echo main | xargs git push origin"))


def test_gh_pr_create_is_a_gated_write():
    assert writes("gh pr create --head feat/x --title t") == [("create_pull_request", "feat/x")]


# ---------------------------------------------------------------- text that must NOT be mistaken for a push

@pytest.mark.parametrize("cmd", [
    'git commit -m "docs: git push is blocked in ENFORCE; a && b"',
    "git commit -m \"$(cat <<'EOF'\nfix: do not run `git push origin main` here\n\ngit push origin main\nEOF\n)\"",
    'echo "a & b" && ls',
    "echo 'git push origin main'",
    "git status\ngit log --oneline",
    "git pull --ff-only origin main",
])
def test_quoted_or_heredoc_text_is_not_a_push(cmd):
    assert writes(cmd) == [], cmd


def test_stderr_redirect_does_not_create_a_second_target():
    assert writes("git push origin feat/x 2>&1") == [("git_push", "feat/x")]


def test_existing_forms_still_classified():
    assert writes("git push origin main && ls") == [("git_push", "main")]
    assert writes("git -C sub push origin main") == [("git_push", "main")]
    assert writes("gh pr merge 7") == [("merge_pull_request", "pr:7")]


# ---------------------------------------------------------------- GitHub MCP writes that reached no gate

@pytest.mark.parametrize("tool,args,expected", [
    ("mcp__github__create_branch", {"branch": "feat/x"}, ("create_branch", "feat/x")),
    ("mcp__github__update_pull_request", {"pullNumber": 7, "title": "t"}, ("update_pull_request", "pr:7")),
    ("mcp__github__update_pull_request_branch", {"pullNumber": 7}, ("update_pull_request_branch", "pr:7")),
    ("mcp__github__actions_run_trigger", {"method": "run_workflow", "ref": "main"}, ("run_workflow", "main")),
])
def test_mcp_writes_in_write_tools_are_classified(tool, args, expected):
    got = hook.classify_mcp(tool, args)
    assert [(w["tool"], w["branch"]) for w in got] == [expected]


def test_every_gemcore_write_tool_with_an_mcp_name_is_classified():
    for short in ("create_branch", "update_pull_request", "update_pull_request_branch", "run_workflow"):
        assert short in gem.StatefulGitHubOpsMonitor.WRITE_TOOLS
        assert hook.classify_mcp(f"mcp__github__{short}", {"pullNumber": 1}), short


# ---------------------------------------------------------------- no-ForgeCore deny wording and rule id

@pytest.fixture()
def no_forgecore(monkeypatch):
    for name in ("AUTODEV_URL", "GEM_FORGECORE_URL", "AUTODEV_API_BEARER_TOKEN", "GEM_ENFORCE_AFTER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GEM_ENFORCEMENT", "ENFORCE")


def _blocked(no_forgecore):
    write = {"tool": "git_push", "branch": "feat/x", "payload": None, "event": None, "extra": []}
    return hook.gate_one(write, "s", "o/r")


def test_missing_attestor_has_its_own_rule_id(no_forgecore):
    d = _blocked(no_forgecore)
    assert d.decision == "BLOCK" and hook.rule_ids(d.violations) == ["ATTESTOR_MISSING"]


def test_deny_hint_does_not_suggest_a_branch_that_is_also_blocked(no_forgecore):
    reason = hook.respond([_blocked(no_forgecore)], "Bash")["hookSpecificOutput"]["permissionDecisionReason"]
    assert "feat/<slug>" not in reason and "AUTODEV_URL" in reason


def test_protected_branch_deny_keeps_the_branch_hint():
    d = gem.GateDecision(False, "BLOCK", ["Direct write to protected branch 'main' is forbidden."], "git_push", "main",
                         gem.EnforcementMode.ENFORCE, {})
    assert "feat/<slug>" in hook.respond([d], "Bash")["hookSpecificOutput"]["permissionDecisionReason"]
