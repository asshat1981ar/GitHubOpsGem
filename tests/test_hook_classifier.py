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


# ---------------------------------------------------------------- review round 2 (adversarial probes)

@pytest.mark.parametrize("cmd", [
    # heredocs: the body can be a script, or hold a live $(...)
    "bash <<EOF\ngit push origin main\nEOF",
    "cat <<EOF\n$(git push origin main)\nEOF",
    "echo <<EOF\nEOF\ngit push origin main\nEOF",
    "echo '<<EOF'\ngit push origin main\nEOF",
    "echo hi # <<EOF\ngit push origin main\nEOF",
    "echo $((1<<EOF))\ngit push origin main\nEOF",
    # wrapper options and path-qualified binaries
    "sudo -u root git push origin main",
    "sudo -E git push origin main",
    "sudo -- git push origin main",
    "env -i git push origin main",
    "env -u X git push origin main",
    "nice -n 5 git push origin main",
    "command -p git push origin main",
    "time -p git push origin main",
    "timeout 5 git push origin main",
    "timeout 5 sh -c 'git push origin main'",
    "setsid git push origin main",
    "/usr/bin/git push origin main",
    "./git push origin main",
    # shell grammar
    "(git push origin main)",
    "{ git push origin main; }",
    "if true; then git push origin main; fi",
    "for i in 1; do git push origin main; done",
    "! git push origin main",
    # nesting and xargs
    "echo $(echo $(echo $(echo $(git push origin main))))",
    "xargs sh -c 'git push origin main'",
    "xargs -I{} sh -c 'git push {}'",
    # redirection glued to the refspec, trailing comment, push options
    "git push origin main>/dev/null",
    "git push origin main #comment",
    "git push -o ci.skip origin main",
    # gh global flags
    "gh -R a/b pr merge 5",
    "gh --repo a/b pr merge 5",
])
def test_review_round2_bypasses_are_classified(cmd):
    assert any(t.startswith("git_") or t == "merge_pull_request" for t, _ in writes(cmd)), cmd


def test_gh_global_flags_do_not_hide_pr_create():
    assert writes("gh -R a/b pr create --head feat/x") == [("create_pull_request", "feat/x")]


def test_push_option_value_is_not_a_second_target():
    assert writes("git push -o ci.skip origin feat/x") == [("git_push", "feat/x")]
    assert writes("git push origin main #comment") == [("git_push", "main")]


def test_heredoc_to_a_non_shell_is_still_data():
    cmd = "cat > notes.txt <<'EOF'\ngit push origin main\n`git push origin main`\nEOF"
    assert writes(cmd) == []


def test_unterminated_heredoc_fails_closed():
    assert writes("cat <<EOF\ngit push origin main") != []


@pytest.mark.parametrize("make", [
    lambda: "git push origin " + "a" * 2_000_000,
    lambda: "echo '" + "x" * 1_000_000,
    lambda: 'echo "' + "x" * 1_000_000,
    lambda: "echo " + "\\" * 1_000_000,
    lambda: 'echo "$(echo x)"' * 30_000,
    lambda: "cat <<EOF\n" * 14_000,
    lambda: "echo hi;" * 250_000,
])
def test_pathological_input_is_bounded(make):
    import time
    cmd = make()
    t0 = time.monotonic()
    out = hook.classify_bash(cmd, "/tmp")
    assert time.monotonic() - t0 < 2.0
    assert isinstance(out, list)


def test_oversized_command_mentioning_a_push_is_not_waved_through():
    out = hook.classify_bash("git push origin main " + "x" * 200_000, "/tmp")
    assert out and any("too long" in e for w in out for e in w["extra"])


def test_oversized_command_is_gated_even_when_it_looks_harmless():
    out = hook.classify_bash("echo " + "x" * 200_001, "/tmp")
    assert out and any("too long" in e for w in out for e in w["extra"])


def test_padding_cannot_hide_an_obfuscated_push_past_the_cap():
    cmd = "#" + "a" * 200_001 + "\ngit pu''sh origin main"
    assert hook.classify_bash(cmd, "/tmp")


# ---------------------------------------------------------------- deny wording

def test_missing_config_and_outage_get_different_hints():
    cfg = gem.GateDecision(False, "BLOCK", ["No ForgeCore attestor configured (AUTODEV_URL ...): unsigned write "
                                            "blocked in ENFORCE."], "git_push", "feat/x", gem.EnforcementMode.ENFORCE, {})
    out = gem.GateDecision(False, "BLOCK", ["ForgeCore attestation unavailable, failing closed: down"], "git_push",
                           "feat/x", gem.EnforcementMode.ENFORCE, {})
    r_cfg = hook.respond([cfg], "Bash")["hookSpecificOutput"]["permissionDecisionReason"]
    r_out = hook.respond([out], "Bash")["hookSpecificOutput"]["permissionDecisionReason"]
    for r in (r_cfg, r_out):
        assert "feat/<slug>" not in r and "Tell the user" in r and "plain terminal" not in r
    assert "not configured" in r_cfg and "did not answer" in r_out


def test_nesting_past_the_limit_fails_closed():
    deep = "$(" * 12 + "git push origin main" + ")" * 12
    out = hook.classify_bash(deep, "/tmp")
    assert out and any("too long" in e for w in out for e in w["extra"])
    assert hook.classify_bash("$(" * 12 + "echo hi" + ")" * 12, "/tmp")  # too deep to follow: gated either way
    assert hook.classify_bash("$(" * 4 + "echo hi" + ")" * 4, "/tmp") == []


# ---------------------------------------------------------------- review round 3 (reviewer's confirmed probes)

@pytest.mark.parametrize("cmd", [
    "echo \"it's $(git push origin main)\"",
    "echo \"it's `git push origin main`\"",
    "cat <<EOF\nit's\n$(git push origin main)\nEOF",
    "sudo -nu root git push origin main",
    "sudo --user root git push origin main",
    "timeout --signal KILL 5 git push origin main",
    "env -S 'git push origin main'",
    "env -iS 'git push origin main'",
    "env --split-string='git push origin main'",
    "env --chdir /tmp git push origin main",
    "env --unset X git push origin main",
    "nice --adjustment 5 git push origin main",
    "su -c 'git push origin main'",
    "find . -exec git push origin main \\;",
    "flock /tmp/l git push origin main",
    "watch git push origin main",
    "<<EOF bash\ngit push origin main\nEOF",
    "bash 2>&1 <<EOF\ngit push origin main\nEOF",
    "cat <<EOF | bash\ngit push origin main\nEOF",
    "git push $(echo origin) main",
    "git $(echo -n) push origin main",
    "git push origin foo#bar:main",
    "git push origin a#b main",
    "git push origin '>' main",
])
def test_round3_bypasses_reach_main(cmd):
    assert ("git_push", "main") in writes(cmd), cmd


def test_round3_gh_and_xargs_forms():
    assert ("create_pull_request", "main") in writes("gh pr create --title '>' --head main")
    assert any(t.startswith("git_") for t, _ in writes("echo main | xargs -I{} git push origin {}"))


def test_documented_limits_stay_documented():
    """Shell expansion and indirection the hook cannot resolve; the server-side ruleset covers these."""
    assert writes("git pus{h,} origin main") == []
    assert writes("git $'push' origin main") == []
    assert writes("alias gp='git push'; gp origin main") == []
    assert writes("ssh host git push origin main") == []


@pytest.mark.parametrize("make", [
    lambda: "cat " + "<<A " * 15_000,
    lambda: "$(" * 30_000 + "git push origin main",
    lambda: "(( x " + "<<A " * 12_000,
    lambda: "<<-" * 20_000,
    lambda: "git push origin " + "a" * 190_000,
    lambda: "echo '" + "x" * 190_000,
    lambda: 'echo "$(echo x)"' * 11_000,
    lambda: "cat <<EOF\n" * 17_000,
    lambda: "echo hi;" * 23_000,
    lambda: "a'b\"" * 40_000,
])
def test_work_stays_bounded_just_under_the_cap(make):
    import time
    cmd = make()
    assert len(cmd) <= hook.MAX_COMMAND_CHARS
    t0 = time.monotonic()
    hook.classify_bash(cmd, "/tmp")
    assert time.monotonic() - t0 < 2.0
