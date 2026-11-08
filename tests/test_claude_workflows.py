"""Hardening policy for the Claude Code Action workflows, expressed as tests."""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_DIR = ROOT / ".github" / "workflows"
FILES = sorted([*WF_DIR.glob("claude*.yml"), WF_DIR / "agent-approval-check.yml"])
GEMCTL = ROOT / "gemctl.py"
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
VERSION = re.compile(r"#\s*v\d+\.\d+\.\d+\b")
CLAUDE_ACTION = "anthropics/claude-code-action@"


def load(p):
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def triggers(doc):
    on = doc.get("on", doc.get(True))
    return {on: None} if isinstance(on, str) else dict(on or {})


def claude_steps(job):
    return [s for s in job.get("steps") or [] if str(s.get("uses", "")).startswith(CLAUDE_ACTION)]


def _tool(name):
    return shutil.which(name)


def test_files_exist():
    assert {p.name for p in FILES} >= {"claude.yml", "claude-review.yml", "claude-gem-verdict.yml",
                                       "agent-approval-check.yml"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
class TestPolicy:
    def test_top_level_permissions_empty(self, path):
        assert load(path)["permissions"] == {}

    def test_jobs_have_timeout_and_concurrency(self, path):
        for name, job in load(path)["jobs"].items():
            assert 0 < job["timeout-minutes"] <= 60, name
            assert job["concurrency"]["group"], name

    def test_uses_pinned_with_version_comment(self, path):
        doc = load(path)
        for job in doc["jobs"].values():
            for s in job.get("steps") or []:
                if "uses" in s:
                    assert PINNED.match(s["uses"]), s["uses"]
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r"^\s*(-\s*)?uses:", line):
                assert VERSION.search(line), line

    def test_no_expression_in_run(self, path):
        for job in load(path)["jobs"].values():
            for s in job.get("steps") or []:
                assert "${{" not in str(s.get("run", "")), s.get("name")

    def test_checkout_does_not_persist_credentials(self, path):
        for job in load(path)["jobs"].values():
            for s in job.get("steps") or []:
                if str(s.get("uses", "")).startswith("actions/checkout@"):
                    assert s["with"]["persist-credentials"] is False

    def test_claude_args_required_flags(self, path):
        for job in load(path)["jobs"].values():
            for s in claude_steps(job):
                args = s["with"]["claude_args"]
                for flag in ("--permission-mode auto", "--model", "--max-turns", "--allowedTools"):
                    assert flag in args, flag

    def test_forbidden_inputs_absent(self, path):
        text = path.read_text(encoding="utf-8")
        for key in ("show_full_output", "allowed_non_write_users", "allowed_bots"):
            assert key not in text

    def test_kill_switch_and_dependabot_guard(self, path):
        for name, job in load(path)["jobs"].items():
            if claude_steps(job):
                cond = str(job.get("if", ""))
                assert "vars.CLAUDE_PAUSE != 'true'" in cond, name
                if any("pull_request" in t for t in triggers(load(path))):
                    assert "github.actor != 'dependabot[bot]'" in cond, name

    def test_id_token_rules(self, path):
        for name, job in load(path)["jobs"].items():
            perms = job.get("permissions", {})
            if path.name not in ("claude.yml", "claude-review.yml"):
                assert "id-token" not in perms, name
            for s in claude_steps(job):
                if "github_token" in s["with"]:
                    assert "id-token" not in perms
                    assert perms.get("contents") != "write"
                else:
                    assert perms.get("id-token") == "write", name

    def test_pull_request_target_only_in_approval_check(self, path):
        has = "pull_request_target" in triggers(load(path))
        assert has == (path.name == "agent-approval-check.yml")
        if has:
            assert "actions/checkout" not in path.read_text(encoding="utf-8")

    def test_gemctl_scan_has_no_critical(self, path):
        lines = path.read_text(encoding="utf-8").splitlines()
        patch = f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{ln}\n" for ln in lines)
        proc = subprocess.run([sys.executable, "-I", str(GEMCTL), "scan-diff", "--path",
                               f".github/workflows/{path.name}", "--patch", "-"],
                              input=patch, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        assert '"critical": 0' in proc.stdout, proc.stdout

    @pytest.mark.skipif(not _tool("actionlint"), reason="actionlint not installed")
    def test_actionlint(self, path):
        r = subprocess.run(["actionlint", "-no-color", str(path)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout


def test_verdict_has_deterministic_fallback():
    job = load(WF_DIR / "claude-gem-verdict.yml")["jobs"]["verdict"]
    last = job["steps"][-1]
    assert "!cancelled()" in str(last["if"])
    assert "WARN" in last["run"]
    assert any(s.get("continue-on-error") for s in claude_steps(job))


# ---- Santa round 1 hardening (F1-F6) ----
BUILD_TOOL = re.compile(r"python3?|pytest|pip|gradle|npm|pnpm|yarn|cargo|make|godot|probes|lifecycle|gemctl|actionlint|zizmor")


def _allowed(step):
    m = re.search(r'--allowedTools "([^"]*)"', step["with"]["claude_args"])
    assert m, "no --allowedTools"
    return [t.strip() for t in re.split(r",(?![^()]*\))", m.group(1))]


def test_claude_yml_fork_guard_step():
    job = load(WF_DIR / "claude.yml")["jobs"]["claude"]
    steps = job["steps"]
    fork = steps[0]
    assert fork.get("id") == "fork"
    assert "isCrossRepository" in fork["run"]
    assert "${{" not in fork["run"]
    assert fork["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "PR" in fork["env"] and "REPO" in fork["env"]
    assert "cross=true" in fork["run"]  # fails closed
    (claude,) = claude_steps(job)
    assert claude["if"] == "steps.fork.outputs.cross != 'true'"
    assert steps.index(fork) < steps.index(claude)
    cond = str(job["if"])
    for ev in ("pull_request_review_comment", "pull_request_review"):
        line = next(ln for ln in cond.splitlines() if f"'{ev}'" in ln)
        assert "github.event.pull_request.head.repo.full_name == github.repository" in line, ev


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_claude_jobs_scrub_env(path):
    for name, job in load(path)["jobs"].items():
        if claude_steps(job):
            assert str(job.get("env", {}).get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")) == "1", name


def test_claude_yml_allows_no_build_tools():
    (claude,) = claude_steps(load(WF_DIR / "claude.yml")["jobs"]["claude"])
    tools = _allowed(claude)
    assert tools
    for t in tools:
        assert t.startswith(("Bash(git diff", "Bash(git log", "Bash(git status", "Bash(git show",
                             "Bash(gh pr view", "Bash(gh pr diff", "Bash(gh issue view")), t
        assert not BUILD_TOOL.search(t[len('Bash('):]), t


@pytest.mark.parametrize("path", [WF_DIR / "claude-review.yml", WF_DIR / "claude-gem-verdict.yml"], ids=lambda p: p.name)
def test_agent_mode_jobs_do_not_read_comments(path):
    text = path.read_text(encoding="utf-8")
    assert "include_comments_by_actor" not in text
    assert "gh api" not in text and "--comments" not in text
    for job in load(path)["jobs"].values():
        for s in claude_steps(job):
            tools = _allowed(s)
            assert "Bash(gh pr view:*)" not in tools
            assert not any(t.startswith("Bash(gh api") or t.startswith("Bash(gh pr comment") for t in tools)


def test_settings_json_allow_has_no_bash():
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))["permissions"]
    assert not any(a.startswith("Bash(") for a in perms["allow"])
    assert "Read(./.env*)" in perms["deny"] and "Read(./.git/config)" in perms["deny"]


def test_agent_approval_ruleset_ships_disabled():
    rs = json.loads((ROOT / "ci" / "rulesets" / "agent-approval.json").read_text(encoding="utf-8"))
    assert rs["enforcement"] == "disabled"
    script = (ROOT / "ci" / "apply_rulesets.sh").read_text(encoding="utf-8")
    assert "enforcement" in script and "disabled" in script


def test_verdict_uses_deterministic_count():
    run = load(WF_DIR / "claude-gem-verdict.yml")["jobs"]["verdict"]["steps"][-1]["run"]
    assert "totals.critical" in run and "no Claude verdict" in run
    assert "actor.login != 'dependabot[bot]'" in str(load(WF_DIR / "claude-gem-verdict.yml")["jobs"]["verdict"]["if"])
