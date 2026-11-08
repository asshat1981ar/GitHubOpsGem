"""Tests for the gem-review workflow (WU-10): static hardening invariants, linters, dogfooding with the
gem's own scanner, and a local simulation of the workflow's run steps against throwaway git repos."""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REUSABLE = ROOT / "ci" / "gem-review.yml"
CALLER = ROOT / "ci" / "gem-review-caller.example.yml"
HELPER = ROOT / "ci" / "gem_review_steps.py"
GEMCTL = ROOT / "gemctl.py"
WORKFLOWS = [REUSABLE, CALLER]
# Where each file is installed, so gemctl applies its workflow rules (it decides by path).
INSTALL_PATH = {REUSABLE: ".github/workflows/gem-review.yml", CALLER: ".github/workflows/gem-review.yml"}

SHA40 = re.compile(r"^[0-9a-f]{40}$")
PINNED_USES = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v\d+\.\d+\.\d+\b")
READ_ONLY = {"contents": "read", "pull-requests": "read"}
FAKE_PAT = "ghp_" + "Z9yX" * 9  # built at runtime so this file holds no secret-shaped literal
CLEAN_PIN = "actions/checkout@" + "3d3c42e5aac5ba805825da76410c181273ba90b1"


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(doc):
    on = doc.get("on", doc.get(True))  # PyYAML (YAML 1.1) reads a bare `on` key as True
    return {on: None} if isinstance(on, str) else dict(on or {})


def jobs(doc):
    return doc["jobs"].items()


def steps(doc):
    for _, job in jobs(doc):
        yield from job.get("steps") or []


def all_uses(doc):
    for _, job in jobs(doc):
        if "uses" in job:
            yield job["uses"]
        for step in job.get("steps") or []:
            if "uses" in step:
                yield step["uses"]


def new_file_patch(text):
    lines = text.splitlines()
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{ln}\n" for ln in lines)


def gemctl(*args, stdin=""):
    return subprocess.run([sys.executable, "-I", str(GEMCTL), *args], input=stdin, capture_output=True,
                          text=True, timeout=60)


# ---------------------------------------------------------------- static invariants (both files)

@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_uses_is_pinned_to_a_full_sha_with_version_comment(path):
    uses = list(all_uses(load(path)))
    assert uses, "expected at least one uses:"
    for target in uses:
        assert not target.startswith(("./", "docker://")), target
        assert PINNED_USES.match(target), f"not pinned to a 40-hex commit SHA: {target}"
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\s*(-\s*)?uses:", line):
            assert VERSION_COMMENT.search(line), f"missing '# vX.Y.Z' comment: {line.strip()}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_permissions_are_read_only_at_workflow_and_job_level(path):
    doc = load(path)
    assert doc.get("permissions") == READ_ONLY
    for name, job in jobs(doc):
        assert job.get("permissions") == READ_ONLY, name
    code = "\n".join(ln.split("#", 1)[0] for ln in path.read_text(encoding="utf-8").splitlines())
    assert not re.search(r":\s*write\b|write-all|read-all", code)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_privileged_pull_request_trigger(path):
    assert "pull_request_target" not in path.read_text(encoding="utf-8")
    expected = {"workflow_call"} if path == REUSABLE else {"pull_request"}
    assert set(triggers(load(path))) == expected


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_expression_inside_run(path):
    for step in steps(load(path)):
        if "run" in step:
            assert "${{" not in step["run"], step.get("name")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkout_never_persists_credentials(path):
    for step in steps(load(path)):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert (step.get("with") or {}).get("persist-credentials") is False, step.get("name")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_job_has_a_timeout(path):
    reusable_jobs = dict(jobs(load(REUSABLE)))
    for name, job in jobs(load(path)):
        if "uses" in job:
            # GitHub forbids timeout-minutes on a job that calls a reusable workflow; the called jobs carry it.
            assert "timeout-minutes" not in job
            assert job["uses"].split("@")[0].endswith("/.github/workflows/gem-review.yml")
            assert all(0 < j.get("timeout-minutes", 0) <= 60 for j in reusable_jobs.values())
        else:
            assert 0 < job.get("timeout-minutes", 0) <= 60, name


def test_one_concurrency_group_per_pr_and_no_caller_deadlock():
    caller_group = load(CALLER)["concurrency"]["group"]
    (job,) = dict(jobs(load(REUSABLE))).values()
    callee_group = job["concurrency"]["group"]
    for group in (caller_group, callee_group):
        assert "github.event.pull_request.number" in group
    assert caller_group != callee_group
    assert load(CALLER)["concurrency"]["cancel-in-progress"] is True and job["concurrency"]["cancel-in-progress"] is True


def test_reusable_inputs_and_validation_comes_first():
    doc = load(REUSABLE)
    ins = triggers(doc)["workflow_call"]["inputs"]
    assert ins["gem_ref"]["required"] is True and ins["gem_ref"]["type"] == "string"
    assert ins["gem_repository"]["default"] == "asshat1981ar/GitHubOpsGem"
    assert ins["fail_on"]["default"] == "critical" and ins["base_ref"]["default"] == ""
    st = list(steps(doc))
    assert st[0]["name"] == "Validate inputs" and "{40}" in st[0]["run"]
    assert st[0]["env"]["GEM_REF"] == "${{ inputs.gem_ref }}"
    gem_checkout = next(i for i, s in enumerate(st) if (s.get("with") or {}).get("ref") == "${{ inputs.gem_ref }}")
    assert gem_checkout > 0
    assert not any("secrets" in (job or {}) for _, job in jobs(load(CALLER)))


def test_caller_pins_workflow_and_gem_to_the_same_sha():
    (job,) = dict(jobs(load(CALLER))).values()
    pin = job["uses"].rsplit("@", 1)[1]
    assert SHA40.match(pin) and job["with"]["gem_ref"] == pin and job["with"]["fail_on"] == "critical"


# ---------------------------------------------------------------- linters

def _tool(name):
    exe = shutil.which(name)
    if not exe:
        pytest.skip(f"{name} not installed")
    return exe


def test_actionlint_clean():
    r = subprocess.run([_tool("actionlint"), "-no-color", *map(str, WORKFLOWS)], capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


def test_zizmor_clean_even_when_pedantic():
    r = subprocess.run([_tool("zizmor"), "--offline", "--persona", "auditor", "--no-ignores", "--format", "json",
                        *map(str, WORKFLOWS)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and json.loads(r.stdout) == [], r.stdout + r.stderr


# ---------------------------------------------------------------- dogfood: the gem scans its own workflow

@pytest.mark.parametrize("path", [REUSABLE, CALLER, HELPER, Path(__file__)], ids=lambda p: p.name)
def test_gemctl_scan_diff_finds_nothing_critical(path):
    patch = new_file_patch(path.read_text(encoding="utf-8"))
    for as_path in {str(path.relative_to(ROOT)), INSTALL_PATH.get(path, str(path.relative_to(ROOT)))}:
        r = gemctl("scan-diff", "--path", as_path, "--fail-on-critical", stdin=patch)
        out = json.loads(r.stdout)
        assert r.returncode == 0 and out["critical"] == 0 and out["findings"] == [], (as_path, out)


def test_gemctl_debt_on_the_helper_is_clean():
    d = json.loads(gemctl("debt", "--has-tests", "--prompt-versioned", "--provenance",
                          stdin=new_file_patch(HELPER.read_text(encoding="utf-8"))).stdout)
    assert d["smell_hits"] == d["deprecated_hits"] == d["policy_hits"] == 0 and d["detected_debts"] == []


def test_dogfood_would_catch_an_unpinned_action_at_the_install_path():
    bad = REUSABLE.read_text(encoding="utf-8").replace(CLEAN_PIN, "actions/checkout@v7", 1)
    out = json.loads(gemctl("scan-diff", "--path", INSTALL_PATH[REUSABLE], stdin=new_file_patch(bad)).stdout)
    assert out["critical"] == 1 and out["findings"][0]["category"] == "UNPINNED_ACTION_SHA"


# ---------------------------------------------------------------- local simulation of the workflow

EXPR = re.compile(r"\$\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}")


def _lookup(ctx, dotted):
    cur = ctx
    for part in dotted.split("."):
        cur = cur[part]  # KeyError = the workflow uses a context this simulation does not model
    return str(cur)


def _evaluate(value, ctx):
    if not isinstance(value, str):
        return value
    out = EXPR.sub(lambda m: _lookup(ctx, m.group(1)), value)
    assert "${{" not in out, f"unsupported expression in {value!r}"
    return out


class Repo:
    """Throwaway upstream repo: commits on main, then a PR branch."""

    def __init__(self, path):
        self.path = path
        self.env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=os.devnull)
        path.mkdir()
        self.git("init", "-q", "-b", "main")
        self.commit({"README.md": "fixture\n"}, "init")

    def git(self, *args):
        r = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, env=self.env, timeout=60)
        assert r.returncode == 0, r.stderr.decode()
        return r.stdout.decode().strip()

    def commit(self, files, msg, moves=()):
        for src, dst in moves:
            (self.path / dst).parent.mkdir(parents=True, exist_ok=True)
            self.git("mv", src, dst)
        for name, content in files.items():
            p = self.path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def branch(self, name, start="main"):
        self.git("checkout", "-q", "-B", name, start)


def simulate(tmp_path, repo, head, base, **inputs):
    """Run every step of ci/gem-review.yml the way the runner would. `run:` steps execute verbatim under
    `bash --noprofile --norc -eo pipefail` with their `env:` evaluated; the three `uses:` steps are
    emulated (clone at the PR head, copy of the gem, no-op setup-python, copy of the uploaded path)."""
    doc = load(REUSABLE)
    defaults = {k: v.get("default", "") for k, v in triggers(doc)["workflow_call"]["inputs"].items()}
    ins = {**defaults, "gem_ref": "a" * 40, **inputs}
    ws, temp, art, shim = (tmp_path / d for d in ("workspace", "runner_temp", "artifact", "bin"))
    for d in (ws, temp, shim):
        d.mkdir()
    (shim / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    (shim / "python").chmod(0o755)
    summary = temp / "step_summary.md"
    summary.touch()
    ctx = {"inputs": ins, "runner": {"temp": str(temp)},
           "github": {"repository": "owner/repo", "run_id": "1",
                      "event": {"pull_request": {"number": 7, "head": {"sha": head}, "base": {"sha": base}}}}}
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "GEM_", "RUNNER_"))}
    base_env.update(PATH=f"{shim}{os.pathsep}{os.environ['PATH']}", RUNNER_TEMP=str(temp), GITHUB_WORKSPACE=str(ws),
                    GITHUB_STEP_SUMMARY=str(summary), HOME=str(tmp_path), GIT_CONFIG_NOSYSTEM="1")
    (job,) = doc["jobs"].values()
    results, failed = [], False
    for step in job["steps"]:
        name = step["name"]
        if failed and step.get("if") not in ("${{ !cancelled() }}", "${{ always() }}"):
            results.append((name, "skipped", ""))
            continue
        if "uses" in step:
            action, w = step["uses"].split("@")[0], {k: _evaluate(v, ctx) for k, v in (step.get("with") or {}).items()}
            if action == "actions/checkout" and w["path"] == "target":
                subprocess.run(["git", "clone", "-q", str(repo.path), str(ws / "target")], check=True, env=repo.env)
                subprocess.run(["git", "-C", str(ws / "target"), "checkout", "-q", "--detach", w["ref"]], check=True)
            elif action == "actions/checkout":
                assert w["path"] == "gem" and w["ref"] == ins["gem_ref"] and w["repository"] == ins["gem_repository"]
                for f in ("gemctl.py", "mcp_reference_monitor.py", "ci/gem_review_steps.py"):
                    (ws / "gem" / f).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(ROOT / f, ws / "gem" / f)
            elif action == "actions/upload-artifact" and Path(w["path"]).is_dir():
                shutil.copytree(w["path"], art)
            results.append((name, 0, ""))
            continue
        script = tmp_path / "step.sh"
        script.write_text(step["run"])
        env = dict(base_env, **{k: _evaluate(v, ctx) for k, v in (step.get("env") or {}).items()})
        r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)], cwd=ws, env=env,
                           capture_output=True, text=True, timeout=180)
        results.append((name, r.returncode, r.stdout + r.stderr))
        failed = failed or r.returncode != 0
    res_file = art / "gem-review.json"
    return {"steps": results, "failed": failed, "summary": summary.read_text(encoding="utf-8"),
            "results": json.loads(res_file.read_text()) if res_file.is_file() else None,
            "log": "".join(out for _, _, out in results)}


def _exit_of(sim, name):
    return next(code for step, code, _ in sim["steps"] if step == name)


def _categories(sim):
    return sorted(fd["category"] for f in sim["results"]["files"] for fd in f["findings"])


@pytest.fixture
def repo(tmp_path):
    r = Repo(tmp_path / "upstream")
    r.commit({".github/workflows/ci.yml": f"on: pull_request\njobs:\n  b:\n    steps:\n      - uses: {CLEAN_PIN} # v7.0.1\n",
              "app/main.py": "print('hi')\n"}, "base")
    return r


def test_sim_dirty_pr_writes_summary_and_fails_on_critical(tmp_path, repo):
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    head = repo.commit({".github/workflows/ci.yml": "on: pull_request\njobs:\n  b:\n    steps:\n      - uses: foo/bar@v1\n",
                        "app/settings.py": f"TOKEN = '{FAKE_PAT}'\n"}, "dirty")
    sim = simulate(tmp_path, repo, head, base)
    assert sim["failed"] and _exit_of(sim, "Fail on critical findings") == 2
    for step in ("Validate inputs", "Compute the diff against the merge base", "Scan each changed file (gemctl scan-diff)",
                 "Measure LLM tech debt (gemctl debt)", "Write the job summary", "Upload the JSON results"):
        assert _exit_of(sim, step) == 0, sim["log"]
    assert sim["results"]["verdict"] == "BLOCK" and sim["results"]["totals"]["critical"] == 2
    assert _categories(sim) == ["SECRET_LEAK:GITHUB_PAT", "UNPINNED_ACTION_SHA"]
    md = sim["summary"]
    assert md.startswith("## gem-review: BLOCK") and "| CRITICAL | `UNPINNED_ACTION_SHA` |" in md
    assert "`SECRET_LEAK:GITHUB_PAT`" in md and "LLM tech-debt metrics" in md and FAKE_PAT not in md
    assert "::error title=gem-review::2 CRITICAL finding(s)" in sim["log"]


def test_sim_clean_pr_passes(tmp_path, repo):
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    head = repo.commit({"app/main.py": "print('hello')\n", "tests/test_main.py": "def test_x():\n    assert True\n"},
                       "clean")
    sim = simulate(tmp_path, repo, head, base)
    assert not sim["failed"], sim["log"]
    assert all(code == 0 for _, code, _ in sim["steps"])
    assert sim["results"]["verdict"] == "PASS" and sim["results"]["totals"] == {
        "files": 2, "findings": 0, "critical": 0, "by_severity": {"CRITICAL": 0, "MAJOR": 0, "MINOR": 0}}
    assert sim["summary"].startswith("## gem-review: PASS") and "| Test files in this PR | yes |" in sim["summary"]


def test_sim_fail_on_never_reports_without_failing(tmp_path, repo):
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    head = repo.commit({"app/settings.py": f"TOKEN = '{FAKE_PAT}'\n"}, "dirty")
    sim = simulate(tmp_path, repo, head, base, fail_on="never")
    assert not sim["failed"] and sim["results"]["verdict"] == "WARN" and sim["results"]["totals"]["critical"] == 1
    assert "reported only" in sim["summary"]


@pytest.mark.parametrize("bad", ["v7.0.1", "main", "a" * 39, "A" * 41, "$(touch pwned)", "a" * 40 + "\n"])
def test_sim_rejects_a_gem_ref_that_is_not_a_full_sha(tmp_path, repo, bad):
    base = repo.git("rev-parse", "main")
    sim = simulate(tmp_path, repo, base, base, gem_ref=bad)
    assert sim["failed"] and _exit_of(sim, "Validate inputs") != 0
    assert all(code == "skipped" for step, code, _ in sim["steps"][1:] if step != "Upload the JSON results")
    assert not (tmp_path / "workspace" / "pwned").exists() and "gem_ref must be" in sim["log"]


@pytest.mark.parametrize("field,bad", [("fail_on", "warn"), ("gem_repository", "a/b c"), ("base_ref", "main..x"),
                                       ("base_ref", "-x")])
def test_sim_rejects_other_bad_inputs(tmp_path, repo, field, bad):
    base = repo.git("rev-parse", "main")
    sim = simulate(tmp_path, repo, base, base, **{field: bad})
    assert _exit_of(sim, "Validate inputs") != 0


def test_sim_diffs_against_the_merge_base_not_the_base_tip(tmp_path, repo):
    repo.branch("pr")
    head = repo.commit({"app/feature.py": "x = 1\n"}, "clean pr")
    repo.branch("main", "main")
    base_tip = repo.commit({"app/leak.py": f"T = '{FAKE_PAT}'\n"}, "base moved on")
    sim = simulate(tmp_path, repo, head, base_tip)
    assert not sim["failed"], sim["log"]
    assert [f["path"] for f in sim["results"]["files"]] == ["app/feature.py"]


def test_sim_explicit_base_ref_resolves_the_remote_branch(tmp_path, repo):
    repo.branch("pr")
    head = repo.commit({"app/settings.py": f"TOKEN = '{FAKE_PAT}'\n"}, "dirty")
    sim = simulate(tmp_path, repo, head, "", base_ref="main")
    assert _exit_of(sim, "Fail on critical findings") == 2 and sim["results"]["totals"]["critical"] == 1


def test_sim_gitattributes_and_renames_cannot_hide_findings(tmp_path, repo):
    repo.commit({"docs/sample.yml": "jobs:\n  b:\n    steps:\n      - uses: foo/bar@v1\n"}, "docs sample")
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    head = repo.commit({".gitattributes": "* -diff\n", "app/hidden.py": f"T = '{FAKE_PAT}'\n"}, "evade",
                       moves=[("docs/sample.yml", ".github/workflows/sample.yml")])
    sim = simulate(tmp_path, repo, head, base)
    assert sim["failed"] and _categories(sim) == ["SECRET_LEAK:GITHUB_PAT", "UNPINNED_ACTION_SHA"]


def test_sim_hostile_file_names_and_binary_content(tmp_path, repo):
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    hostile = "evil\n::warning::pwned|`x`.py"
    head = repo.commit({hostile: f"T = '{FAKE_PAT}'\n", "-dash.py": "x = 1\n",
                        "img.png": b"\x89PNG\r\n\x1a\n\xff\xfe\x00" + FAKE_PAT.encode(),
                        # \x1c is a line break to str.splitlines() but not to git: it must not hide the next line
                        "app/sep.py": f"a = 'x\x1cy'\nT = '{FAKE_PAT}'\n"}, "hostile")
    sim = simulate(tmp_path, repo, head, base)
    assert _exit_of(sim, "Scan each changed file (gemctl scan-diff)") == 0, sim["log"]
    assert sim["results"]["totals"]["files"] == 4 and sim["results"]["totals"]["critical"] == 3
    assert not any(line.startswith("::warning") for line in sim["log"].splitlines())
    rows = [ln for ln in sim["summary"].splitlines() if ln.startswith("| CRITICAL | `")]
    assert len(rows) == 3 and all(ln.count("|") == 5 for ln in rows)
    assert not any(ln.startswith("::") for ln in sim["summary"].splitlines())


# ---------------------------------------------------------------- installed copy, self-caller, rulesets
INSTALLED = ROOT / ".github" / "workflows" / "gem-review.yml"
SELF_CALLER = ROOT / ".github" / "workflows" / "gem-review-pr.yml"
RULESETS = sorted((ROOT / "ci" / "rulesets").glob("*.json"))


def test_installed_reusable_workflow_is_the_tested_source():
    assert INSTALLED.read_bytes() == REUSABLE.read_bytes(), "re-copy ci/gem-review.yml to .github/workflows/"


def test_self_caller_is_hardened_and_reviews_with_the_base_commit():
    w = load(SELF_CALLER)
    assert set(w[True]) == {"pull_request"} and "pull_request_target" not in SELF_CALLER.read_text()
    assert w["permissions"] == {"contents": "read", "pull-requests": "read"}
    (name, job), = jobs(w)
    assert job["uses"] == "./.github/workflows/gem-review.yml"   # same commit as the caller (see file comment)
    assert job["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert job["with"]["gem_ref"] == "${{ github.event.pull_request.base.sha }}"
    assert job["with"]["fail_on"] == "critical" and "secrets" not in job
    (callee,) = dict(jobs(load(REUSABLE))).values()
    assert w["concurrency"]["group"] != callee["concurrency"]["group"]


def test_ruleset_requires_the_check_that_actually_runs():
    (caller_job, _), = jobs(load(SELF_CALLER))
    (callee_job, _), = jobs(load(REUSABLE))
    expected = f"{caller_job} / {callee_job}"
    main = json.loads((ROOT / "ci" / "rulesets" / "main.json").read_text())
    checks = [r for r in main["rules"] if r["type"] == "required_status_checks"][0]["parameters"]["required_status_checks"]
    assert checks == [{"context": expected, "integration_id": 15368}]          # 15368 = GitHub Actions
    types = {r["type"] for r in main["rules"]}
    assert {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} <= types
    assert all(b["bypass_mode"] == "pull_request" for b in main["bypass_actors"])  # no direct-push bypass
    for path in RULESETS:
        rs = json.loads(path.read_text())
        assert rs["enforcement"] == "active" and rs["target"] in {"branch", "tag"}


def test_new_workflow_files_pass_actionlint_and_zizmor():
    files = [str(INSTALLED), str(SELF_CALLER)]
    r = subprocess.run([_tool("actionlint"), "-no-color", *files], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    r = subprocess.run([_tool("zizmor"), "--offline", "--min-severity", "low", *files], capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


def test_sim_scan_uses_pr_head_checkout_for_env_context(tmp_path, repo):
    """gem-review gives scan-diff the PR-head checkout, so an env binding outside the hunk is seen.

    Patch-only scans fail closed on `${{ env.X }}` with no visible binding (CodeRabbit 4506305087); in CI the
    changed file is on disk in `target/`, so a safely bound X must not become a CRITICAL there.
    """
    filler = "".join(f"      - run: echo step{i}\n" for i in range(12))
    base_wf = ("on: pull_request\nenv:\n  GREETING: hello\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
               + filler)
    repo.commit({".github/workflows/env.yml": base_wf}, "env workflow")
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    head = repo.commit({".github/workflows/env.yml": base_wf + "      - run: echo \"${{ env.GREETING }}\"\n"},
                       "use env")
    sim = simulate(tmp_path, repo, head, base)
    assert _exit_of(sim, "Scan each changed file (gemctl scan-diff)") == 0, sim["log"]
    assert "CWE-94_WORKFLOW_INJECTION" not in _categories(sim), sim["results"]
    assert not sim["failed"], sim["log"]


def test_sim_scan_with_pr_head_checkout_still_flags_tainted_env(tmp_path, repo):
    """Full-file context must keep an untrusted binding outside the hunk tainted."""
    filler = "".join(f"      - run: echo step{i}\n" for i in range(12))
    base_wf = ("on: issues\nenv:\n  TITLE: ${{ github.event.issue.title }}\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
               "    steps:\n" + filler)
    repo.commit({".github/workflows/env.yml": base_wf}, "env workflow")
    base = repo.git("rev-parse", "main")
    repo.branch("pr")
    head = repo.commit({".github/workflows/env.yml": base_wf + "      - run: echo \"${{ env.TITLE }}\"\n"}, "use env")
    sim = simulate(tmp_path, repo, head, base)
    assert "CWE-94_WORKFLOW_INJECTION" in _categories(sim), sim["log"]
