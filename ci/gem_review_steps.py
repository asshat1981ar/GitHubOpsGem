#!/usr/bin/env python3
"""Steps of the gem-review workflow (GitHubOpsGem WU-10), one subcommand per workflow step.

The workflow (ci/gem-review.yml, installed as .github/workflows/gem-review.yml) runs this file from the
gem checkout, so the code that reviews a pull request always comes from the pinned gem_ref and never
from the pull request. Stdlib only. Nothing in the repository under review is executed: it is diffed
with git and read by gemctl, nothing more. All state lives under --work:

  <work>/patches/NNNN.patch  one unified diff per changed file, plus all.patch (not uploaded)
  <work>/results/*.json      diff.json, scan.json, debt.json, gem-review.json (uploaded as an artifact)

  diff     --repo DIR --work DIR [--base REF] [--pr-base-sha SHA]
  scan     --gem DIR --work DIR
  debt     --gem DIR --work DIR
  summary  --work DIR --fail-on critical|never [--gem-ref SHA] [--summary FILE]
  enforce  --work DIR --fail-on critical|never

Exit codes follow gemctl: 0 ok, 1 error (the check fails closed), 2 BLOCK (enforce only).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
REF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]{0,254}$")
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|androidTest|testFixtures)/"
    r"|(^|/)test_[^/]*\.py$|_test\.(py|go|rs|kt|java|[jt]sx?)$|\.(test|spec)\.[jt]sx?$|Tests?\.(kt|java|swift)$")
SEVERITIES = ("CRITICAL", "MAJOR", "MINOR")
FAIL_ON = ("critical", "never")
# --text: a PR's .gitattributes cannot hide a file behind "-diff"/"binary".
# --no-renames: a file moved into .github/workflows/ is scanned in full, not as a bare rename.
DIFF_OPTS = ("--no-color", "--no-ext-diff", "--no-textconv", "--text", "--no-renames",
             "--unified=3", "--src-prefix=a/", "--dst-prefix=b/")
# gemctl walks patches with str.splitlines(), which also breaks on \r, \v, \f, \x1c-\x1e, \x85, \u2028 and
# \u2029. git breaks only on \n, so one of those inside an added line shifts gemctl's hunk counters and hides
# the lines after it from the scan. They become spaces, so git and gemctl agree on every line boundary.
EXTRA_LINE_BREAKS = str.maketrans({c: " " for c in "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"})
MAX_ROWS = 200
TIMEOUT_S = 300


class StepError(RuntimeError):
    """A condition the step cannot review past; reported as exit 1 so the check fails closed."""


def log(msg: str) -> None:
    # Untrusted text only reaches the log through json.dumps; the replace is a second guard so no
    # output line can begin a "::" workflow command.
    print("gem-review: " + msg.replace("\r", "\\r").replace("\n", "\\n"), flush=True)


def _cmd_escape(msg: str) -> str:
    return msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _load(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise StepError(f"{path.name} is missing; an earlier gem-review step did not finish")
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _dump(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


# --------------------------------------------------------------------------- diff

def _git(repo: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_LITERAL_PATHSPECS="1", GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1",
               LC_ALL="C")
    proc = subprocess.run(["git", "--no-optional-locks", "-C", repo, *args], capture_output=True, env=env,
                          timeout=TIMEOUT_S, check=False)
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")[-400:]
        raise StepError(f"git {args[0]} failed with exit {proc.returncode}: {json.dumps(err)}")
    return proc


def resolve_commit(repo: str, ref: str) -> str:
    if ".." in ref or not (SHA_RE.match(ref) or REF_RE.match(ref)):
        raise StepError(f"base {json.dumps(ref)} is not a branch, tag or commit SHA")
    candidates = [ref] if SHA_RE.match(ref) else [f"refs/remotes/origin/{ref}", ref]
    for cand in candidates:
        proc = _git(repo, "rev-parse", "--verify", "--quiet", cand + "^{commit}", check=False)
        if proc.returncode == 0:
            return proc.stdout.decode().strip()
    raise StepError(f"base {json.dumps(ref)} is not in the checkout; check out with fetch-depth: 0")


def cmd_diff(a: argparse.Namespace) -> int:
    work = Path(a.work)
    (work / "patches").mkdir(parents=True, exist_ok=True)
    base_input = a.base or a.pr_base_sha
    if not base_input:
        raise StepError("no base to diff against: set base_ref, or call gem-review from a pull_request event")
    base = resolve_commit(a.repo, base_input)
    head = _git(a.repo, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    mb = _git(a.repo, "merge-base", base, head, check=False)
    if mb.returncode != 0:
        raise StepError("base and HEAD share no merge base (unrelated histories or a shallow checkout)")
    merge_base = mb.stdout.decode().strip()

    names = _git(a.repo, "diff", "--name-only", "-z", "--no-renames", "--diff-filter=d", merge_base, head).stdout
    files: List[Dict[str, str]] = []
    whole: List[str] = []
    for i, raw_name in enumerate((n for n in names.split(b"\0") if n), 1):
        text = _git(a.repo, "diff", *DIFF_OPTS, merge_base, head, "--", os.fsdecode(raw_name)).stdout
        # gemctl reads strict UTF-8, so undecodable (binary) bytes become U+FFFD.
        patch = text.decode("utf-8", "replace").translate(EXTRA_LINE_BREAKS)
        rel = f"patches/{i:04d}.patch"
        (work / rel).write_text(patch, encoding="utf-8")
        whole.append(patch)
        files.append({"path": raw_name.decode("utf-8", "replace"), "patch": rel})
    (work / "patches" / "all.patch").write_text("".join(whole), encoding="utf-8")

    has_tests = any(TEST_PATH_RE.search(f["path"]) for f in files)
    _dump(work / "results" / "diff.json", {
        "schema": "gem-review/diff/v1", "base_input": base_input, "base": base, "merge_base": merge_base,
        "head": head, "has_tests": has_tests, "files": files})
    log(f"{len(files)} changed file(s) between merge base {merge_base[:12]} and head {head[:12]}")
    return 0


# --------------------------------------------------------------------------- gemctl steps

def _gemctl(gem: str, *args: str) -> subprocess.CompletedProcess:
    script = Path(gem) / "gemctl.py"
    if not script.is_file():
        raise StepError(f"gemctl.py not found in the gem checkout {json.dumps(gem)}")
    # -I: no PYTHONPATH / user site / cwd on sys.path; gemctl adds its own directory itself.
    return subprocess.run([sys.executable, "-I", str(script), *args], capture_output=True, text=True,
                          timeout=TIMEOUT_S, check=False)


def cmd_scan(a: argparse.Namespace) -> int:
    work = Path(a.work)
    manifest = _load(work / "results" / "diff.json")
    by_sev = {s: 0 for s in SEVERITIES}
    out: List[Dict[str, Any]] = []
    for f in manifest["files"]:
        # --opt=value keeps a file named "-x" from being parsed as a flag.
        proc = _gemctl(a.gem, "scan-diff", f"--path={f['path']}", f"--patch={work / f['patch']}")
        if proc.returncode != 0:
            raise StepError(f"gemctl scan-diff failed on {json.dumps(f['path'])} with exit {proc.returncode}: "
                            f"{json.dumps(proc.stderr[-400:])}")
        rep = json.loads(proc.stdout)
        findings = list(rep.get("findings") or [])
        for fd in findings:
            by_sev[str(fd.get("severity"))] = by_sev.get(str(fd.get("severity")), 0) + 1
        counted = sum(str(fd.get("severity")) == "CRITICAL" for fd in findings)
        out.append({"path": f["path"], "critical": max(int(rep.get("critical") or 0), counted),
                    "findings": findings})
    version = _gemctl(a.gem, "version")
    totals = {"files": len(out), "findings": sum(len(f["findings"]) for f in out),
              "critical": sum(f["critical"] for f in out), "by_severity": by_sev}
    _dump(work / "results" / "scan.json", {
        "schema": "gem-review/scan/v1", "gem_version": version.stdout.strip() if version.returncode == 0 else "unknown",
        "files": out, "totals": totals})
    log(f"scan-diff: {totals['critical']} critical of {totals['findings']} finding(s) in {totals['files']} file(s)")
    return 0


def cmd_debt(a: argparse.Namespace) -> int:
    work = Path(a.work)
    manifest = _load(work / "results" / "diff.json")
    args = ["debt", f"--patch={work / 'patches' / 'all.patch'}"]
    if manifest.get("has_tests"):
        args.append("--has-tests")
    proc = _gemctl(a.gem, *args)
    if proc.returncode != 0:
        raise StepError(f"gemctl debt failed with exit {proc.returncode}: {json.dumps(proc.stderr[-400:])}")
    report = json.loads(proc.stdout)
    _dump(work / "results" / "debt.json", {"schema": "gem-review/debt/v1",
                                           "has_tests": bool(manifest.get("has_tests")), "report": report})
    log(f"debt: psc={report.get('psc_score')} dur={report.get('dur_score')} policy_hits={report.get('policy_hits')}")
    return 0


# --------------------------------------------------------------------------- summary / enforce

def _code(value: Any, limit: int = 240) -> str:
    """Render untrusted text as an inert Markdown code span that cannot break out of a table cell."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))  # drops newlines and bidi controls
    text = text.replace("`", "'").replace("|", "\u00a6").strip()
    if len(text) > limit:
        text = text[: limit - 1] + "\u2026"
    return f"`{text}`" if text else "-"


def verdict_of(critical: int, findings: int, fail_on: str) -> str:
    if critical and fail_on == "critical":
        return "BLOCK"
    return "WARN" if findings else "PASS"


def render_markdown(r: Dict[str, Any]) -> str:
    t, debt = r["totals"], r["debt"]
    crit, n = t["critical"], t["findings"]
    lines = [f"## gem-review: {r['verdict']}", ""]
    if r["verdict"] == "BLOCK":
        lines.append(f"{crit} CRITICAL finding(s) and `fail_on` is `critical`, so this check fails.")
    elif crit:
        lines.append(f"{crit} CRITICAL finding(s), reported only because `fail_on` is `never`.")
    elif n:
        lines.append(f"No CRITICAL findings; {n} lower-severity finding(s) to review.")
    else:
        lines.append(f"No findings in {t['files']} changed file(s).")
    gem = f"{_code(r['gem_version'])} @ {_code((r.get('gem_ref') or 'unknown')[:12])}"
    lines += ["", "| Head | Merge base | Changed files | Gem |", "|---|---|---:|---|",
              f"| {_code(r['head'][:12])} | {_code(r['merge_base'][:12])} | {t['files']} | {gem} |", "",
              "| " + " | ".join(SEVERITIES) + " |", "|" + "---:|" * len(SEVERITIES),
              "| " + " | ".join(str(t["by_severity"].get(s, 0)) for s in SEVERITIES) + " |", ""]

    rows = sorted(((fd, f["path"]) for f in r["files"] for fd in f["findings"]),
                  key=lambda x: (SEVERITIES.index(x[0].get("severity")) if x[0].get("severity") in SEVERITIES
                                 else len(SEVERITIES), x[1], int(x[0].get("line") or 0)))
    if rows:
        lines += ["### Findings", "", "| Severity | Category | Location | Message |", "|---|---|---|---|"]
        for fd, path in rows[:MAX_ROWS]:
            sev = fd.get("severity")
            where = _code(f"{path}:{fd.get('line')}")
            lines.append(f"| {sev if sev in SEVERITIES else _code(sev)} | {_code(fd.get('category'))} "
                         f"| {where} | {_code(fd.get('message'), 400)} |")
        if len(rows) > MAX_ROWS:
            lines.append(f"\n_Showing {MAX_ROWS} of {len(rows)}; all of them are in the `gem-review-results` "
                         "artifact._")
        lines.append("")

    aup = (f"{debt.get('aup_score')}" if debt.get("aup_measured") else "not measured")
    detected = list(dict.fromkeys(str(d) for d in debt.get("detected_debts") or []))
    lines += ["### LLM tech-debt metrics (advisory; never fails the check)", "",
              "| Metric | Value |", "|---|---|",
              f"| PSC, smell density of added lines | {debt.get('psc_score')} |",
              f"| DUR, deprecated-API rate | {debt.get('dur_score')} |",
              f"| AUP, API plausibility | {aup} |",
              f"| Smell / deprecated / policy hits | {debt.get('smell_hits')} / {debt.get('deprecated_hits')} / "
              f"{debt.get('policy_hits')} |",
              f"| Test files in this PR | {'yes' if r['has_tests'] else 'no'} |", ""]
    if detected:
        lines += ["Detected debt: " + ", ".join(_code(d) for d in detected), ""]
    return "\n".join(lines) + "\n"


def cmd_summary(a: argparse.Namespace) -> int:
    work = Path(a.work)
    diff = _load(work / "results" / "diff.json")
    scan = _load(work / "results" / "scan.json")
    debt = _load(work / "results" / "debt.json")
    t = scan["totals"]
    results = {
        "schema": "gem-review/v1", "verdict": verdict_of(t["critical"], t["findings"], a.fail_on),
        "fail_on": a.fail_on, "gem_ref": a.gem_ref, "gem_version": scan.get("gem_version"),
        "base": diff["base"], "merge_base": diff["merge_base"], "head": diff["head"],
        "has_tests": diff["has_tests"], "totals": t, "files": scan["files"], "debt": debt["report"]}
    _dump(work / "results" / "gem-review.json", results)
    md = render_markdown(results)
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    else:
        sys.stdout.write(md)
    log(f"verdict {results['verdict']}: {t['critical']} critical, {t['findings']} finding(s)")
    return 0


def cmd_enforce(a: argparse.Namespace) -> int:
    results = _load(Path(a.work) / "results" / "gem-review.json")
    critical = int(results["totals"]["critical"])
    if a.fail_on == "critical" and critical > 0:
        print(f"::error title=gem-review::{critical} CRITICAL finding(s); see the job summary", flush=True)
        return 2
    log(f"pass: {critical} critical finding(s), fail_on={a.fail_on}")
    return 0


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gem_review_steps", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("diff")
    s.add_argument("--repo", required=True)
    s.add_argument("--work", required=True)
    s.add_argument("--base", default="")
    s.add_argument("--pr-base-sha", default="")
    s.set_defaults(fn=cmd_diff)

    for name, fn in (("scan", cmd_scan), ("debt", cmd_debt)):
        s = sub.add_parser(name)
        s.add_argument("--gem", required=True)
        s.add_argument("--work", required=True)
        s.set_defaults(fn=fn)

    s = sub.add_parser("summary")
    s.add_argument("--work", required=True)
    s.add_argument("--fail-on", choices=FAIL_ON, required=True)
    s.add_argument("--gem-ref", default="")
    s.add_argument("--summary", default="")
    s.set_defaults(fn=cmd_summary)

    s = sub.add_parser("enforce")
    s.add_argument("--work", required=True)
    s.add_argument("--fail-on", choices=FAIL_ON, required=True)
    s.set_defaults(fn=cmd_enforce)
    return p


def main(argv: List[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return int(a.fn(a))
    except (StepError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f"::error title=gem-review::{_cmd_escape(f'{a.cmd}: {type(exc).__name__}: {exc}')}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
