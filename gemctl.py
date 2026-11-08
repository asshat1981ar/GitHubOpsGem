#!/usr/bin/env python3
"""gemctl — command-line front end for gemcore (GitHubOpsGem). Stdlib only, runs under Termux.

Every subcommand reads files or stdin and writes JSON (or text where noted) to stdout.
Exit codes: 0 = ok / PASS / WARN, 2 = BLOCK or verification failed, 1 = usage or input error.

  gemctl scan-diff  --path FILE [--patch PATCHFILE|-]         findings for one file's unified diff
  gemctl debt       --patch PATCHFILE|- [--has-tests] [--tests-passed yes|no]
                    [--prompt-versioned] [--provenance]        PSC / DUR / policy report
  gemctl gate       --tool T --branch B [--event APPROVE] [--payload FILE|-]
                    [--patches FILES.json] [--mode warn|enforce] [--xml]
  gemctl ci-window  [--max 220] [--tail 40] < log            root-cause-first CI log window (text)
  gemctl strip      [--assume-open] < text                   remove <think> reasoning (text)
  gemctl verify     --attestation FILE|-                      ask ForgeCore whether an attestation is valid
  gemctl heavy      on [--wait 600] [--export] | off | status  wake / sleep the 4xB200 burst deployment (WU-07)
  gemctl trailer    add MSG_FILE | note [COMMIT] | verify RANGE | install-hook [--repo PATH]
                                                             Gem-Gate commit trailers + git-notes (WU-09b)
  gemctl version

`gemctl heavy on` exits 2 when the controller refuses (spend cap or deployment guard) and 3 when the B200 is
still warming after --wait seconds; keep working on ds-main either way.

`gemctl trailer` notes live under refs/notes/gem-gate and `git push` does not send them:
git push origin refs/notes/gem-gate
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from enum import Enum
from typing import Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_reference_monitor as gem  # noqa: E402


def _read(src: Optional[str]) -> str:
    if src in (None, "-"):
        return sys.stdin.read()
    with open(src, encoding="utf-8") as fh:
        return fh.read()


def _jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    return obj


def _emit(obj: Any) -> None:
    json.dump(_jsonable(obj), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def cmd_scan_diff(a: argparse.Namespace) -> int:
    findings = gem.SupplyChainAndSecretScanner.audit_diff(a.path, _read(a.patch))
    _emit({"path": a.path, "findings": findings,
           "critical": sum(f.severity == gem.Severity.CRITICAL for f in findings)})
    return 2 if a.fail_on_critical and any(f.severity == gem.Severity.CRITICAL for f in findings) else 0


def cmd_debt(a: argparse.Namespace) -> int:
    tests_passed = None if a.tests_passed is None else a.tests_passed == "yes"
    rep = gem.LLMTechnicalDebtSensor.evaluate_patch(
        _read(a.patch), has_tests=a.has_tests, has_prompt_versioning=a.prompt_versioned,
        has_provenance_receipt=a.provenance, tests_passed=tests_passed)
    _emit(rep)
    return 0


def _monitor(mode: Optional[str]) -> gem.StatefulGitHubOpsMonitor:
    cfg = gem.GemConfig.from_env()
    if mode:
        cfg = dataclasses.replace(cfg, mode=gem.EnforcementMode(mode.upper()), enforce_after=None)
    return gem.StatefulGitHubOpsMonitor(config=cfg)


def cmd_gate(a: argparse.Namespace) -> int:
    mon = _monitor(a.mode)
    if a.patches:
        files = json.loads(_read(a.patches))
        mon.ingest_pull_request_files(files)
    payload = _read(a.payload) if a.payload else None
    debt = None
    if a.patches and a.tool in mon.REVIEW_TOOLS | {"merge_pull_request"}:
        joined = "\n".join(f.get("patch", "") for f in json.loads(_read(a.patches)))
        debt = gem.LLMTechnicalDebtSensor.evaluate_patch(joined, a.has_tests, True, True)
    gd = mon.evaluate_write(a.tool, a.branch, action_event=a.event, payload_text=payload, debt_report=debt)
    if a.xml:
        sys.stdout.write(gd.to_xml() + "\n")
    else:
        _emit({"allowed": gd.allowed, "decision": gd.decision, "violations": gd.violations,
               "mode": gd.mode, "tool": gd.tool_name, "branch": gd.target_branch,
               "signature": gd.signature, "attestation": gd.attestation, "facts": gd.facts})
    return 2 if gd.decision == "BLOCK" else 0


def cmd_ci_window(a: argparse.Namespace) -> int:
    sys.stdout.write(gem.StatefulGitHubOpsMonitor.truncate_ci_log(sys.stdin.read(), a.max, a.tail) + "\n")
    return 0


def cmd_strip(a: argparse.Namespace) -> int:
    f = gem.ThinkStreamFilter(assume_open=a.assume_open)
    out = f.feed(sys.stdin.read()) + f.flush()
    sys.stdout.write(out)
    sys.stderr.write(f"stripped_blocks={f.stripped_blocks}\n")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    att = gem.ForgeCoreAttestor.from_env()
    if att is None:
        sys.stderr.write("gemctl verify needs AUTODEV_URL (or GEM_FORGECORE_URL) and AUTODEV_API_BEARER_TOKEN\n")
        return 1
    try:
        result = att.verify(json.loads(_read(a.attestation)))
    except gem.ForgeCoreUnavailable as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    _emit(result)
    return 0 if result.get("valid") else 2


def _refusal(body: dict) -> str:
    why = body.get("refused", "")
    if why.startswith("cap_"):
        period = "today's" if why == "cap_day" else "this week's"
        return (f"{period} GPU cap is reached (${body.get('headroom_usd', 0)} left, a wake needs "
                f"${body.get('reserve_usd', '?')}); resets {body.get('resets_at')}")
    if why == "guard":
        return f"deployment guard failed: {body.get('detail')}"
    return str(body.get("detail") or body.get("error") or body)


def cmd_heavy(a: argparse.Namespace) -> int:
    import gem_lifecycle_client as lc

    try:
        if a.action == "status":
            code, st = lc.call("GET", "/status")
            _emit(st)
            return 0 if code == 200 else 1
        if a.action == "off":
            code, body = lc.call("POST", "/heavy", {"on": False})
            if code >= 300:
                sys.stderr.write(f"gemctl heavy off: HTTP {code}: {body}\n")
                return 1
            sys.stderr.write("B200 scaling to zero. In Claude Code switch back with: /model ds-main\n")
            return 0
        code, body = lc.call("POST", "/heavy", {"on": True})
        if code in (409, 503):
            sys.stderr.write(f"B200 not started: {_refusal(body)}. Keep working on ds-main.\n")
            return 2
        if code >= 300:
            sys.stderr.write(f"gemctl heavy on: HTTP {code}: {body}\n")
            return 1
        deadline = time.monotonic() + a.wait
        while True:
            _, st = lc.call("GET", "/status")
            if st.get("burst_ready"):
                break
            if time.monotonic() >= deadline:
                sys.stderr.write(f"B200 still {st.get('b200', 'warming')} after {a.wait}s; keep working on ds-main "
                                 "and check again with: gemctl heavy status\n")
                return 3
            sys.stderr.write(f"B200 {st.get('b200')} (desired {st.get('desired')}, replicas {st.get('replicas')}); "
                             f"${st.get('headroom_usd')} of GPU budget left\n")
            time.sleep(a.poll)
        if a.export:
            sys.stdout.write("export ANTHROPIC_MODEL=ds-burst\n")
        sys.stderr.write(f"B200 ready (${st.get('usd_per_hour_running')}/h, ${st.get('headroom_usd')} left before "
                         f"the {st.get('binding_cap')} cap). In Claude Code: /model ds-burst. It sleeps after "
                         f"{int(st.get('idle_sleep_s') or 180)}s without requests.\n")
        return 0
    except lc.LifecycleUnavailable as exc:
        sys.stderr.write(f"{exc}. Is the tunnel up (ssh -L 8090:127.0.0.1:8090 awsbox) and "
                         "GEM_LIFECYCLE_TOKEN set?\n")
        return 1


TRAILER_HELP = """Gem-Gate commit trailers backed by ForgeCore attestations (WU-09b, see gem_trailers.py).

  gemctl trailer install-hook [--repo PATH]  write the commit-msg hook (.git/hooks or core.hooksPath);
                                             an existing non-gem hook is kept and chained, never clobbered
  gemctl trailer add MSG_FILE                what the hook runs: append Gem-Gate: <attestation_id> for the
                                             newest PASS/WARN attestation of this repo + branch (<15 min old);
                                             none found: note on stderr, exit 0 (exit 1 if GEM_TRAILER_REQUIRED=1)
  gemctl trailer note [COMMIT]               attach the stored attestation for COMMIT's trailer (default HEAD)
                                             as a git note under refs/notes/gem-gate
  gemctl trailer verify RANGE                JSON report per commit, e.g. RANGE=origin/main..HEAD;
                                             exit 0 all verified, 2 blocked/invalid/mismatch, 1 missing/unavailable

Notes are NOT pushed by `git push`. Publish them with:  git push origin refs/notes/gem-gate
and fetch them before verifying elsewhere:              git fetch origin refs/notes/gem-gate:refs/notes/gem-gate
verify needs AUTODEV_URL (or GEM_FORGECORE_URL) and AUTODEV_API_BEARER_TOKEN; repository = GEM_REPOSITORY or origin.
"""


def cmd_trailer(a: argparse.Namespace) -> int:
    import gem_trailers as gt

    if a.action == "add":
        return gt.add_trailer(a.msg_file)
    if a.action == "note":
        sha, att_id = gt.attach_note_from_store(a.commit)
        sys.stderr.write(f"gem-gate: attestation {att_id} attached to {sha[:12]} under {gt.NOTES_REF}. "
                         f"Publish it with: git push origin {gt.NOTES_REF}\n")
        return 0
    if a.action == "verify":
        att = gem.ForgeCoreAttestor.from_env()
        if att is None:
            sys.stderr.write("gemctl trailer verify: ForgeCore not configured (AUTODEV_URL or GEM_FORGECORE_URL, "
                             "plus AUTODEV_API_BEARER_TOKEN); signatures cannot be checked\n")
        report = gt.verify_range(a.rev_range, att)
        _emit(report)
        return gt.exit_code(report)
    _emit(gt.install_hook(a.repo, gemctl_path=os.path.abspath(__file__), python=sys.executable))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gemctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan-diff"); s.add_argument("--path", required=True); s.add_argument("--patch")
    s.add_argument("--fail-on-critical", action="store_true"); s.set_defaults(fn=cmd_scan_diff)

    s = sub.add_parser("debt"); s.add_argument("--patch"); s.add_argument("--has-tests", action="store_true")
    s.add_argument("--tests-passed", choices=["yes", "no"]); s.add_argument("--prompt-versioned", action="store_true")
    s.add_argument("--provenance", action="store_true"); s.set_defaults(fn=cmd_debt)

    s = sub.add_parser("gate"); s.add_argument("--tool", required=True); s.add_argument("--branch", required=True)
    s.add_argument("--event", choices=["APPROVE", "COMMENT", "REQUEST_CHANGES"]); s.add_argument("--payload")
    s.add_argument("--patches"); s.add_argument("--has-tests", action="store_true")
    s.add_argument("--mode", choices=["warn", "enforce"]); s.add_argument("--xml", action="store_true")
    s.set_defaults(fn=cmd_gate)

    s = sub.add_parser("ci-window"); s.add_argument("--max", type=int, default=220)
    s.add_argument("--tail", type=int, default=40); s.set_defaults(fn=cmd_ci_window)

    s = sub.add_parser("strip"); s.add_argument("--assume-open", action="store_true"); s.set_defaults(fn=cmd_strip)

    s = sub.add_parser("verify"); s.add_argument("--attestation"); s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("heavy"); s.add_argument("action", choices=["on", "off", "status"])
    s.add_argument("--wait", type=int, default=600); s.add_argument("--poll", type=float, default=10.0)
    s.add_argument("--export", action="store_true"); s.set_defaults(fn=cmd_heavy)

    s = sub.add_parser("trailer", help="Gem-Gate commit trailers + git notes (push: git push origin refs/notes/gem-gate)",
                       description=TRAILER_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    t = s.add_subparsers(dest="action", required=True)
    t.add_parser("add", help="append the Gem-Gate trailer (commit-msg hook)").add_argument("msg_file")
    t.add_parser("note", help="attach the stored attestation as a git note under refs/notes/gem-gate; "
                 "push with: git push origin refs/notes/gem-gate").add_argument("commit", nargs="?", default="HEAD")
    t.add_parser("verify", help="verify every commit in RANGE (needs refs/notes/gem-gate fetched)"
                 ).add_argument("rev_range", metavar="RANGE")
    t.add_parser("install-hook", help="write the commit-msg hook").add_argument("--repo", default=".")
    s.set_defaults(fn=cmd_trailer)

    s = sub.add_parser("version"); s.set_defaults(fn=lambda a: (sys.stdout.write(gem.__version__ + "\n"), 0)[1])
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write(f"gemctl: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
