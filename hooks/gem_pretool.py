#!/usr/bin/env python3
"""GitHubOpsGem PreToolUse hook for Claude Code (WU-08). Stdlib only, runs under Termux.

Reads Claude Code's PreToolUse JSON on stdin, decides whether the call is a GitHub write, gates it
through gemcore (which asks ForgeCore to decide and sign when AUTODEV_URL is set), logs one event
line, and answers:

  PASS  -> exit 0, no output. Never emits "allow": that would skip Claude Code's own permission prompts.
  WARN  -> exit 0, `systemMessage` for you and `additionalContext` for the model; the call proceeds.
  BLOCK -> exit 0 with permissionDecision "deny" (wins even in bypass-permissions mode).

Fail-closed: if the hook itself errors on a write in ENFORCE mode, it denies.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (os.path.join(HERE, ".."), os.path.join(os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem")), "lib")):
    if os.path.isfile(os.path.join(candidate, "mcp_reference_monitor.py")):
        sys.path.insert(0, os.path.abspath(candidate))
        break
import mcp_reference_monitor as gem  # noqa: E402

GEM_HOME = os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem"))

# violation text prefix -> stable rule id (used by the warn-week graduation report)
RULES: List[Tuple[str, str]] = [
    ("kernel: direct write to protected ref", "KERNEL_PROTECTED_REF"),
    ("Direct write to protected branch", "PROTECTED_REF"),
    ("Outbound payload contains credential", "SECRET_PAYLOAD"),
    ("Active prompt-injection alert", "INJECTION_TAINT"),
    ("Review/merge action without ingested PR evidence", "MERGE_NO_EVIDENCE"),
    ("ForgeCore attestation unavailable", "ATTESTATION_UNAVAILABLE"),
    ("Fast-integration debt", "FAST_INTEGRATION"),
    ("House-policy calls", "POLICY_CALLS"),
    ("Unverified cross-boundary ABI symbols", "ABI_UNVERIFIED"),
    ("Critical supply-chain/secret findings", "SUPPLY_CHAIN"),
    ("Auto-approval forbidden", "UNTRUSTED_APPROVAL"),
    ("Force push", "FORCE_PUSH"),
    ("Push of all refs", "PUSH_ALL_REFS"),
    ("Hook error", "HOOK_ERROR"),
]

SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


# --------------------------------------------------------------------------- classification

def _current_branch(cwd: Optional[str]) -> str:
    """Branch a bare `git push` targets. symbolic-ref also works on an unborn branch."""
    for argv in (["git", "symbolic-ref", "--short", "HEAD"], ["git", "rev-parse", "--abbrev-ref", "HEAD"]):
        try:
            out = subprocess.run(argv, cwd=cwd or None, capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    return "HEAD"


def _repo_slug(cwd: Optional[str]) -> str:
    if os.environ.get("GEM_REPOSITORY"):
        return os.environ["GEM_REPOSITORY"]
    try:
        url = subprocess.run(["git", "config", "--get", "remote.origin.url"], cwd=cwd or None,
                             capture_output=True, text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        url = ""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return m.group(1) if m else "unknown/unknown"


def classify_bash(command: str, cwd: Optional[str]) -> List[Dict[str, Any]]:
    """Return one write description per gated git/gh operation in a shell command."""
    writes: List[Dict[str, Any]] = []
    for segment in SEGMENT_SPLIT.split(command or ""):
        try:
            argv = shlex.split(segment)
        except ValueError:
            argv = segment.split()
        while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):  # leading VAR=value
            argv = argv[1:]
        if not argv:
            continue
        git_cwd = cwd
        sub_i = None
        if argv[0] == "git":
            i = 1
            while i < len(argv) and argv[i].startswith("-"):
                if argv[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(argv):
                    if argv[i] == "-C":
                        git_cwd = os.path.join(cwd or os.getcwd(), argv[i + 1])
                    i += 2
                else:
                    i += 1
            sub_i = i if i < len(argv) else None
        if sub_i is not None and argv[sub_i] == "push":
            args = argv[sub_i + 1:]
            flags = [x for x in args if x.startswith("-")]
            positional = [x for x in args if not x.startswith("-")]
            force = any(f in ("-f", "--force") or f.startswith("--force-with-lease") or f == "--force-if-includes"
                        for f in flags) or any(p.startswith("+") for p in positional[1:])
            deleting = "-d" in flags or "--delete" in flags
            extra: List[str] = []
            if "--all" in flags or "--mirror" in flags:
                extra.append("Push of all refs (--all/--mirror) touches protected branches.")
            refspecs = positional[1:]
            targets = []
            for spec in refspecs or ["HEAD"]:
                spec = spec.lstrip("+")
                dst = spec.split(":", 1)[1] if ":" in spec else spec
                if dst in ("HEAD", "@") or not dst:
                    dst = _current_branch(git_cwd) if not (deleting and dst) else dst
                targets.append(dst)
            if force:
                extra.append("Force push rewrites shared history.")
            for t in targets:
                writes.append({"tool": "git_force_push" if force else "git_push", "branch": t,
                               "extra": list(extra), "payload": None, "event": None})
        elif argv[0] == "gh" and argv[1:3] == ["pr", "merge"]:
            writes.append({"tool": "merge_pull_request", "branch": f"pr:{argv[3] if len(argv) > 3 else '?'}",
                           "extra": [], "payload": None, "event": None})
    return writes


def classify_mcp(tool_name: str, tool_input: Dict[str, Any]) -> List[Dict[str, Any]]:
    short = tool_name.split("__")[-1]
    ti = tool_input or {}
    if short == "push_files":
        payload = "\n".join(str(f.get("content", "")) for f in ti.get("files", []) if isinstance(f, dict))
        return [{"tool": "push_files", "branch": str(ti.get("branch", "")), "payload": payload, "extra": [], "event": None}]
    if short in ("create_or_update_file", "delete_file"):
        return [{"tool": short, "branch": str(ti.get("branch", "")), "payload": str(ti.get("content", "")),
                 "extra": [], "event": None}]
    if short == "merge_pull_request":
        return [{"tool": "merge_pull_request", "branch": f"pr:{ti.get('pullNumber', ti.get('pull_number', '?'))}",
                 "payload": None, "extra": [], "event": None}]
    if short == "create_pull_request":
        return [{"tool": "create_pull_request", "branch": str(ti.get("head", "")),
                 "payload": f"{ti.get('title', '')}\n{ti.get('body', '')}", "extra": [], "event": None}]
    if short in ("create_pull_request_review", "pull_request_review_write"):
        event = str(ti.get("event", "")).upper() or None
        return [{"tool": short, "branch": f"pr:{ti.get('pullNumber', ti.get('pull_number', '?'))}",
                 "payload": str(ti.get("body", "")), "extra": [], "event": event}]
    if short in ("add_issue_comment", "create_issue", "update_issue"):
        return [{"tool": "add_issue_comment", "branch": "issue", "payload": str(ti.get("body", "")),
                 "extra": [], "event": None}]
    return []


def classify(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    tool = str(event.get("tool_name", ""))
    ti = event.get("tool_input") or {}
    if tool == "Bash":
        return classify_bash(str(ti.get("command", "")), event.get("cwd"))
    if tool.startswith("mcp__") and "github" in tool.lower():
        return classify_mcp(tool, ti)
    return []


# --------------------------------------------------------------------------- gating + output

def rule_ids(violations: List[str]) -> List[str]:
    ids = []
    for v in violations:
        ids.append(next((rid for prefix, rid in RULES if v.startswith(prefix)), "OTHER"))
    return sorted(set(ids))


def log_event(record: Dict[str, Any]) -> None:
    try:
        os.makedirs(GEM_HOME, exist_ok=True)
        with open(os.path.join(GEM_HOME, "events.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass  # logging must never change a gate decision


def gate_one(write: Dict[str, Any], session_id: str, repo: str) -> "gem.GateDecision":
    mon = gem.StatefulGitHubOpsMonitor(repository=repo, session_id=session_id)
    return mon.evaluate_write(write["tool"], write["branch"], action_event=write.get("event"),
                              payload_text=write.get("payload") or None,
                              extra_violations=write.get("extra") or None)


def respond(decisions: List["gem.GateDecision"], tool_name: str) -> Dict[str, Any]:
    blocked = [d for d in decisions if d.decision == "BLOCK"]
    warned = [d for d in decisions if d.decision == "WARN"]
    if blocked:
        d = blocked[0]
        signer = (f" Verdict signed by ForgeCore (attestation {d.attestation.get('attestation_id')})."
                  if d.attestation else "")
        reason = (f"GitHubOpsGem blocked {d.tool_name} -> {d.target_branch}: " + "; ".join(d.violations)
                  + signer + " Use a feat/<slug> or fix/<issue>-<slug> branch and open a PR instead.")
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    if warned:
        lines = [f"{d.tool_name} -> {d.target_branch}: " + "; ".join(d.violations) for d in warned]
        msg = "GitHubOpsGem WARN (week-one shadow mode, not blocking): " + " | ".join(lines)
        return {"systemMessage": msg,
                "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "additionalContext": msg + " Fix this or say why it is a false positive."}}
    return {}


def main() -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        writes = classify(event)
    except Exception as exc:  # noqa: BLE001 - a broken payload must not silently pass a write
        writes, event = [], {}
        mode = gem.GemConfig.from_env().effective_mode()
        if mode == gem.EnforcementMode.ENFORCE and re.search(r"git\s+push|mcp__\w*github", raw):
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                     "permissionDecisionReason": f"Hook error, failing closed: {exc}"}}))
        return 0
    if not writes:
        return 0

    session_id = str(event.get("session_id") or os.environ.get("GEM_SESSION_ID") or "unknown")
    repo = _repo_slug(event.get("cwd"))
    decisions = []
    for w in writes:
        try:
            gd = gate_one(w, session_id, repo)
        except Exception as exc:  # noqa: BLE001
            enforce = gem.GemConfig.from_env().effective_mode() == gem.EnforcementMode.ENFORCE
            gd = gem.GateDecision(not enforce, "BLOCK" if enforce else "WARN", [f"Hook error: {exc}"],
                                  w["tool"], w["branch"], gem.GemConfig.from_env().effective_mode())
        decisions.append(gd)
        log_event({
            "ts": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "side": "hook",
            "session": session_id, "repo": repo, "tool": gd.tool_name, "target": gd.target_branch,
            "decision": gd.decision, "mode": gd.mode.value, "rules": rule_ids(gd.violations),
            "attestation_id": (gd.attestation or {}).get("attestation_id"),
            "detail_sha256": hashlib.sha256("|".join(gd.violations).encode()).hexdigest()[:16],
            "user_override": False,
        })
    out = respond(decisions, str(event.get("tool_name", "")))
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
