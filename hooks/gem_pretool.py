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
import tempfile
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
    ("No ForgeCore attestor configured", "ATTESTOR_MISSING"),
    ("Command too long to classify", "UNPARSED_COMMAND"),
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

# --- shell classification limits and tables -------------------------------------------------------------------
# The hook is a best-effort speed bump for an agent's own commands, not a shell parser. The enforcement that
# cannot be bypassed from here is server-side (rulesets on main, the gem-review required check). Not covered:
# aliases, scripts, variables and brace/ANSI-C expansion (`git pus{h,}`, `git $'push'`), `ssh host git push`,
# `git update-ref`, `gh api` and other gh writes, interpreters (`python -c`). A command we cannot parse (over the
# size or nesting limit) is gated, not waved through.
MAX_COMMAND_CHARS = 200_000
MAX_NESTING = 8
MAX_HEREDOC_CANDIDATES = 64
PLACEHOLDER = "\x01"  # stands in for a $(...) / `...` that was lifted out of a command word
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
SCRIPT_READERS = SHELLS | {"eval", "source", "."}
# Commands that run another command. Their own options are not parsed: the wrapped command is the first later
# word that is a command we recognise; quoted strings they swallow (env -S 'x', su -c 'x') are classified too.
WRAPPERS = {"sudo", "doas", "env", "command", "exec", "nohup", "time", "nice", "ionice", "timeout", "setsid",
            "stdbuf", "builtin", "su", "runuser", "flock", "watch", "busybox", "find", "parallel", "chroot", "strace"}
COMMAND_WORDS = {"git", "gh", "eval", "xargs"} | SHELLS | WRAPPERS
GRAMMAR = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"}
XARGS_ARG_OPTS = {"-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "-R", "-S"}
PUSH_ARG_OPTS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
HEREDOC_OP = re.compile(r"<<(-?)[ \t]*(?:(['\"])([^'\"\n]+)\2|([A-Za-z_]\w*))")
INLINE_REDIRECT = re.compile(r"^([^<>]*?)(\d*(?:>>?|<)&?|&>>?)(.*)$")


def _split_top_level(command: str) -> List[str]:
    """Split on ; & && | || ( ) and newlines that are outside quotes. `>&` / `&>` redirections are not separators."""
    segments: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\" and quote != "'" and i + 1 < n:
            cur.append(command[i:i + 2])
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c in ";|\n()" or (c == "&" and not (i > 0 and command[i - 1] in "<>") and command[i + 1:i + 2] != ">"):
            segments.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    segments.append("".join(cur))
    return [x.strip() for x in segments if x.strip()]


def _extract_substitutions(command: str, quotes: bool = True) -> Tuple[str, List[str]]:
    """Lift $(...) and `...` out of a command. Returns the text with each replaced by PLACEHOLDER (so the word it
    sat in stays one word) and the lifted bodies. They run even inside double quotes, never inside single quotes;
    an apostrophe inside double quotes is just text. `quotes=False` is for heredoc bodies, where no quote quotes."""
    out: List[str] = []
    bodies: List[str] = []
    single = double = False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\" and not single and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if quotes and c == "'" and not double:
            single = not single
        elif quotes and c == '"' and not single:
            double = not double
        elif not single and command.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (command[j] == "(") - (command[j] == ")")
                j += 1
            if depth:  # unterminated: everything after is the body (one pass, no rescans)
                bodies.append(command[i + 2:])
                out.append(PLACEHOLDER)
                break
            bodies.append(command[i + 2:j - 1])
            out.append(PLACEHOLDER)
            i = j
            continue
        elif not single and c == "`":
            j = command.find("`", i + 1)
            bodies.append(command[i + 1:j] if j != -1 else command[i + 1:])
            out.append(PLACEHOLDER)
            i = (j if j != -1 else n) + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), bodies


def _substitutions(command: str, quotes: bool = True) -> List[str]:
    return _extract_substitutions(command, quotes)[1]


def _heredoc_body(command: str, i: int, delim: str, quoted: bool, dash: bool, script: bool) -> Tuple[int, Optional[str]]:
    """Consume one heredoc body starting at `i`. Returns (index after the terminator, replacement text) or
    (i, None) when unterminated. A script reader keeps the body (it is commands); a quoted delimiter drops it
    (data); an unquoted delimiter keeps only its $(...) and backtick bodies, which the shell does run."""
    end = re.compile(r"^" + (r"[ \t]*" if dash else "") + re.escape(delim) + r"[ \t]*$", re.M).search(command, i)
    if not end:
        return i, None
    body = command[i:end.start()]
    if script:
        return end.end(), command[i:end.end()]
    if quoted:
        return end.end(), ""
    inner = _substitutions(body, quotes=False)
    return end.end(), ("\n".join(inner) + "\n") if inner else ""


def _expand_heredocs(command: str) -> str:
    """Treat heredoc bodies as data, except for script readers and live substitutions. One pass, no rescans: an
    unterminated heredoc, or more than MAX_HEREDOC_CANDIDATES `<<`, leaves the rest as commands (fail closed)."""
    out: List[str] = []
    pending: List[Tuple[str, bool, bool, bool]] = []
    quote: Optional[str] = None
    give_up = False
    candidates = 0
    line_start = 0
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\" and quote != "'" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            out.append(c)
            i += 1
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "#" and (i == 0 or command[i - 1] in " \t\n;&|()"):
            j = command.find("\n", i)
            j = n if j == -1 else j
            out.append(command[i:j])
            i = j
            continue
        if c == "\n":
            out.append(c)
            i += 1
            for delim, quoted, dash, script in pending:
                i, body = _heredoc_body(command, i, delim, quoted, dash, script)
                if body is None:
                    give_up = True
                    break
                out.append(body)
            pending = []
            line_start = i
            continue
        if not give_up and command.startswith("<<", i) and command[i + 2:i + 3] != "<" \
                and (i == 0 or command[i - 1] != "<"):
            candidates += 1
            if candidates > MAX_HEREDOC_CANDIDATES:
                give_up = True
            else:
                eol = command.find("\n", i)
                line = command[line_start:n if eol == -1 else eol]
                before = command[line_start:i]
                arithmetic = "((" in before and "))" not in before[before.rfind("(("):]
                m = None if arithmetic else HEREDOC_OP.match(command, i)
                if m:
                    # the receiver can sit before or after the operator: `bash <<EOF`, `<<EOF bash`, `<<EOF | bash`
                    words = {os.path.basename(w) for w in re.split(r"[\s;&|()]+", line)}
                    pending.append((m.group(3) or m.group(4), bool(m.group(2)), bool(m.group(1)),
                                    bool(words & SCRIPT_READERS)))
                    out.append(m.group(0))
                    i = m.end()
                    continue
        out.append(c)
        i += 1
    return "".join(out)


def _raw_words(segment: str) -> List[str]:
    """Split on whitespace outside quotes, keeping the quotes in each word. One pass."""
    words: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if c == "\\" and quote != "'" and i + 1 < n:
            cur.append(segment[i:i + 2])
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c in " \t\r\n":
            if cur:
                words.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        words.append("".join(cur))
    return words


def _tokens(segment: str) -> List[str]:
    """Words of one command with redirections and comments removed. Redirections are recognised before quote
    removal so a quoted '>' stays an argument."""
    words: List[str] = []
    skip = False
    for tok in _raw_words(segment):
        if tok.startswith("#"):
            break  # a comment runs to the end of the command
        if skip:
            skip = False
            continue
        if tok[:1] not in ("'", '"'):
            m = INLINE_REDIRECT.match(tok)
            if m:
                head, _op, target = m.groups()
                if head:
                    words.append(head)
                skip = not target  # a bare operator takes the next token as its target
                continue
        try:
            words.append("".join(shlex.split(tok)) if re.search(r"['\"\\]", tok) else tok)
        except ValueError:
            words.append(tok)
    return words


def _unwrap(argv: List[str]) -> Tuple[List[str], List[str]]:
    """Strip leading VAR=value, shell grammar words and wrappers. For a wrapper the wrapped command is the first
    later word that is a command we recognise; whitespace-containing words it skips (env -S 'x', su -c 'x') are
    returned so the caller classifies them as commands too."""
    skipped: List[str] = []
    while argv:
        head = argv[0]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head) or head in GRAMMAR:
            argv = argv[1:]
            continue
        if os.path.basename(head) not in WRAPPERS:
            break
        rest = argv[1:]
        k = next((m for m, w in enumerate(rest) if os.path.basename(w) in COMMAND_WORDS), len(rest))
        skipped.extend(w.split("=", 1)[1] if w.startswith("-") and "=" in w else w
                       for w in rest[:k] if re.search(r"\s", w))  # env --split-string='x' carries its value
        argv = rest[k:]
    return argv, skipped


def _unparsed(why: str) -> List[Dict[str, Any]]:
    """A command we will not or cannot parse is gated as an unparsed write, never waved through. Large file
    writes belong in the Write/Edit tools."""
    note = f"Command too long to classify ({why}); split it, or use the Write/Edit tools for file contents."
    return [{"tool": "git_push", "branch": "unparsed", "extra": [note], "payload": None, "event": None}]


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


def classify_bash(command: str, cwd: Optional[str], depth: int = 0) -> List[Dict[str, Any]]:
    """Return one write description per gated git/gh operation in a shell command, including operations behind
    newlines, `&`, parentheses, $(...), backticks, `bash -c`, here-strings, script heredocs, `eval`, `xargs` and
    wrappers (sudo, env, timeout, ...). Quoted text and data heredocs are not commands. Limits: see the note above
    MAX_COMMAND_CHARS."""
    command = command or ""
    if depth == 0 and len(command) > MAX_COMMAND_CHARS:
        return _unparsed(f"> {MAX_COMMAND_CHARS} characters")
    if depth > MAX_NESTING:
        return _unparsed(f"nested more than {MAX_NESTING} levels deep")
    writes: List[Dict[str, Any]] = []
    text, bodies = _extract_substitutions(_expand_heredocs(command.replace("\\\n", " ")))
    for inner in bodies:
        writes.extend(classify_bash(inner, cwd, depth + 1))
    for segment in _split_top_level(text):
        raw = _tokens(segment)
        argv, skipped = _unwrap(raw)
        for s in skipped:
            writes.extend(classify_bash(s, cwd, depth + 1))
        if not argv:
            continue
        name = os.path.basename(argv[0])
        if name in SHELLS:
            here = next((k for k, a in enumerate(raw) if a.startswith("<<<")), None)
            if here is not None:  # here-string: the string is the script
                script = raw[here][3:] or (raw[here + 1] if here + 1 < len(raw) else "")
                writes.extend(classify_bash(script, cwd, depth + 1))
            for j, a in enumerate(argv[1:], start=1):
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a) and j + 1 < len(argv):
                    writes.extend(classify_bash(argv[j + 1], cwd, depth + 1))
                    break
            continue
        if name == "eval":
            writes.extend(classify_bash(" ".join(argv[1:]), cwd, depth + 1))
            continue
        if name == "xargs":
            rest = argv[1:]
            while rest and rest[0].startswith("-"):
                opt, rest = rest[0], rest[1:]
                if opt in XARGS_ARG_OPTS and rest:
                    rest = rest[1:]
            if rest:
                writes.extend(classify_bash(shlex.join(rest), cwd, depth + 1))
            continue
        git_cwd = cwd
        sub_i = None
        if name == "git":
            i = 1
            while i < len(argv) and (argv[i].startswith("-") or argv[i] == PLACEHOLDER):
                if argv[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(argv):
                    if argv[i] == "-C":
                        git_cwd = os.path.join(cwd or os.getcwd(), argv[i + 1])
                    i += 2
                else:
                    i += 1
            sub_i = i if i < len(argv) else None
        if sub_i is not None and argv[sub_i] == "push":
            args: List[str] = []
            k = sub_i + 1
            while k < len(argv):  # drop option values (-o ci.skip) so they are not read as remote or refspec
                if argv[k] in PUSH_ARG_OPTS and k + 1 < len(argv):
                    k += 2
                    continue
                args.append(argv[k])
                k += 1
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
        elif name == "gh":
            k = 1
            while k < len(argv) and argv[k].startswith("-"):  # global flags: -R owner/repo, --hostname h
                k += 2 if argv[k] in ("-R", "--repo", "--hostname") else 1
            sub, rest = argv[k:k + 2], argv[k + 2:]
            if sub == ["pr", "merge"]:
                num = next((a for a in rest if not a.startswith("-")), "?")
                writes.append({"tool": "merge_pull_request", "branch": f"pr:{num}",
                               "extra": [], "payload": None, "event": None})
            elif sub == ["pr", "create"]:
                head = next((rest[m + 1] for m, a in enumerate(rest) if a in ("--head", "-H") and m + 1 < len(rest)), None)
                head = head or next((a.split("=", 1)[1] for a in rest if a.startswith("--head=")), None)
                writes.append({"tool": "create_pull_request", "branch": head or _current_branch(cwd),
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
    if short == "create_branch":
        return [{"tool": "create_branch", "branch": str(ti.get("branch", "")), "payload": None, "extra": [],
                 "event": None}]
    if short in ("update_pull_request", "update_pull_request_branch"):
        body = f"{ti.get('title', '')}\n{ti.get('body', '')}" if short == "update_pull_request" else None
        return [{"tool": short, "branch": f"pr:{ti.get('pullNumber', ti.get('pull_number', '?'))}",
                 "payload": body, "extra": [], "event": None}]
    if short in ("actions_run_trigger", "run_workflow"):
        return [{"tool": "run_workflow", "branch": str(ti.get("ref", "")), "payload": None, "extra": [],
                 "event": None}]
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


def store_attestation(att: Optional[Dict[str, Any]]) -> Optional[str]:
    """Keep the full attestation at $GEM_HOME/attestations/<id>.json for `gemctl trailer` (WU-09b).
    Atomic, owner-only (file 0600, dir 0700). Fail-open: storage must never change a gate decision."""
    try:
        att_id = str((att or {}).get("attestation_id") or "")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", att_id):
            return None
        folder = os.path.join(GEM_HOME, "attestations")
        os.makedirs(folder, mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=folder)  # mkstemp creates 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(att, fh, sort_keys=True)
            path = os.path.join(folder, att_id + ".json")
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path
    except Exception:  # noqa: BLE001
        return None


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
        if any(v.startswith("No ForgeCore attestor") for v in d.violations):
            hint = (" ForgeCore is not configured in this session (AUTODEV_URL and AUTODEV_API_BEARER_TOKEN); a "
                    "different branch will not help. Tell the user; do not work around this gate.")
        elif any(v.startswith("ForgeCore attestation unavailable") for v in d.violations):
            hint = (" ForgeCore did not answer (tunnel or server down); a different branch will not help. Tell the "
                    "user; do not retry in a loop or work around this gate.")
        else:
            hint = " Use a feat/<slug> or fix/<issue>-<slug> branch and open a PR instead."
        reason = (f"GitHubOpsGem blocked {d.tool_name} -> {d.target_branch}: " + "; ".join(d.violations)
                  + signer + hint)
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    if warned:
        lines = [f"{d.tool_name} -> {d.target_branch}: " + "; ".join(d.violations) for d in warned]
        msg = "GitHubOpsGem WARN (week-one shadow mode, not blocking): " + " | ".join(lines)
        return {"systemMessage": msg,
                "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "additionalContext": msg + " Fix this or say why it is a false positive."}}
    return {}


# --------------------------------------------------------------------------- B200 operator guard (WU-07 review #10)
# The model may read B200 status, never operate it: waking the 4xB200 bills about $52/h. Always enforced,
# like outbound secrets, whatever the warn/enforce mode. Defense in depth: the operator token also lives in a
# 0600 file the hooks never export, and the controller limits each token to its role.
LIFECYCLE_BASH = [
    (re.compile(r"operator\.token"), "reads the B200 operator token"),
    (re.compile(r"\bGEM_LIFECYCLE_(?:FEED_)?TOKEN\b"), "uses a B200 controller token"),
    (re.compile(r"\b(?:gem|gemctl(?:\.py)?)\s+heavy\s+(?:on|off)\b"), "switches the B200 on or off"),
    (re.compile(r"(?:127\.0\.0\.1|localhost|\[::1\]):8090/(?:wake|sleep|heavy|touch|signal|session|check)"),
     "calls a B200 controller write endpoint"),
    (re.compile(r"\bgem_lifecycle_client\b"), "drives the B200 controller client directly"),
    (re.compile(r"/etc/gem/lifecycle\.env"), "reads the controller's secrets file"),
]
LIFECYCLE_PATHS = re.compile(r"operator\.token|/etc/gem/lifecycle\.env")


def lifecycle_guard(event: Dict[str, Any]) -> Optional[str]:
    """Reason to deny if this tool call would operate the B200 or read its operator credentials."""
    tool = str(event.get("tool_name", ""))
    ti = event.get("tool_input") or {}
    if tool == "Bash":
        cmd = str(ti.get("command", ""))
        for rx, what in LIFECYCLE_BASH:
            if rx.search(cmd):
                return what
    elif tool in ("Read", "Grep", "Glob", "Edit", "Write", "NotebookEdit"):
        target = " ".join(str(ti.get(k, "")) for k in ("file_path", "path", "pattern", "notebook_path"))
        if LIFECYCLE_PATHS.search(target):
            return "touches the B200 operator credentials"
    return None


def main() -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        writes = classify(event)
    except Exception as exc:  # noqa: BLE001 - a broken payload must not silently pass a write
        writes, event = [], {}
        try:
            mode = gem.GemConfig.from_env().effective_mode()
        except Exception:  # noqa: BLE001 - an unreadable config must not turn a broken payload into a pass
            mode = gem.EnforcementMode.ENFORCE
        if mode == gem.EnforcementMode.ENFORCE and re.search(r"git\s+push|mcp__\w*github", raw):
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                     "permissionDecisionReason": f"Hook error, failing closed: {exc}"}}))
        return 0
    why = lifecycle_guard(event)
    if why:
        log_event({"ts": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "side": "hook",
                   "session": str(event.get("session_id") or "unknown"), "repo": _repo_slug(event.get("cwd")),
                   "tool": str(event.get("tool_name", "")), "target": "b200-controller", "decision": "BLOCK",
                   "mode": "ALWAYS", "rules": ["LIFECYCLE_OPERATOR"], "user_override": False})
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": (f"GEM: this {why}. Only the user operates the 4xB200 burst deployment "
                                         "(about $52/h). Ask them to run `gem heavy on` themselves; `gem heavy "
                                         "status` is fine to run.")}}))
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
            "attestation_path": store_attestation(gd.attestation) if gd.attestation else None,
            "detail_sha256": hashlib.sha256("|".join(gd.violations).encode()).hexdigest()[:16],
            "user_override": False,
        })
    out = respond(decisions, str(event.get("tool_name", "")))
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
