#!/usr/bin/env python3
"""Gem-Gate commit trailers + git-notes attestation verify (WU-09b). Stdlib only, runs under Termux.

Every commit an agent makes carries a `Gem-Gate: <attestation_id>` trailer that points to a
ForgeCore-signed gate attestation (ADR-007). A human or CI can verify any commit range.

  1. The PreToolUse hook (hooks/gem_pretool.py) stores every attestation it receives at
     $GEM_HOME/attestations/<attestation_id>.json (file 0600, dir 0700; GEM_HOME defaults to ~/.gem).
  2. The commit-msg hook written by `gemctl trailer install-hook` runs `gemctl trailer add "$1"`. That
     appends the newest PASS or WARN attestation (never BLOCK) for this repository and branch issued in
     the last 15 minutes. If there is none it adds nothing, prints one line to stderr and exits 0, or
     exits 1 and blocks the commit when GEM_TRAILER_REQUIRED=1.
  3. `gemctl trailer note [COMMIT]` copies the full attestation from the local store into a git note
     under refs/notes/gem-gate, so CI can verify without the local store. `git push` does NOT send
     notes; push them yourself, and fetch them before verifying elsewhere:

         git push origin refs/notes/gem-gate
         git fetch origin refs/notes/gem-gate:refs/notes/gem-gate      # CI side

     Notes do not follow `git commit --amend` or `git rebase` unless you also set
     `git config notes.rewriteRef refs/notes/gem-gate`; re-run `gemctl trailer note` after rewriting.
  4. `gemctl trailer verify RANGE` checks each commit: trailer present, note present, the note's
     attestation_id equals the trailer, the repository matches, the decision is not BLOCK, then asks
     ForgeCore's /api/v1/gate/verify. One status per commit:
     verified | missing_trailer | missing_note | mismatch | blocked | invalid_signature | forgecore_unavailable.

What a verified trailer proves: ForgeCore signed a non-BLOCK gate decision for this repository and
branch shortly before the commit was written. It does not bind the commit's content (git push claims
carry no payload hash), and one attestation can be copied onto other commits of the same repository.
"""

from __future__ import annotations

import datetime as _dt
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_reference_monitor as gem  # noqa: E402

TRAILER_KEY = "Gem-Gate"
NOTES_REF = "refs/notes/gem-gate"
DEFAULT_MAX_AGE_S = 900
CLOCK_SKEW_S = 120          # tolerated ForgeCore-ahead-of-us clock skew on issued_at
USABLE_DECISIONS = ("PASS", "WARN")
STATUSES = ("verified", "missing_trailer", "missing_note", "mismatch", "blocked", "invalid_signature",
            "forgecore_unavailable")
HARD_FAILURES = {"mismatch", "blocked", "invalid_signature"}   # exit 2; anything else unverified exits 1
HOOK_MARKER = "# gem-gate commit-msg hook (WU-09b)"
CHAINED_SUFFIX = ".gem-chained"

ATTESTATION_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_RFC3339_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:?\d{2})$")
_SLUG_RE = re.compile(r"[:/]([^/:\s]+/[^/:\s]+?)(?:\.git)?/*$")


class TrailerError(ValueError):
    """A trailer operation could not be done (git failed, nothing stored, hook conflict, bad input)."""


# --------------------------------------------------------------------------- helpers

def _git(args: List[str], cwd: Optional[str] = None, stdin: Optional[str] = None,
         check: bool = True) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(["git", *args], cwd=cwd or None, input=stdin, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise TrailerError(f"git {args[0]} failed: {exc}") from exc
    if check and r.returncode != 0:
        raise TrailerError(f"git {args[0]} failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r


def gem_home(override: Optional[str] = None) -> str:
    return os.path.expanduser(override or os.environ.get("GEM_HOME", "~/.gem"))


def attestations_dir(home: Optional[str] = None) -> str:
    return os.path.join(gem_home(home), "attestations")


def normalize_ref(ref: str) -> str:
    """Same normalization gemcore applies before ForgeCore sees a ref (refs/heads/x, origin/x -> x)."""
    return gem.StatefulGitHubOpsMonitor.normalize_branch(ref or "")


def parse_repo_slug(url: str) -> Optional[str]:
    """owner/name from an https, ssh or scp-style remote URL."""
    m = _SLUG_RE.search((url or "").strip())
    return m.group(1) if m else None


def repo_slug(cwd: Optional[str] = None) -> Optional[str]:
    """GEM_REPOSITORY, or else the `origin` remote URL parsed to owner/name."""
    if os.environ.get("GEM_REPOSITORY"):
        return os.environ["GEM_REPOSITORY"]
    r = _git(["config", "--get", "remote.origin.url"], cwd, check=False)
    return parse_repo_slug(r.stdout) if r.returncode == 0 else None


def _known_repo(repo: Any) -> bool:
    """The hook's placeholder unknown/unknown would let unrelated repositories share attestations."""
    r = str(repo or "").strip().lower()
    return bool(r) and r != "unknown/unknown"


def _same_repo(a: Any, b: Any) -> bool:
    """GitHub owner/name is case-insensitive. An unknown repository never matches anything."""
    return _known_repo(a) and str(a).strip().lower() == str(b or "").strip().lower()


def current_branch(cwd: Optional[str] = None) -> Optional[str]:
    """`git rev-parse --abbrev-ref HEAD`; symbolic-ref covers an unborn branch. None when detached."""
    for argv in (["rev-parse", "--abbrev-ref", "HEAD"], ["symbolic-ref", "--short", "HEAD"]):
        r = _git(argv, cwd, check=False)
        name = r.stdout.strip()
        if r.returncode == 0 and name and name != "HEAD":
            return name
    return None


def parse_rfc3339(value: Any) -> Optional[float]:
    """RFC3339 -> epoch seconds. Accepts Z or offsets and any fraction length (ForgeCore may emit nanoseconds)."""
    m = _RFC3339_RE.match(str(value or "").strip())
    if not m:
        return None
    date, clock, frac, tz = m.groups()
    tz = "+00:00" if tz in ("Z", "z") else (tz if ":" in tz else f"{tz[:3]}:{tz[3:]}")
    try:
        return _dt.datetime.fromisoformat(f"{date}T{clock}.{((frac or '') + '000000')[:6]}{tz}").timestamp()
    except ValueError:
        return None


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _check_id(att_id: str) -> str:
    att_id = (att_id or "").strip()
    if not ATTESTATION_ID_RE.match(att_id):   # also keeps trailer text from becoming a store path
        raise TrailerError(f"not an attestation id (want 32 hex characters): {att_id[:80]!r}")
    return att_id


def _resolve_commit(commit: str, cwd: Optional[str]) -> str:
    if not commit or commit.startswith("-"):
        raise TrailerError(f"bad commit: {commit!r}")
    r = _git(["rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"], cwd, check=False)
    if r.returncode != 0 or not r.stdout.strip():
        raise TrailerError(f"no such commit: {commit}")
    return r.stdout.strip()


# --------------------------------------------------------------------------- local store

def stored_attestation(att_id: str, home: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = os.path.join(attestations_dir(home), _check_id(att_id) + ".json")
    try:
        with open(path, encoding="utf-8") as fh:
            att = json.load(fh)
    except (OSError, ValueError):
        return None
    return att if isinstance(att, dict) and att.get("attestation_id") == att_id else None


def latest_attestation(repo: str, ref: str, max_age_s: float = DEFAULT_MAX_AGE_S, *,
                       home: Optional[str] = None, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Newest stored PASS or WARN attestation (never BLOCK) for this repository and target ref,
    issued less than max_age_s ago. Unparseable, unsigned or misnamed store entries are skipped."""
    want = normalize_ref(ref)
    if not want or want == "HEAD" or not _known_repo(repo):
        return None
    now = time.time() if now is None else now
    best: Optional[Tuple[Tuple[float, str], Dict[str, Any]]] = None
    for path in glob.glob(os.path.join(attestations_dir(home), "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                att = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(att, dict):
            continue
        att_id = str(att.get("attestation_id") or "")
        if not ATTESTATION_ID_RE.match(att_id) or os.path.basename(path) != att_id + ".json":
            continue
        if att.get("decision") not in USABLE_DECISIONS or not att.get("signature"):
            continue
        if not _same_repo(att.get("repository"), repo) or normalize_ref(str(att.get("target_ref") or "")) != want:
            continue
        issued = parse_rfc3339(att.get("issued_at"))
        if issued is None or not (-CLOCK_SKEW_S <= now - issued <= max_age_s):
            continue
        key = (issued, att_id)
        if best is None or key > best[0]:
            best = (key, att)
    return best[1] if best else None


# --------------------------------------------------------------------------- commit-msg hook

def add_trailer(msg_path: str, *, cwd: Optional[str] = None, required: Optional[bool] = None,
                home: Optional[str] = None, max_age_s: float = DEFAULT_MAX_AGE_S) -> int:
    """Append `Gem-Gate: <id>` to a commit message file. Returns the hook's exit code.

    Idempotent: an existing Gem-Gate trailer is replaced, never duplicated. With no fresh attestation it
    adds nothing, prints one line to stderr and returns 0 (1 when GEM_TRAILER_REQUIRED=1)."""
    if required is None:
        required = os.environ.get("GEM_TRAILER_REQUIRED", "").strip() == "1"

    def skip(why: str) -> int:
        tail = " GEM_TRAILER_REQUIRED=1, so the commit is blocked." if required else ""
        sys.stderr.write(f"gem-gate: no {TRAILER_KEY} trailer: {why}.{tail}\n".replace("\r", " "))
        return 1 if required else 0

    try:
        repo = repo_slug(cwd)
        if not repo or not _known_repo(repo):
            return skip("repository unknown (set GEM_REPOSITORY or a GitHub origin remote)")
        branch = current_branch(cwd)
        if not branch:
            return skip("detached HEAD has no branch to match")
        att = latest_attestation(repo, branch, max_age_s, home=home)
        if att is None:
            return skip(f"no PASS/WARN attestation for {repo} {branch} in the last {int(max_age_s)}s "
                        "(gate a push to this branch first)")
        r = _git(["interpret-trailers", "--in-place", "--if-exists", "replace", "--if-missing", "add",
                  "--trailer", f"{TRAILER_KEY}: {att['attestation_id']}", os.path.abspath(msg_path)], cwd, check=False)
        if r.returncode != 0:
            return skip("git interpret-trailers failed: " + " ".join(r.stderr.split())[:200])
        return 0
    except Exception as exc:  # noqa: BLE001 - a hook bug must not block commits unless the trailer is required
        return skip(f"error: {' '.join(str(exc).split())[:200]}")


# --------------------------------------------------------------------------- notes

def commit_trailers(commit: str, cwd: Optional[str] = None) -> List[str]:
    """Gem-Gate trailer values of one commit (parsed by git, key matched case-insensitively)."""
    sha = _resolve_commit(commit, cwd)
    r = _git(["log", "-1", "--no-show-signature", f"--format=%(trailers:key={TRAILER_KEY},valueonly,separator=%x1f)",
              sha, "--"], cwd)
    return [v.strip() for v in r.stdout.strip("\n").split("\x1f") if v.strip()]


def read_note(commit: str, cwd: Optional[str] = None) -> Optional[str]:
    r = _git(["notes", "--ref", NOTES_REF, "show", _resolve_commit(commit, cwd)], cwd, check=False)
    return r.stdout if r.returncode == 0 else None


def attach_note(commit: str, attestation: Dict[str, Any], *, cwd: Optional[str] = None) -> str:
    """Store the full attestation JSON as a note under refs/notes/gem-gate (replacing any earlier one).
    Returns the commit sha. Publish with: git push origin refs/notes/gem-gate"""
    if not isinstance(attestation, dict):
        raise TrailerError("attestation must be a JSON object")
    _check_id(str(attestation.get("attestation_id") or ""))
    sha = _resolve_commit(commit, cwd)
    _git(["notes", "--ref", NOTES_REF, "add", "-f", "-F", "-", sha], cwd, stdin=_canonical(attestation) + "\n")
    return sha


def attach_note_from_store(commit: str = "HEAD", *, cwd: Optional[str] = None,
                           home: Optional[str] = None) -> Tuple[str, str]:
    """Attach the note for COMMIT's own Gem-Gate trailer, taking the attestation from the local store."""
    values = sorted(set(commit_trailers(commit, cwd)))
    if not values:
        raise TrailerError(f"{commit} has no {TRAILER_KEY} trailer")
    if len(values) > 1:
        raise TrailerError(f"{commit} has {len(values)} different {TRAILER_KEY} trailers")
    att_id = _check_id(values[0])
    att = stored_attestation(att_id, home)
    if att is None:
        raise TrailerError(f"attestation {att_id} is not in {attestations_dir(home)}")
    return attach_note(commit, att, cwd=cwd), att_id


# --------------------------------------------------------------------------- verify

def _range_commits(rev_range: str, cwd: Optional[str]) -> List[Tuple[str, List[str]]]:
    if not rev_range or rev_range.startswith("-"):
        raise TrailerError(f"bad revision range: {rev_range!r}")
    r = _git(["log", "--reverse", "--no-show-signature", "--no-color",
              f"--format=%H%x1f%(trailers:key={TRAILER_KEY},valueonly,separator=%x1f)%x1e",
              "--end-of-options", rev_range, "--"], cwd)
    out = []
    for record in r.stdout.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, *values = record.split("\x1f")
        out.append((sha.strip(), [v.strip() for v in values if v.strip()]))
    return out


def verify_range(rev_range: str, attestor: Optional["gem.ForgeCoreAttestor"], *, cwd: Optional[str] = None,
                 repository: Optional[str] = None) -> Dict[str, Any]:
    """Verify every commit in a git revision range (e.g. origin/main..HEAD), oldest first.

    attestor is a gemcore ForgeCoreAttestor (None: ForgeCore not configured, so nothing verifies).
    Notes must be present locally: git fetch origin refs/notes/gem-gate:refs/notes/gem-gate"""
    repository = repository or repo_slug(cwd)
    if not repository or not _known_repo(repository):
        raise TrailerError("cannot tell which repository this is; set GEM_REPOSITORY=owner/name")
    cache: Dict[str, Dict[str, Any]] = {}
    down: List[str] = []   # set after a transport failure, so a dead ForgeCore costs one timeout, not one per commit
    commits = [_verify_commit(sha, values, attestor, repository, cwd, cache, down)
               for sha, values in _range_commits(rev_range, cwd)]
    summary = {s: sum(c["status"] == s for c in commits) for s in STATUSES}
    return {"range": rev_range, "repository": repository, "notes_ref": NOTES_REF,
            "ok": all(c["status"] == "verified" for c in commits), "summary": summary, "commits": commits}


def _verify_commit(sha: str, values: List[str], attestor: Any, repository: str, cwd: Optional[str],
                   cache: Dict[str, Dict[str, Any]], down: List[str]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"commit": sha, "status": "", "attestation_id": None, "reason": ""}

    def done(status: str, reason: str = "") -> Dict[str, Any]:
        entry.update(status=status, reason=reason)
        return entry

    distinct = sorted(set(values))
    if not distinct:
        return done("missing_trailer", f"no {TRAILER_KEY} trailer")
    if len(distinct) > 1:
        return done("mismatch", f"{len(distinct)} different {TRAILER_KEY} trailers")
    trailer = distinct[0]
    entry["attestation_id"] = trailer
    if not ATTESTATION_ID_RE.match(trailer):
        return done("mismatch", "trailer is not a 32-hex attestation id")
    raw = read_note(sha, cwd)
    if raw is None:
        return done("missing_note", f"no note under {NOTES_REF} (git fetch origin {NOTES_REF}:{NOTES_REF})")
    try:
        att = json.loads(raw)
    except ValueError:
        att = None
    if not isinstance(att, dict):
        return done("mismatch", "note is not an attestation JSON object")
    entry.update(decision=att.get("decision"), target_ref=att.get("target_ref"), issued_at=att.get("issued_at"))
    if att.get("attestation_id") != trailer:
        return done("mismatch", f"note attestation_id {str(att.get('attestation_id'))[:40]!r} != trailer")
    if not _same_repo(att.get("repository"), repository):
        return done("mismatch", f"attestation is for {str(att.get('repository'))[:100]!r}, not {repository!r}")
    if att.get("decision") == "BLOCK":
        return done("blocked", "attestation decision is BLOCK")
    if att.get("decision") not in USABLE_DECISIONS:
        return done("mismatch", f"unknown decision {str(att.get('decision'))[:20]!r}")
    if attestor is None:
        return done("forgecore_unavailable",
                    "ForgeCore not configured (AUTODEV_URL or GEM_FORGECORE_URL, plus AUTODEV_API_BEARER_TOKEN)")
    if down:
        return done("forgecore_unavailable", down[0])
    key = _canonical(att)
    if key not in cache:
        try:
            result = attestor.verify({"attestation": att})
        except gem.ForgeCoreUnavailable as exc:
            if not isinstance(exc.__cause__, urllib.error.HTTPError):
                down.append(str(exc))
            return done("forgecore_unavailable", str(exc)[:300])
        if not isinstance(result, dict):
            return done("forgecore_unavailable", "ForgeCore /verify returned a non-object")
        cache[key] = result
    result = cache[key]
    entry["recorded"] = bool(result.get("recorded"))
    if result.get("valid") is True:
        return done("verified")
    return done("invalid_signature", "ForgeCore /verify: valid=false (attestation altered or not ForgeCore-signed)")


def exit_code(report: Dict[str, Any]) -> int:
    """0 all verified; 2 any blocked, invalid or mismatched; 1 otherwise (missing or ForgeCore unavailable)."""
    statuses = {c["status"] for c in report.get("commits", [])}
    if statuses & HARD_FAILURES:
        return 2
    return 1 if statuses - {"verified"} else 0


# --------------------------------------------------------------------------- hook installer

def _hook_script(gemctl_path: str, python: str) -> str:
    sh = shutil.which("sh") or "/bin/sh"   # Termux has no /bin/sh outside termux-exec
    q = shlex.quote
    return f"""#!{sh}
{HOOK_MARKER}, written by `gemctl trailer install-hook`.
# Appends "{TRAILER_KEY}: <attestation_id>" to the message (see gem_trailers.py).
# GEM_TRAILER_REQUIRED=1 blocks commits that get no trailer. A commit-msg hook that was here
# before is kept as commit-msg{CHAINED_SUFFIX} and runs first.
# Notes are not pushed by `git push`: git push origin {NOTES_REF}
chained="$(dirname "$0")/commit-msg{CHAINED_SUFFIX}"
if [ -x "$chained" ]; then
    "$chained" "$@" || exit $?
fi
gemctl={q(gemctl_path)}
if [ ! -f "$gemctl" ]; then
    echo "gem-gate: $gemctl not found, no {TRAILER_KEY} trailer added" >&2
    [ "${{GEM_TRAILER_REQUIRED:-0}}" = "1" ] && exit 1
    exit 0
fi
exec {q(python)} -I "$gemctl" trailer add "$1"
"""


def install_hook(repo: str = ".", *, gemctl_path: str, python: Optional[str] = None) -> Dict[str, Any]:
    """Write the commit-msg hook into .git/hooks (or core.hooksPath). An existing gem hook is updated;
    a foreign one is renamed to commit-msg.gem-chained and still runs first. If that name is taken too,
    refuse rather than overwrite anything."""
    top = _git(["rev-parse", "--show-toplevel"], os.path.abspath(repo)).stdout.strip()
    hooks_dir = _git(["rev-parse", "--git-path", "hooks"], top).stdout.strip()   # honors core.hooksPath
    hooks_dir = os.path.normpath(os.path.join(top, os.path.expanduser(hooks_dir)))
    os.makedirs(hooks_dir, exist_ok=True)
    hook = os.path.join(hooks_dir, "commit-msg")
    chained = hook + CHAINED_SUFFIX
    action = "installed"
    if os.path.lexists(hook):
        try:
            with open(hook, encoding="utf-8", errors="replace") as fh:
                ours = HOOK_MARKER in fh.read()
        except OSError:
            ours = False
        if ours:
            action = "updated"
        elif os.path.lexists(chained):
            raise TrailerError(f"{hook} is not a gem-gate hook and {chained} already exists; refusing to "
                               "overwrite either. Merge them by hand, then re-run install-hook.")
        else:
            os.replace(hook, chained)
            action = "chained"
    fd, tmp = tempfile.mkstemp(prefix=".commit-msg-", dir=hooks_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_hook_script(os.path.abspath(gemctl_path), python or sys.executable))
        os.chmod(tmp, 0o755)
        os.replace(tmp, hook)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return {"hook": hook, "action": action, "chained": chained if os.path.lexists(chained) else None,
            "next": f"after committing: gemctl trailer note && git push origin {NOTES_REF}"}
