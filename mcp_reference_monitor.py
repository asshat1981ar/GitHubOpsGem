#!/usr/bin/env python3
"""
GitHubOpsGem v5.4 - Deterministic MCP Reference Monitor, DeepSeek protocol sanitizer,
aTRIZ-SWE scoring helpers and LLM technical-debt sensor.

v5.1 changes over v5 (each closes an audit probe, see tests/test_monitor.py):
  * One shared, header-aware unified-diff walker (fixes '++' line drift)       P01
  * Ref-normalised protected-branch lock (refs/heads/main, origin/main)        P02
  * Orphan </think> stripping + streaming ThinkStreamFilter                    P03
  * XML tool-call repair is allowlisted; privileged calls are rejected         P04
  * ABI receipts require recorded search results and whole-word matches      P05
  * Wider FFI extraction: unsafe/C-unwind/no_mangle/actual/@_cdecl            P06
  * Workflow scanner: quoted + reusable `uses:`, broad CWE-94 sinks,
    pull_request_target pwn-request detection                                  P07
  * CI windowing keeps the FIRST (root-cause) window + marks elisions          P08/P19
  * Loop breaker counts consecutive identical FAILURES and resets on success   P09
  * Current Claude Code tool names (Read/Grep/Glob/Edit/Write)                 P10
  * DUR uses a curated deprecated-API list; AUP flagged as unmeasured          P11
  * Gate consumes tech-debt reports, payload secret scan, injection taint      P12/P14/P15
  * Phase guard: review/merge actions require ingested evidence               P13
  * More secret shapes (Anthropic, OpenAI, Slack, Google, Hugging Face)        P16
  * Ideality is finite and JSON-safe                                           P17
  * Broader (still best-effort) injection heuristics                           P18
  * WARN | ENFORCE enforcement modes with optional date flip
  * Code-rendered, HMAC-signed <PreFlightGate> receipts
  * All deployment identifiers come from environment, not code

v5.2 (unified spec PDF / Linear ledger, 2026-11-07):
  * Strict fast-integration policy: untested or failing-test merges block (configurable: strict|smell)
  * House-policy calls (`claude --print|-p`, `os.system`, shell=True) counted as policy_hits, not DUR
  * Silent JSON / promise catches added to PSC smells
  * Metric docstring corrected against arXiv:2606.14796 (AUP and DUR are independent)

v5.3 (ADR-007 in asshat1981ar/autodev):
  * ForgeCoreAttestor: gate claims go to ForgeCore, which derives the decision and signs it with a
    server-held key. Unreachable ForgeCore fails closed in ENFORCE; local HMAC is a dev fallback only.

v5.4 (WU-04 gemctl, WU-08 hooks):
  * Shell pushes (`git_push`, `git_force_push`) join the branch-write, write and taint tool sets,
    matching ForgeCore's vocabulary. Found by the hook tests: a bare `git push origin main` passed.
  * evaluate_write(extra_violations=...) so hook-detected issues (force push, --all) are part of the
    claim ForgeCore signs, not added after the signature.

fix/cwe94-precision:
  * CWE-94_WORKFLOW_INJECTION only in execution sinks (`run:`, actions/github-script `script:`) and only for
    attacker-controllable contexts (UntrustedContextPolicy deny/allow lists). It used to fire on any
    `${{ github.event.* }}` anywhere, e.g. a `concurrency:` group or the `env:` binding it recommends.
  * Review of PR #2: multi-line values assembled before scanning (folded expressions), YAML escapes, aliases,
    flow collections (parsed, also over several lines), block-scalar content indentation, quote-aware
    `${{ }}` extraction, boolean results skipped, CodeQL-modelled code inputs of other actions, env and matrix
    taint by worklist; patch-only ambiguity fails closed (unseen env bindings and anchors, script-like hunk
    tops); a post-image is used only if it is the patch's target blob.
"""

from __future__ import annotations

import bisect
import datetime as _dt
import hashlib
import hmac
import html
import json
import math
import os
import re
import unicodedata
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Set, Tuple

__version__ = "5.4.0"


# --------------------------------------------------------------------------- config

class EnforcementMode(str, Enum):
    WARN = "WARN"        # violations reported, call allowed (shadow mode)
    ENFORCE = "ENFORCE"  # violations block


@dataclass(frozen=True)
class GemConfig:
    deployment_id: str = "accounts/CHANGE_ME/deployments/CHANGE_ME"
    base_model: str = "deepseek-v4p1-flash-1017"
    max_context_tokens: int = 131072
    input_budget_tokens: int = 96000
    output_budget_tokens: int = 16384
    mode: EnforcementMode = EnforcementMode.ENFORCE
    enforce_after: Optional[_dt.date] = None  # WARN until this date, then ENFORCE

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "GemConfig":
        e = dict(os.environ if env is None else env)
        after = e.get("GEM_ENFORCE_AFTER")
        return cls(
            deployment_id=e.get("GEM_DEPLOYMENT_ID", cls.deployment_id),
            base_model=e.get("GEM_BASE_MODEL", cls.base_model),
            max_context_tokens=int(e.get("GEM_MAX_CONTEXT_TOKENS", cls.max_context_tokens)),
            input_budget_tokens=int(e.get("GEM_INPUT_BUDGET_TOKENS", cls.input_budget_tokens)),
            output_budget_tokens=int(e.get("GEM_OUTPUT_BUDGET_TOKENS", cls.output_budget_tokens)),
            mode=EnforcementMode(e.get("GEM_ENFORCEMENT", "ENFORCE").upper()),
            enforce_after=_dt.date.fromisoformat(after) if after else None,
        )

    def effective_mode(self, today: Optional[_dt.date] = None) -> EnforcementMode:
        today = today or _dt.date.today()
        if self.enforce_after is not None:
            return EnforcementMode.ENFORCE if today >= self.enforce_after else EnforcementMode.WARN
        return self.mode


# --------------------------------------------------------------------------- enums

class TrustLevel(str, Enum):
    OWNER = "OWNER"
    MEMBER = "MEMBER"
    COLLABORATOR = "COLLABORATOR"
    CONTRIBUTOR = "CONTRIBUTOR"
    FIRST_TIME_CONTRIBUTOR = "FIRST_TIME_CONTRIBUTOR"
    FIRST_TIMER = "FIRST_TIMER"
    MANNEQUIN = "MANNEQUIN"
    NONE = "NONE"

    @classmethod
    def from_author_association(cls, value: Optional[str]) -> "TrustLevel":
        """Map GitHub's `author_association` field; unknown values fail closed."""
        try:
            return cls(str(value or "NONE").upper())
        except ValueError:
            return cls.NONE


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"


class WorkflowPhase(str, Enum):
    DISCOVER = "DISCOVER"
    INGEST = "INGEST"
    GRAPH = "GRAPH"
    ANALYZE = "ANALYZE"
    GATE = "GATE"
    COMMIT = "COMMIT"
    RECOVER = "RECOVER"


class ThinkingHat(str, Enum):
    WHITE = "WHITE"
    RED = "RED"
    BLACK = "BLACK"
    YELLOW = "YELLOW"
    GREEN = "GREEN"
    BLUE = "BLUE"


class ScamperOperator(str, Enum):
    SUBSTITUTE = "T_S"
    COMBINE = "T_C"
    ADAPT = "T_A"
    MODIFY = "T_M"
    PUT_TO_ANOTHER_USE = "T_P"
    ELIMINATE = "T_E"
    REVERSE = "T_R"


class TechnicalDebtCategory(str, Enum):
    CODE_DEBT = "CODE_DEBT"
    DESIGN_DEBT = "DESIGN_DEBT"
    ARCHITECTURE_DEBT = "ARCHITECTURE_DEBT"
    TEST_DEBT = "TEST_DEBT"
    DOCUMENTATION_DEBT = "DOCUMENTATION_DEBT"
    FAST_INTEGRATION_DEBT = "FAST_INTEGRATION_DEBT"
    PROMPT_DEBT = "PROMPT_DEBT"
    GOVERNANCE_DEBT = "GOVERNANCE_DEBT"
    PROVENANCE_DEBT = "PROVENANCE_DEBT"
    DATA_DEBT = "DATA_DEBT"
    ETHICAL_DEBT = "ETHICAL_DEBT"


# --------------------------------------------------------------------------- diff walking

HUNK_HEADER_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")


@dataclass(frozen=True)
class PatchLine:
    kind: str                 # "add" | "del" | "ctx"
    new_line: Optional[int]   # right-side line number (None for deletions)
    old_line: Optional[int]   # left-side line number (None for additions)
    content: str              # line text without the +/-/space prefix


def iter_patch_lines(patch_text: str) -> Iterator[PatchLine]:
    """Header-aware unified-diff walker.

    Inside a hunk, lines are classified by their first character and the hunk's declared
    counts, so an added line whose content starts with '++' or '--' is never mistaken for a
    '+++ b/file' / '--- a/file' header (the v5 off-by-one, probe P01).
    """
    old_no = new_no = 0
    old_left = new_left = 0
    in_hunk = False
    # Split on LF only: str.splitlines() also breaks on \x1c-\x1e, \x85, \u2028/9, \v, \f, which let an
    # attacker push the rest of an added line into a fake context line the scanners skip.
    for raw in (line[:-1] if line.endswith("\r") else line for line in patch_text.split("\n")):
        m = HUNK_HEADER_RE.match(raw)
        if m:
            old_no, new_no = int(m.group(1)), int(m.group(3))
            old_left = int(m.group(2)) if m.group(2) is not None else 1
            new_left = int(m.group(4)) if m.group(4) is not None else 1
            in_hunk = True
            continue
        if not in_hunk or (old_left <= 0 and new_left <= 0):
            in_hunk = False
            continue  # file headers, "diff --git", index lines, trailing junk
        if raw.startswith("\\"):
            continue  # "\ No newline at end of file"
        tag, body = (raw[:1], raw[1:]) if raw else (" ", "")
        if tag == "+":
            yield PatchLine("add", new_no, None, body)
            new_no += 1
            new_left -= 1
        elif tag == "-":
            yield PatchLine("del", None, old_no, body)
            old_no += 1
            old_left -= 1
        else:  # context (GitHub sometimes strips the leading space of blank lines)
            yield PatchLine("ctx", new_no, old_no, body if tag == " " else raw)
            new_no += 1
            old_no += 1
            new_left -= 1
            old_left -= 1


def added_lines(patch_text: str) -> List[PatchLine]:
    return [p for p in iter_patch_lines(patch_text) if p.kind == "add"]


# --------------------------------------------------------------------------- findings / review plan

@dataclass(frozen=True)
class InlineFinding:
    path: str
    line: int
    severity: Severity
    category: str
    message: str
    suggestion: Optional[str] = None

    def format_markdown(self) -> str:
        body = f"**[{self.severity.value} | {self.category}]** {self.message}"
        if self.suggestion:
            body += f"\n```suggestion\n{self.suggestion}\n```"
        return body


@dataclass
class ReviewSubmissionPlan:
    valid_inline_comments: List[Dict[str, Any]] = field(default_factory=list)
    fallback_body_findings: List[InlineFinding] = field(default_factory=list)

    def format_review_body(self, summary_header: str) -> str:
        parts = [summary_header]
        if self.fallback_body_findings:
            parts.append("\n### Out-of-Hunk / File-Level Findings")
            for f in self.fallback_body_findings:
                parts.append(f"- `{f.path}:{f.line}` - {f.format_markdown()}")
        return "\n".join(parts)


class DiffHunkValidator:
    """Validates right-side diff hunk line numbers to prevent HTTP 422 review errors."""

    HUNK_HEADER_RE = HUNK_HEADER_RE

    @classmethod
    def parse_valid_right_lines(cls, patch_text: str) -> Set[int]:
        return {p.new_line for p in iter_patch_lines(patch_text) if p.new_line is not None}

    @classmethod
    def partition_findings(cls, findings: List[InlineFinding], file_patches: Dict[str, str]) -> ReviewSubmissionPlan:
        plan = ReviewSubmissionPlan()
        valid_map = {path: cls.parse_valid_right_lines(patch) for path, patch in file_patches.items()}
        for finding in findings:
            if finding.path in valid_map and finding.line in valid_map[finding.path]:
                plan.valid_inline_comments.append({
                    "path": finding.path, "line": finding.line, "side": "RIGHT", "body": finding.format_markdown(),
                })
            else:
                plan.fallback_body_findings.append(finding)
        return plan


# --------------------------------------------------------------------------- workflow expression injection (CWE-94)

class UntrustedContextPolicy:
    """Which `${{ }}` contexts can carry attacker-chosen text.

    GitHub pastes the text of a `${{ }}` expression into the step before the step runs. That is code
    injection (CWE-94) only when the text lands in code that is executed (WorkflowInjectionScanner decides
    that) AND an attacker can choose the value (this class decides that). An expression is unsafe if ANY
    context it reads is unsafe, whatever operators or functions combine them (`a || b`, `format()`,
    `contains()`, `toJSON()`).

    Sources for DENY:
      * CodeQL's actions model of untrusted event properties: github/codeql
        actions/ql/lib/ext/config/untrusted_event_properties.yml, plus `github.head_ref` from
        actions/ql/lib/codeql/actions/dataflow/FlowSources.qll (GitHubCtxSource).
      * GitHub Docs, "Script injections" (docs.github.com/en/actions/concepts/security/script-injections), and
        the GitHub blog "How to secure GitHub Actions workflows: 4 tips to handle untrusted input".
      * zizmor's template-injection audit (docs.zizmor.sh/audits/#template-injection), which also reports
        `inputs.*` and non-static `env.*` expanded in code, and step outputs at informational severity.
        Here `inputs.*`, `steps.*.outputs.*` and `needs.*.outputs.*` are reported at full severity: they can
        carry arbitrary text from an untrusted caller or an earlier step.
    A context that is an ancestor of a DENY entry is unsafe too, because the object contains that field
    (`toJSON(github.event.pull_request)`, `toJSON(github)`): CodeQL models these as JSON sources.

    Contexts on neither list are not reported. Only attacker-controllable data is injection; numbers, SHAs,
    ids and names that GitHub or the repository's writers choose are not.
    """

    DENY: Tuple[str, ...] = (
        # Branch names the PR author chooses. Only the head branch: see ALLOW for github.ref and friends.
        "github.head_ref",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.pull_request.head.repo.default_branch",
        "github.event.workflow_run.head_branch",
        "github.event.workflow_run.pull_requests.*.head.ref",
        "github.event.merge_group.head_ref",
        "github.event.changes.head.ref.from",
        # Titles and free text written by whoever opens the issue, PR, comment, review, discussion or wiki page.
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.repo.description",
        "github.event.pull_request.head.repo.homepage",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.pages.*.page_name",
        "github.event.pages.*.title",
        "github.event.changes.title.from",
        "github.event.changes.body.from",
        "github.event.workflow_run.display_title",
        "github.event.workflow_run.head_repository.description",
        # Commit metadata: anyone can set the message and the author/committer name and e-mail of a commit.
        "github.event.commits.*.message",
        "github.event.commits.*.author.email",
        "github.event.commits.*.author.name",
        "github.event.commits.*.committer.email",
        "github.event.commits.*.committer.name",
        "github.event.head_commit.message",
        "github.event.head_commit.author.email",
        "github.event.head_commit.author.name",
        "github.event.head_commit.committer.email",
        "github.event.head_commit.committer.name",
        "github.event.workflow_run.head_commit.message",
        "github.event.workflow_run.head_commit.author.*",
        "github.event.workflow_run.head_commit.committer.*",
        "github.event.merge_group.committer.email",
        "github.event.merge_group.committer.name",
        # File paths taken from the triggering repository.
        "github.event.workflow.path",
        "github.event.workflow_run.path",
        "github.event.workflow_run.referenced_workflows.*.path",
        # workflow_dispatch / workflow_call inputs: free text whenever the caller is untrusted.
        "inputs.*",
        "github.event.inputs.*",
        # Values produced at run time; they can carry untrusted data from an earlier step or job.
        "steps.*.outputs.*",
        "needs.*.outputs.*",
    )

    ALLOW: Tuple[str, ...] = (
        # Numbers, SHAs and run identifiers.
        "github.event.pull_request.number",
        "github.event.issue.number",
        "github.event.number",
        "github.sha",
        "github.event.pull_request.head.sha",
        "github.event.pull_request.base.sha",
        "github.run_id",
        "github.run_number",
        "github.run_attempt",
        # Names GitHub or the repository's writers set.
        "github.repository",
        "github.repository_owner",
        "github.workflow",
        "github.job",
        "github.event_name",
        "github.ref_type",
        # Deliberate choice: github.ref, github.base_ref and github.ref_name are treated as safe. An attacker
        # could influence them only through branch names, and on pull_request they name the PR merge ref
        # (refs/pull/<n>/merge) and the base branch, which only the base repository's writers create. On push
        # and the other events they name a ref that someone with write access pushed. The only branch name a
        # PR author chooses is the head branch, and github.head_ref / pull_request.head.ref are in DENY.
        "github.ref",
        "github.base_ref",
        "github.ref_name",
        # runner.* is set by the runner. matrix.* is assumed static (a matrix built with fromJSON() from
        # untrusted data would not be; that is not evaluated here). secrets.* are not attacker-controlled;
        # exposing a secret in a script is a different issue, handled by the secret rules, not CWE-94.
        "runner.*",
        "matrix.*",
        "secrets.*",
    )

    _DENY = tuple(tuple(p.split(".")) for p in DENY)
    _ALLOW = tuple(tuple(p.split(".")) for p in ALLOW)
    # One pass over the expression: string literals (an unterminated one runs to the end), identifiers,
    # numbers, two-character operators, then any single character.
    _TOKEN_RE = re.compile(r"\s+|'(?:[^']|'')*'?|[A-Za-z_][A-Za-z0-9_-]*|[0-9][0-9A-Za-z_.]*|==|!=|<=|>=|&&|\|\||.", re.S)
    _IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
    _BOOLEAN_FUNCTIONS = frozenset({"contains", "startswith", "endswith", "success", "failure", "always", "cancelled"})
    _COMPARISONS = frozenset({"==", "!=", "<", ">", "<=", ">="})
    _MAX_BOOLEAN_TOKENS = 2000  # longer expressions are not analysed as boolean (they are scanned in full)

    @staticmethod
    def _compatible(chain: Tuple[str, ...], pattern: Tuple[str, ...]) -> bool:
        # Compared over the shorter length: equal, a field below the pattern, or an object above it.
        return all(c == p or "*" in (c, p) for c, p in zip(chain, pattern))

    @classmethod
    def _tokens(cls, expr: str) -> List[str]:
        return [t for t in cls._TOKEN_RE.findall(expr) if not t.isspace()]

    @staticmethod
    def _closers(toks: List[str]) -> Dict[int, int]:
        """Index of each '(' / '[' -> index of its matching closer."""
        match: Dict[int, int] = {}
        stack: List[int] = []
        for i, t in enumerate(toks):
            if t in ("(", "["):
                stack.append(i)
            elif t in (")", "]") and stack:
                match[stack.pop()] = i
        return match

    @classmethod
    def contexts(cls, expr: str) -> List[str]:
        """Context paths an expression reads, e.g. `github.event.commits.*.message` (as written; contexts
        are case-insensitive, so compare them lower-cased).

        `x['key']` becomes `x.key`; `x[0]` and `x[<expr>]` become `x.*` (the inner expression is read too).
        String literals and function names are not contexts. Linear in the length of the expression.
        """
        toks = cls._tokens(expr)
        closer = cls._closers(toks)
        found: Dict[str, str] = {}
        for i, t in enumerate(toks):
            if not cls._IDENT_RE.match(t) or (i and toks[i - 1] == "."):
                continue
            parts, j = [t], i + 1
            while j < len(toks):
                if toks[j] == "." and j + 1 < len(toks) and (toks[j + 1] == "*" or cls._IDENT_RE.match(toks[j + 1])):
                    parts.append(toks[j + 1])
                    j += 2
                elif toks[j] == "[" and j in closer:
                    inner = toks[j + 1:closer[j]]
                    key = inner[0][1:-1].replace("''", "'") if (
                        len(inner) == 1 and len(inner[0]) >= 2 and inner[0][0] == inner[0][-1] == "'") else ""
                    parts.append(key if cls._IDENT_RE.match(key) else "*")
                    j = closer[j] + 1
                else:
                    break
            if j < len(toks) and toks[j] == "(":
                continue  # function call: toJSON(...), format(...)
            ctx = ".".join(parts)
            found.setdefault(ctx.lower(), ctx)
        return list(found.values())

    @classmethod
    def is_boolean(cls, expr: str) -> bool:
        """True when the expression always yields true or false (a comparison, `!x`, contains() and the other
        boolean functions), so its expansion cannot carry attacker text. `a || b` and `a && b` yield one of
        their operands, so they are boolean only when every operand is."""
        toks = cls._tokens(expr)
        return len(toks) <= cls._MAX_BOOLEAN_TOKENS and cls._boolean_tokens(toks)

    @classmethod
    def _boolean_tokens(cls, toks: List[str]) -> bool:
        closer = cls._closers(toks)
        while toks and toks[0] == "(" and closer.get(0) == len(toks) - 1:
            toks = toks[1:-1]
            closer = cls._closers(toks)
        if not toks:
            return False
        depth, top = 0, []  # (index, token) at nesting depth 0
        for i, t in enumerate(toks):
            if t in ("(", "["):
                depth += 1
            elif t in (")", "]"):
                depth -= 1
            elif depth == 0:
                top.append((i, t))
        for op in ("||", "&&"):
            cuts = [i for i, t in top if t == op]
            if cuts:
                bounds = [-1, *cuts, len(toks)]
                return all(cls._boolean_tokens(toks[a + 1:b]) for a, b in zip(bounds, bounds[1:]))
        if toks[0] == "!" or any(t in cls._COMPARISONS for _, t in top):
            return True
        if len(toks) >= 3 and toks[0].lower() in cls._BOOLEAN_FUNCTIONS and toks[1] == "(" \
                and closer.get(1) == len(toks) - 1:
            return True
        return len(toks) == 1 and toks[0].lower() in ("true", "false")

    @classmethod
    def classify(cls, context: str) -> str:
        """'unsafe' (attacker-controllable), 'safe' (on ALLOW) or 'unlisted'. DENY wins over ALLOW."""
        chain = tuple(context.lower().split("."))
        if any(cls._compatible(chain, p) for p in cls._DENY):
            return "unsafe"
        if any(len(chain) >= len(p) and cls._compatible(chain, p) for p in cls._ALLOW):
            return "safe"
        return "unlisted"

    @classmethod
    def unsafe_contexts(cls, expr: str, taint: Optional["_Taint"] = None) -> List[str]:
        """The unsafe contexts one expression reads, as text for a finding.

        `env.NAME` and `matrix.NAME` are unsafe when `taint` says the variable is bound to an unsafe value.
        When `taint.env_closed` (only part of the file is in view), an `env.NAME` with no binding in view is
        unsafe too: the binding may carry untrusted data.
        """
        t = taint if taint is not None else _Taint()
        out: List[str] = []
        for ctx in cls.contexts(expr):
            seg = ctx.lower().split(".")
            name = seg[1] if len(seg) > 1 and seg[1] != "*" else ""
            if seg[0] == "env":
                if not name:
                    hit, note = bool(t.env) or t.env_closed, ""
                elif name in t.env:
                    hit, note = True, ""
                else:
                    hit = t.env_closed and name not in t.env_bound
                    note = " (bound outside this diff)"
            elif seg[0] == "matrix":
                hit, note = ("*" in t.matrix or (name in t.matrix if name else bool(t.matrix))), ""
            else:
                hit, note = cls.classify(ctx) == "unsafe", ""
            if hit:
                out.append(ctx + note)
        return out


@dataclass
class _Taint:
    """What the file in view says about env and matrix variables (names lower-cased)."""
    env: Set[str] = field(default_factory=set)        # env variables bound to an unsafe value
    env_bound: Set[str] = field(default_factory=set)  # env variables bound anywhere in view
    env_closed: bool = False                          # only part of the file is in view: unseen binding = unsafe
    matrix: Set[str] = field(default_factory=set)     # matrix variables bound to an unsafe value; "*" = all


@dataclass
class _YamlFrame:
    col: int                                # column of the key, or of the "-" of a sequence item
    kind: str                               # "key" | "item"
    key: str = ""                           # unquoted key, lower-cased
    name: str = ""                          # unquoted key as written (env variable names)
    step: Optional[Dict[str, str]] = None   # sequence items: what this file shows of the item ("uses")
    has_value: bool = False                 # key with an inline value (scalar, block or flow): no child keys
    anchor: Optional[str] = None            # `key: &a` with the value on the next line


@dataclass
class _Sink:
    kind: str                               # "run" | "input" | "unknown"
    step: Optional[Dict[str, str]] = None   # "input": the step whose `uses:` decides whether the input runs code
    key: str = ""                           # "input": the input's name


@dataclass
class _Value:
    """One YAML value as far as the diff shows it, one piece per source line, and what it is bound to."""
    sink: Optional[_Sink] = None
    env_name: Optional[str] = None          # the value of env.NAME
    matrix_name: Optional[str] = None       # the value of matrix.NAME ("*": the whole matrix)
    anchor: Optional[str] = None
    alias: Optional[str] = None             # the value is `*alias`
    style: str = "plain"                    # plain | single | double | block | flow | unknown
    flow_role: str = ""                     # flow collections: step | steps | with | env | matrix | matrix-list | matrix-item
    step: Optional[Dict[str, str]] = None   # flow "step" / "with": the step it belongs to
    pieces: List[Tuple[int, bool, str]] = field(default_factory=list)  # (line, added, text)


@dataclass
class _ValueCont:
    value: _Value
    col: int                                # only lines indented deeper than this can continue the value
    content_col: Optional[int] = None       # block scalars: indentation of the content
    quote: str = ""                         # quoted scalars: the quote still open
    depth: int = 0                          # flow collections: brackets still open
    done: bool = False                      # closed (quote or brackets) or ended by a comment


class _FlowParser:
    """Just enough of YAML flow syntax ({k: v}, [a, b], quoted and plain scalars, comments) to find keys and
    the spans of their values. Never raises; malformed text yields a partial tree."""

    MAX_DEPTH = 64

    def __init__(self, text: str) -> None:
        self.t, self.i = text, 0

    def _ws(self) -> None:
        t = self.t
        while self.i < len(t):
            c = t[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif c == "#" and (self.i == 0 or t[self.i - 1] in " \t\r\n"):
                nl = t.find("\n", self.i)
                self.i = len(t) if nl < 0 else nl
            else:
                break

    def node(self, depth: int = 0) -> Tuple[Any, ...]:
        self._ws()
        if self.i >= len(self.t) or depth > self.MAX_DEPTH:
            return ("scalar", self.i, self.i)
        c = self.t[self.i]
        if c in "{[":
            return self._collection(depth, c)
        return self._scalar()

    def _collection(self, depth: int, opener: str) -> Tuple[Any, ...]:
        close, entries, start = "}" if opener == "{" else "]", [], self.i
        self.i += 1
        while True:
            self._ws()
            if self.i >= len(self.t):
                break
            c = self.t[self.i]
            if c == close:
                self.i += 1
                break
            if c in ",}]":
                self.i += 1
                continue
            before = self.i
            if opener == "[":
                entries.append(self.node(depth + 1))
            else:
                key = self._scalar()
                self._ws()
                value: Tuple[Any, ...] = ("scalar", self.i, self.i)
                if self.i < len(self.t) and self.t[self.i] == ":":
                    self.i += 1
                    value = self.node(depth + 1)
                entries.append((WorkflowInjectionScanner._unquote(self.t[key[1]:key[2]]), value))
            if self.i == before:
                self.i += 1  # always make progress
        return ("map" if opener == "{" else "seq", entries, start, self.i)

    def _scalar(self) -> Tuple[Any, ...]:
        t, s = self.t, self.i
        if s < len(t) and t[s] in "\"'":
            end = WorkflowInjectionScanner._quote_close(t, t[s], s + 1)
            self.i = len(t) if end < 0 else end + 1
            return ("scalar", s, self.i)
        i = s
        while i < len(t):
            c = t[i]
            if t.startswith("${{", i):  # flow indicators inside an expression belong to it
                j = t.find("}}", i + 3)
                i = len(t) if j < 0 else j + 2
                continue
            if c in ",[]{}" or (c == ":" and (i + 1 == len(t) or t[i + 1] in " \t\r\n,[]{}")):
                break
            if c == "#" and i > s and t[i - 1] in " \t\r\n":
                break
            i += 1
        self.i = i
        return ("scalar", s, i)


class WorkflowInjectionScanner:
    """CWE-94 expression injection in GitHub Actions workflows and composite actions.

    Only execution sinks are checked, i.e. the places where GitHub substitutes `${{ }}` text into code that
    is then executed:
      * the value of a step's `run:` (workflows and composite actions),
      * the `script:` input of actions/github-script (any version or ref), and the other action inputs that
        CodeQL's actions models (and zizmor) list as code-injection sinks (ACTION_CODE_INPUTS).
    `env:` values, other `with:` inputs, job-level `with:`, `if:`, `concurrency`, `name:`, `runs-on`,
    `timeout-minutes`, outputs, `uses:` and YAML comments pass values as data and are never reported.
    Inside a sink, an expression is reported when it can yield attacker text: it reads a context that
    UntrustedContextPolicy calls unsafe, or `env.NAME` / `matrix.NAME` bound in view to such a value, and
    its result is not merely true/false. `${{ env.NAME }}` is still a template expansion; zizmor's
    remediation says to use the shell's "$NAME".

    Structure comes from indentation, line by line: block-mapping keys (plain or quoted, YAML escapes
    decoded), sequence items, flow collections (also over several lines), anchors and scalar aliases,
    and multi-line values (block scalars with their content indentation, multi-line plain or quoted
    scalars). Each multi-line value is assembled before its `${{ }}` expressions are extracted, so an
    expression folded over several lines is still one expression; a finding goes to the first added line
    the expression touches. The walk covers the patch's context and added lines, one hunk at a time;
    when the caller passes the post-image file, it is used for the whole-file walk only if it is the
    patch's target (the `index` line's blob id, when present) and matches every context and added line.

    Where only part of the file is in view, ambiguity fails closed: a hunk that starts inside a
    multi-line value is treated as a `run:` script when its top lines are not valid YAML structure (e.g.
    JavaScript object literals in a github-script); `env.NAME` with no binding in view is unsafe; an
    alias whose anchor is not in view is reported. A dynamic matrix whose definition is not in view is
    treated as static.
    """

    KEY_RE = re.compile(r"""(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[A-Za-z0-9_$][A-Za-z0-9_.$/-]*)[ \t]*:(?=[ \t]|$)""")
    BLOCK_HEADER_RE = re.compile(r"^[|>][0-9+-]*$")
    PROPERTY_RE = re.compile(r"([&!])(\S*)\s*")
    ALIAS_RE = re.compile(r"\*([^\s,\[\]{}]+)")
    INDEX_RE = re.compile(r"^index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})\b", re.M)
    ESCAPE_RE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", re.S)
    ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
               "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": " ",
               "P": " "}
    # Action inputs whose value the action executes. From CodeQL's actions models (code-injection sinks, as
    # packaged by zizmor in crates/zizmor/data/codeql-injection-sinks.json) plus the four zizmor adds in
    # crates/zizmor/src/audit/template_injection.rs. Keys and inputs lower-cased; any ref matches.
    ACTION_CODE_INPUTS: Dict[str, Tuple[str, ...]] = {
        "actions/github-script": ("script",),
        "appleboy/ssh-action": ("script",),
        "8398a7/action-slack": ("custom_payload",),
        "azure/cli": ("inlinescript",),
        "azure/powershell": ("inlinescript",),
        "devorbitus/yq-action-output": ("cmd",),
        "gautamkrishnar/blog-post-workflow": ("item_exec",),
        "imjohnbo/issue-bot": ("body", "linked-comments-previous-issue-text", "linked-comments-new-issue-text"),
        "lucasbento/auto-close-issues": ("issue-close-message",),
        "mikefarah/yq": ("cmd",),
        "roots/issue-closer-action": ("issue-close-message", "pr-close-message"),
        "sergeysova/jq-action": ("cmd",),
        "skitionek/notify-microsoft-teams": ("overwrite",),
        "tibdex/backport": ("body_template", "head_template", "labels_template", "title_template"),
        "amadevus/pwsh-script": ("script",),
        "jannekem/run-python-script-action": ("script",),
        "cardinalby/js-eval-action": ("expression",),
        "addnab/docker-run-action": ("options", "run"),
    }
    FIX_RUN = 'map it in the step\'s `env:` (e.g. `TITLE: ${{ github.event.issue.title }}`) and use "$TITLE"'
    FIX_JS = "map it in the step's `env:` and read `process.env.NAME` in the script"

    # ---- entry point

    @classmethod
    def findings(cls, file_path: str, patch_text: str, post_image: Optional[str] = None) -> List[InlineFinding]:
        segments, whole_file = cls._segments(patch_text, post_image)
        values: List[_Value] = []
        for lines, hunk_top in segments:
            cls._walk(lines, values, hunk_top)
        values = cls._expand_flows(values)
        texts = cls._resolve_aliases(values)
        taint = cls._solve_taint(values, texts, closed=not whole_file)
        per_line: Dict[int, Tuple[List[str], str]] = {}
        for v, (text, offsets) in zip(values, texts):
            where = cls._resolve(v.sink) if v.sink is not None else None
            if where is None:
                continue
            if v.alias is not None and text is None:  # alias to an anchor that is not in view
                ln, added, _ = v.pieces[0]
                if added and not whole_file:
                    per_line.setdefault(ln, ([], where))[0].append(f"*{v.alias} (anchor outside this diff)")
                continue
            for start, end, inner in cls._expressions(text or ""):
                if UntrustedContextPolicy.is_boolean(inner):
                    continue
                bad = UntrustedContextPolicy.unsafe_contexts(inner, taint)
                line = cls._first_added(v.pieces, offsets, start, end) if bad else None
                if line is not None:
                    found = per_line.setdefault(line, ([], where))[0]
                    found.extend(c for c in bad if c not in found)
        return [InlineFinding(file_path, max(1, line), Severity.CRITICAL, "CWE-94_WORKFLOW_INJECTION",
                              cls._message(bad, where)) for line, (bad, where) in sorted(per_line.items())]

    @classmethod
    def _message(cls, bad: List[str], where: str) -> str:
        if where == "run":
            sink, fix = "a `run:` script", cls.FIX_RUN
        elif where == "unknown":
            sink, fix = "a multi-line value whose key is outside this diff hunk (treated as a `run:` script)", cls.FIX_RUN
        elif where == "input:actions/github-script":
            sink, fix = "an actions/github-script `script:`", cls.FIX_JS
        elif where == "input:":
            sink, fix = "a `script:` input whose action is outside this diff (treated as actions/github-script)", cls.FIX_JS
        else:
            action = where.split(":", 1)[1]
            sink = f"an input that {action} runs as code"
            fix = ("map it in the step's `env:`, forward it with `envs:` and use \"$NAME\" in the script"
                   if action == "appleboy/ssh-action" else
                   f"map it in the step's `env:` and read the variable inside {action}'s code instead")
        return (f"Untrusted context {', '.join(f'`{c}`' for c in bad)} is expanded by `${{{{ }}}}` inside {sink}; "
                f"GitHub pastes the text into the code before it runs. Instead, {fix}.")

    # ---- which lines are in view

    @classmethod
    def _post_image_is_target(cls, patch_text: str, post_image: str) -> bool:
        """When the patch names its target blob (`index <old>..<new>`), the post-image must hash to it."""
        header = patch_text.split("\n@@", 1)[0] if not patch_text.startswith("@@") else ""
        m = cls.INDEX_RE.search(header)
        if m is None:
            return True
        data = post_image.encode("utf-8")
        blob = b"blob %d\0" % len(data) + data
        want = m.group(2)
        return hashlib.sha1(blob).hexdigest().startswith(want) or hashlib.sha256(blob).hexdigest().startswith(want)

    @classmethod
    def _segments(cls, patch_text: str, post_image: Optional[str]
                  ) -> Tuple[List[Tuple[List[Tuple[int, str, bool]], bool]], bool]:
        """([(lines, hunk_top)], whole_file). lines are (new line number, text, added); hunk_top marks a
        hunk that starts inside the file, so its first lines may belong to a value whose key is not in view."""
        hunks: List[List[Tuple[int, str, bool]]] = []
        prev: Optional[int] = None
        for pl in iter_patch_lines(patch_text):
            if pl.kind == "del" or pl.new_line is None:
                continue
            if prev is None or pl.new_line != prev + 1:
                hunks.append([])
            hunks[-1].append((pl.new_line, pl.content, pl.kind == "add"))
            prev = pl.new_line
        if post_image is not None and hunks and cls._post_image_is_target(patch_text, post_image):
            lines = [ln[:-1] if ln.endswith("\r") else ln for ln in post_image.split("\n")]
            if all(0 < n <= len(lines) and lines[n - 1] == text for hunk in hunks for n, text, _ in hunk):
                added = {n for hunk in hunks for n, _, is_add in hunk if is_add}
                return [([(n, text, n in added) for n, text in enumerate(lines, 1)], False)], True
        headers = [m for m in (HUNK_HEADER_RE.match(ln) for ln in patch_text.split("\n")) if m]
        new_file = len(headers) == 1 and headers[0].group(1) == "0" and headers[0].group(2) == "0"
        return [(hunk, hunk[0][0] > 1) for hunk in hunks], new_file

    # ---- the line walk

    @classmethod
    def _walk(cls, lines: List[Tuple[int, str, bool]], values: List[_Value], hunk_top: bool) -> None:
        stack: List[_YamlFrame] = []
        cont: Optional[_ValueCont] = None
        script_until, script, judged_until = -1, _Value(), -1
        for idx, (ln, raw, added) in enumerate(lines):
            body = raw.rstrip()
            stripped = body.strip()
            indent = len(body) - len(body.lstrip(" "))
            if idx < script_until:  # inside a hunk-top region judged to be script text
                if stripped:
                    script.pieces.append((ln, added, body))
                continue
            if cont is not None:
                if cls._continues(cont, body, stripped, indent, ln, added):
                    continue
                cont = None
            if not stripped or stripped.startswith("#"):
                continue  # blank line or YAML comment
            if stripped in ("---", "...") or (indent == 0 and stripped.startswith("%")):
                stack.clear()
                continue
            if hunk_top and idx >= judged_until and not any(f.col < indent for f in stack):
                judged_until, is_script = cls._script_region(lines, idx)
                if is_script:
                    script_until, script = judged_until, _Value(sink=_Sink("unknown"), style="unknown")
                    script.pieces.append((ln, added, body))
                    values.append(script)
                    continue
            col, rest, item = indent, body[indent:], None
            while rest[:1] == "-" and rest[1:2] in ("", " ", "\t"):  # one or more sequence items
                while stack and (stack[-1].col > col or stack[-1].has_value
                                 or (stack[-1].kind == "item" and stack[-1].col == col)):
                    stack.pop()
                item = _YamlFrame(col, "item", step={})
                stack.append(item)
                gap = 1 + len(rest[1:]) - len(rest[1:].lstrip(" \t"))
                col, rest = col + gap, rest[gap:]
            if not rest or rest.startswith("#"):
                continue  # a bare "-": the item's content starts on the next line
            m = cls.KEY_RE.match(rest)
            if m:
                name = cls._unquote(m.group("key"))
                while stack and (stack[-1].col >= col or stack[-1].has_value):
                    stack.pop()
                parent = stack[-1] if stack else None
                head = cls._split_value(rest[m.end():])
                stack.append(_YamlFrame(col, "key", name.lower(), name, has_value=head["style"] != "empty"))
                if head["style"] == "empty":
                    stack[-1].anchor = head["anchor"]
                    continue
                if name.lower() == "uses" and parent is not None and parent.step is not None and head["text"]:
                    parent.step["uses"] = cls._unquote(head["text"])
                cont = cls._start(cls._value_for(stack, head), col, ln, added, head, values)
                continue
            if item is not None:  # a scalar sequence entry (or a flow-mapping step)
                head = cls._split_value(rest)
                cont = cls._start(cls._value_for(stack, head), item.col, ln, added, head, values)
                continue
            # A scalar on a line of its own: the value of the key above it, or the middle of a multi-line value.
            while stack and stack[-1].col >= indent:
                stack.pop()
            owner = stack[-1] if stack else None
            if owner is None:  # the value's key is outside this hunk: fail closed
                v = _Value(sink=_Sink("unknown"), style="unknown", pieces=[(ln, added, body)])
                values.append(v)
                cont = _ValueCont(v, indent - 1)
            elif owner.kind == "key":
                head = cls._split_value(rest)
                head["anchor"] = head["anchor"] or owner.anchor
                owner.has_value = True
                parent = stack[-2] if len(stack) > 1 else None
                if owner.key == "uses" and parent is not None and parent.step is not None and head["text"]:
                    parent.step["uses"] = cls._unquote(head["text"])
                cont = cls._start(cls._value_for(stack, head), owner.col, ln, added, head, values)
            else:
                cont = _ValueCont(_Value(style="unknown"), owner.col)

    @classmethod
    def _continues(cls, cont: _ValueCont, body: str, stripped: str, indent: int, ln: int, added: bool) -> bool:
        """Add the line to the open multi-line value if it belongs to it."""
        v = cont.value
        if v.style == "block":
            if not stripped:
                return True
            if cont.content_col is None:
                if indent <= cont.col:
                    return False
                cont.content_col = indent
            if indent < cont.content_col:
                return False  # a less-indented comment or key: the block scalar has ended
            v.pieces.append((ln, added, body))
            return True
        if cont.done or not stripped or indent <= cont.col:
            return bool(not stripped and not cont.done)
        if v.style in ("single", "double"):
            end = cls._quote_close(body, cont.quote, indent)
            v.pieces.append((ln, added, body if end < 0 else body[:end + 1]))
            cont.done = end >= 0
            return True
        if v.style == "flow":
            text = cls._strip_comment(body, quotes=True)
            v.pieces.append((ln, added, text))
            cont.depth = cls._flow_depth(text, cont.depth)
            cont.done = cont.depth <= 0
            return True
        if v.style == "plain":
            if cls._has_key(body):
                return False  # plain scalars cannot contain ": ", so this is structure
            text = cls._strip_comment(body)
            v.pieces.append((ln, added, text))
            cont.done = text != body  # a comment ends a plain scalar
            return True
        v.pieces.append((ln, added, body))  # unknown: raw text
        return True

    @classmethod
    def _start(cls, v: _Value, col: int, ln: int, added: bool, head: Dict[str, Any],
               values: List[_Value]) -> Optional[_ValueCont]:
        """Record a value that starts on this line; return its continuation state if it can go on."""
        values.append(v)
        style = head["style"]
        if style == "block":
            return _ValueCont(v, col, content_col=col + head["indent"] if head["indent"] else None)
        v.pieces.append((ln, added, head["text"]))
        if style == "alias":
            v.alias = head["alias"]
            return None
        if style in ("single", "double") and head["open"]:
            return _ValueCont(v, col, quote=head["text"][0])
        if style == "flow" and head["depth"] > 0:
            return _ValueCont(v, col, depth=head["depth"])
        if style == "plain" and head["open"]:
            return _ValueCont(v, col)
        return None

    @classmethod
    def _value_for(cls, stack: List[_YamlFrame], head: Dict[str, Any]) -> _Value:
        """A value for the node on top of the stack (a key, or a sequence item holding a scalar)."""
        top = stack[-1]
        parent = stack[-2] if len(stack) > 1 else None
        style = "plain" if head["style"] in ("empty", "alias") else head["style"]
        v = _Value(style=style, anchor=head["anchor"], matrix_name=cls._matrix_name(stack))
        flow_map = head["style"] == "flow" and head["text"].startswith("{")
        if top.kind == "key":
            v.sink = cls._sink_for(stack)
            if parent is not None and parent.kind == "key" and parent.key == "env":
                v.env_name = top.name
            if head["style"] == "flow":
                if top.key == "with" and flow_map:
                    owner = cls._with_owner(stack)
                    if owner is not False:
                        v.flow_role, v.step = "with", owner
                elif top.key == "env" and flow_map:
                    v.flow_role = "env"
                elif top.key == "steps":
                    v.flow_role = "steps"
                elif v.matrix_name == "*" and top.key == "matrix" and flow_map:
                    v.flow_role, v.matrix_name = "matrix", None
                elif v.matrix_name == "*" and top.key in ("include", "exclude"):
                    v.flow_role, v.matrix_name = "matrix-list", None
        elif flow_map:
            if parent is not None and parent.kind == "key" and parent.key in ("include", "exclude") \
                    and cls._matrix_name(stack[:-1]) == "*":
                v.flow_role, v.matrix_name = "matrix-item", None
            elif cls._is_step(stack, len(stack) - 1):
                v.flow_role, v.step = "step", top.step
        return v

    @classmethod
    def _script_region(cls, lines: List[Tuple[int, str, bool]], start: int) -> Tuple[int, bool]:
        """At a line no visible key owns, look at the lines from there until the text dedents: (end of that
        region, True) if the lines at its indentation are not valid YAML structure, so the region is the inside
        of a block scalar (a script); (end, False) if they are structure."""
        first = lines[start][1].rstrip()
        base = len(first) - len(first.lstrip(" "))
        if base == 0:
            return len(lines), False
        end, script = start, False
        for j in range(start, len(lines)):
            body = lines[j][1].rstrip()
            stripped = body.strip()
            indent = len(body) - len(body.lstrip(" "))
            if stripped and indent < base:
                break
            end = j + 1
            if not stripped or indent != base or stripped.startswith("#") or script:
                continue
            rest, item = stripped, False
            while rest[:1] == "-" and rest[1:2] in ("", " ", "\t"):
                rest, item = rest[1:].lstrip(" \t"), True
            m = cls.KEY_RE.match(rest)
            if m is None:  # a scalar line among keys is text; a sequence entry is structure if it parses
                script = not item or cls._not_yaml_value(rest)
            else:
                script = cls._not_yaml_value(rest[m.end():])
        return end, script

    @classmethod
    def _not_yaml_value(cls, text: str) -> bool:
        """`key: 'x',`, `key: value;` or `- [text](link)` reads as code or prose, not as a YAML value: a
        quoted scalar or flow collection with text after its end, or a plain value ending in , ; or (."""
        v = text.strip()
        end = -1
        if v[:1] in ("'", '"'):
            end = cls._quote_close(v, v[0], 1)
        elif v[:1] in ("[", "{"):
            depth, quote = 0, ""
            for i, c in enumerate(v):
                if quote:
                    quote = "" if c == quote else quote
                elif c in "\"'":
                    quote = c
                elif c in "[{":
                    depth += 1
                elif c in "]}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
        else:
            return cls._strip_comment(v).endswith((",", ";", "("))
        tail = v[end + 1:].strip() if end >= 0 else ""
        return bool(tail) and not tail.startswith("#")

    # ---- what the stack says

    @classmethod
    def _has_key(cls, line: str) -> bool:
        """True if the line is a mapping entry (`key: ...` or `- key: ...`)."""
        rest = line.lstrip(" ")
        while rest[:1] == "-" and rest[1:2] in ("", " ", "\t"):
            rest = rest[1:].lstrip(" \t")
        return bool(cls.KEY_RE.match(rest))

    @staticmethod
    def _is_step(stack: List[_YamlFrame], i: int) -> bool:
        """stack[i] is a sequence item. It is a step unless its sequence visibly belongs to a key other than steps."""
        below = stack[i - 1] if i > 0 else None
        return below is None or (below.kind == "key" and below.key == "steps")

    @classmethod
    def _with_owner(cls, stack: List[_YamlFrame]) -> Any:
        """For a `with:` frame on top of the stack: the step dict it belongs to, None if that step is not in
        view, or False when the `with:` is not a step's (a job calling a reusable workflow, say)."""
        i = len(stack) - 2
        if i < 0:
            return None
        if stack[i].kind == "item" and cls._is_step(stack, i):
            return stack[i].step
        return False

    @classmethod
    def _sink_for(cls, stack: List[_YamlFrame]) -> Optional[_Sink]:
        """The sink whose value the key on top of the stack holds, if any."""
        frame = stack[-1]
        parent = stack[-2] if len(stack) > 1 else None
        if parent is not None and parent.kind == "key" and parent.key == "with":
            owner = cls._with_owner(stack[:-1])
            return None if owner is False else _Sink("input", owner, frame.key)
        if frame.key == "run" and (parent is None or (parent.kind == "item" and cls._is_step(stack, len(stack) - 2))):
            return _Sink("run")
        if frame.key == "script" and parent is None:
            return _Sink("input", None, "script")
        return None  # defaults.run, a job named "run", any other key

    @staticmethod
    def _matrix_name(stack: List[_YamlFrame]) -> Optional[str]:
        """The matrix variable the node on top of the stack defines ("*" for the whole matrix), if any."""
        idx = next((i for i in range(len(stack) - 1, -1, -1) if stack[i].kind == "key" and stack[i].key == "matrix"
                    and (i == 0 or (stack[i - 1].kind == "key" and stack[i - 1].key == "strategy"))), None)
        if idx is None:
            return None
        above = [f for f in stack[idx + 1:] if f.kind == "key"]
        if above and above[0].key in ("include", "exclude"):
            above = above[1:]
        return above[0].name.lower() if above else "*"

    @classmethod
    def _resolve(cls, sink: _Sink) -> Optional[str]:
        """"run", "unknown" or "input:<action>" for a sink that executes its value; None if it is data."""
        if sink.kind != "input":
            return sink.kind
        uses = (sink.step or {}).get("uses")
        if not uses:  # the step's action is not in view: only `script:` fails closed (github-script)
            return "input:" if sink.key == "script" else None
        action = uses.split("@", 1)[0].lower()
        return f"input:{action}" if sink.key.lower() in cls.ACTION_CODE_INPUTS.get(action, ()) else None

    # ---- after the walk

    @classmethod
    def _expand_flows(cls, values: List[_Value]) -> List[_Value]:
        """Replace flow collections that hold steps, `with:`, `env:` or matrix entries by their entries."""
        out: List[_Value] = []
        for v in values:
            out.append(v)
            if v.style != "flow" or not v.flow_role:
                continue
            text, offsets = cls._assemble(v.pieces)
            node = _FlowParser(text).node()

            def sub(n: Tuple[Any, ...], **kw: Any) -> None:
                """A value for the node's text; scalars only, except for matrix variables (any node)."""
                if n[0] != "scalar" and "matrix_name" not in kw:
                    return
                s, e = (n[1], n[2]) if n[0] == "scalar" else (n[2], n[3])
                style = {"'": "single", '"': "double"}.get(text[s:s + 1], "plain")
                out.append(_Value(style=style, pieces=cls._slice(v.pieces, offsets, s, e), **kw))

            def entries(n: Tuple[Any, ...]) -> List[Tuple[str, Tuple[Any, ...]]]:
                return n[1] if n[0] == "map" else []

            def items(n: Tuple[Any, ...]) -> List[Tuple[Any, ...]]:
                return n[1] if n[0] == "seq" else []

            def step(n: Tuple[Any, ...], st: Dict[str, str]) -> None:
                for key, val in entries(n):
                    k = key.lower()
                    if k == "uses" and val[0] == "scalar":
                        st["uses"] = cls._unquote(text[val[1]:val[2]])
                    elif k == "run":
                        sub(val, sink=_Sink("run"))
                    elif k == "with":
                        for ik, iv in entries(val):
                            sub(iv, sink=_Sink("input", st, ik.lower()))
                    elif k == "env":
                        for ek, ev in entries(val):
                            sub(ev, env_name=ek)

            def matrix_vars(n: Tuple[Any, ...]) -> None:
                for key, val in entries(n):
                    sub(val, matrix_name=key.lower())

            if v.flow_role == "step":
                step(node, v.step if v.step is not None else {})
            elif v.flow_role == "steps":
                for it in items(node):
                    step(it, {})
            elif v.flow_role == "with":
                for key, val in entries(node):
                    sub(val, sink=_Sink("input", v.step, key.lower()))
            elif v.flow_role == "env":
                for key, val in entries(node):
                    sub(val, env_name=key)
            elif v.flow_role == "matrix":
                for key, val in entries(node):
                    if key.lower() in ("include", "exclude"):
                        for it in items(val):
                            matrix_vars(it)
                    else:
                        sub(val, matrix_name=key.lower())
            elif v.flow_role == "matrix-list":
                for it in items(node):
                    matrix_vars(it)
            elif v.flow_role == "matrix-item":
                matrix_vars(node)
        return out

    @classmethod
    def _resolve_aliases(cls, values: List[_Value]) -> List[Tuple[Optional[str], List[int]]]:
        """(text, piece offsets) per value; an alias takes the text of the latest anchor before it (None if
        that anchor is not in view)."""
        anchors: Dict[str, str] = {}
        out: List[Tuple[Optional[str], List[int]]] = []
        for v in values:
            if v.alias is not None:
                text = anchors.get(v.alias)
                out.append((text, [0]))
            else:
                text, offsets = cls._assemble(v.pieces, decode=v.style)
                out.append((text, offsets))
            if v.anchor is not None and text is not None:
                anchors[v.anchor] = text
        return out

    @classmethod
    def _solve_taint(cls, values: List[_Value], texts: List[Tuple[Optional[str], List[int]]],
                     closed: bool) -> _Taint:
        """Which env / matrix variables hold attacker text. Each binding is parsed once; taint then spreads
        over a worklist, so a chain of n bindings costs O(n)."""
        P = UntrustedContextPolicy
        bindings: List[Tuple[str, str]] = []
        for v, (text, _) in zip(values, texts):
            for kind, name in (("env", v.env_name), ("matrix", v.matrix_name)):
                if name is not None:
                    bindings.append((kind, name.lower()))
        taint = _Taint(env_closed=closed, env_bound={n for k, n in bindings if k == "env"})
        users: Dict[Tuple[str, str], List[int]] = {}
        queue: Deque[int] = deque()
        b = 0
        for v, (text, _) in zip(values, texts):
            for kind, name in (("env", v.env_name), ("matrix", v.matrix_name)):
                if name is None:
                    continue
                direct = text is None and v.alias is not None and closed  # alias to an anchor not in view
                for _, _, inner in cls._expressions(text or ""):
                    if P.is_boolean(inner):
                        continue
                    for ctx in P.contexts(inner):
                        seg = ctx.lower().split(".")
                        if seg[0] in ("env", "matrix"):
                            ref = seg[1] if len(seg) > 1 else "*"
                            if seg[0] == "env" and closed and (ref == "*" or ref not in taint.env_bound):
                                direct = True
                            else:
                                users.setdefault((seg[0], ref), []).append(b)
                        elif P.classify(ctx) == "unsafe":
                            direct = True
                if direct:
                    queue.append(b)
                b += 1
        tainted: Set[Tuple[str, str]] = set()
        done: Set[int] = set()
        fired: Set[str] = set()
        while queue:
            i = queue.popleft()
            if i in done:
                continue
            done.add(i)
            var = bindings[i]
            if var in tainted:
                continue
            tainted.add(var)
            nxt = list(users.get(var, ()))
            if var[0] not in fired:  # wildcard readers (toJSON(env), matrix.*) depend on any variable
                fired.add(var[0])
                nxt += users.get((var[0], "*"), [])
            if var == ("matrix", "*"):  # a fully dynamic matrix taints every matrix variable
                nxt += [j for (k, _), js in users.items() if k == "matrix" for j in js]
            queue.extend(j for j in nxt if j not in done)
        taint.env = {n for k, n in tainted if k == "env"}
        taint.matrix = {n for k, n in tainted if k == "matrix"}
        return taint

    # ---- text helpers

    @classmethod
    def _assemble(cls, pieces: List[Tuple[int, bool, str]], decode: str = "") -> Tuple[str, List[int]]:
        """The value's text, pieces joined by newlines (double-quoted escapes decoded), and piece offsets."""
        parts = [cls._decode_double(t) if decode == "double" else t for _, _, t in pieces]
        offsets, pos = [], 0
        for p in parts:
            offsets.append(pos)
            pos += len(p) + 1
        return "\n".join(parts), offsets

    @staticmethod
    def _slice(pieces: List[Tuple[int, bool, str]], offsets: List[int], s: int, e: int) -> List[Tuple[int, bool, str]]:
        out = []
        for (ln, added, text), off in zip(pieces, offsets):
            a, b = max(s, off), min(e, off + len(text))
            if a < b:
                out.append((ln, added, text[a - off:b - off]))
        return out

    @staticmethod
    def _first_added(pieces: List[Tuple[int, bool, str]], offsets: List[int], s: int, e: int) -> Optional[int]:
        """The first added line among the pieces that the span [s, e) touches."""
        i = max(0, bisect.bisect_right(offsets, s) - 1)
        while i < len(pieces) and offsets[i] < max(e, s + 1):
            if pieces[i][1]:
                return pieces[i][0]
            i += 1
        return None

    @staticmethod
    def _expressions(text: str) -> List[Tuple[int, int, str]]:
        """(start, end, inner) for each `${{ }}`. A `}}` inside a single-quoted string does not close it. An
        unterminated expression runs to the end of its line; after one, later expressions are cut at their
        line end too, which keeps the scan linear."""
        out: List[Tuple[int, int, str]] = []
        i, exhausted = 0, False
        while True:
            s = text.find("${{", i)
            if s < 0:
                return out
            end, j, quote = -1, s + 3, False
            while not exhausted and j < len(text):
                c = text[j]
                if quote:
                    if c == "'":
                        if text.startswith("'", j + 1):
                            j += 2
                            continue
                        quote = False
                elif c == "'":
                    quote = True
                elif c == "}" and text.startswith("}", j + 1):
                    end = j
                    break
                j += 1
            if end < 0:
                exhausted = True
                nl = text.find("\n", s)
                stop = len(text) if nl < 0 else nl
                out.append((s, stop, text[s + 3:stop]))
                i = max(stop, s + 3)
            else:
                out.append((s, end + 2, text[s + 3:end]))
                i = end + 2

    @classmethod
    def _split_value(cls, text: str) -> Dict[str, Any]:
        """What the text after `key:` (or `- `) says: style empty|block|single|double|flow|plain|alias, the
        value's text on this line (YAML comment removed), anchor, alias, explicit block indentation, whether
        a quoted or plain scalar may go on, and the flow brackets still open."""
        v, anchor = text.strip(), None
        while v[:1] in ("&", "!"):
            m = cls.PROPERTY_RE.match(v)
            if m.group(1) == "&":
                anchor = m.group(2)
            v = v[m.end():]
        head: Dict[str, Any] = {"style": "plain", "text": "", "anchor": anchor, "alias": None, "indent": None,
                                "open": False, "depth": 0}
        if not v or v.startswith("#"):
            head["style"] = "empty"
        elif v.startswith("*"):
            m = cls.ALIAS_RE.match(v)
            head.update(style="alias", alias=m.group(1) if m else v[1:])
        elif cls.BLOCK_HEADER_RE.match(v.split(None, 1)[0]) and (len(v.split(None, 1)) == 1
                                                               or v.split(None, 1)[1].startswith("#")):
            digit = re.search(r"[1-9]", v.split(None, 1)[0])
            head.update(style="block", indent=int(digit.group()) if digit else None)
        elif v[0] in "\"'":
            end = cls._quote_close(v, v[0], 1)
            head.update(style="double" if v[0] == '"' else "single", text=v if end < 0 else v[:end + 1], open=end < 0)
        elif v[0] in "{[":
            t = cls._strip_comment(v, quotes=True)
            head.update(style="flow", text=t, depth=cls._flow_depth(t, 0))
        else:
            t = cls._strip_comment(v)
            head.update(text=t, open=t == v)  # a comment ends a plain scalar
        return head

    @staticmethod
    def _quote_close(text: str, quote: str, start: int) -> int:
        """Index of the quote that closes a scalar whose text continues at `start`, or -1."""
        i = start
        while i < len(text):
            c = text[i]
            if quote == '"' and c == "\\":
                i += 2
                continue
            if c == quote:
                if quote == "'" and text.startswith("'", i + 1):
                    i += 2
                    continue
                return i
            i += 1
        return -1

    @staticmethod
    def _flow_depth(text: str, depth: int) -> int:
        """Bracket depth after this line of a flow collection (quotes and `${{ }}` respected)."""
        quote, i = "", 0
        while i < len(text):
            c = text[i]
            if quote:
                if c == "\\" and quote == '"':
                    i += 1
                elif c == quote:
                    quote = ""
            elif c in "\"'":
                quote = c
            elif text.startswith("${{", i):
                j = text.find("}}", i + 3)
                i = len(text) if j < 0 else j + 2
                continue
            elif c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
            i += 1
        return depth

    @staticmethod
    def _strip_comment(v: str, quotes: bool = False) -> str:
        """Cut a YAML comment: '#' at the start or after whitespace (outside quotes, if `quotes`)."""
        quote, i = "", 0
        while i < len(v):
            c = v[i]
            if quote:
                if c == "\\" and quote == '"':
                    i += 1
                elif c == quote:
                    quote = ""
            elif quotes and c in "\"'":
                quote = c
            elif c == "#" and (i == 0 or v[i - 1] in " \t"):
                return v[:i].rstrip()
            i += 1
        return v

    @classmethod
    def _decode_double(cls, s: str) -> str:
        """YAML double-quoted escapes (\\x24, \\u0024, \\U00000024, \\n, ...) decoded; unknown ones kept."""
        def one(m: "re.Match[str]") -> str:
            e = m.group(1)
            if e[0] in "xuU" and len(e) > 1:
                try:
                    return chr(int(e[1:], 16))
                except (ValueError, OverflowError):
                    return m.group(0)
            return cls.ESCAPES.get(e, m.group(0))
        return cls.ESCAPE_RE.sub(one, s)

    @classmethod
    def _unquote(cls, s: str) -> str:
        s = s.strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            return cls._decode_double(s[1:-1])
        if len(s) >= 2 and s[0] == s[-1] == "'":
            return s[1:-1].replace("''", "'")
        return s


# --------------------------------------------------------------------------- supply chain & secrets

class SupplyChainAndSecretScanner:
    """Scans diffs (and outbound write payloads) for secrets and workflow supply-chain risks."""

    USES_RE = re.compile(r"""^\s*(?:-\s*)?uses:\s*["']?(?P<target>[^\s"'#]+)["']?""")
    FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
    DOCKER_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

    SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
        ("GITHUB_PAT", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b")),
        ("FIREWORKS_KEY", re.compile(r"\b(fw_[A-Za-z0-9]{20,64})\b")),
        ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
        ("OPENAI_KEY", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|\bsk-[A-Za-z0-9]{48}\b")),
        ("SLACK_TOKEN", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
        ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
        ("HUGGINGFACE_TOKEN", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
        ("AWS_ACCESS_KEY", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
        ("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
        ("GENERIC_HIGH_CONF_SECRET", re.compile(
            r"(?i)(?:api_key|apikey|secret_key|access_token|auth_token|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{24,}['\"]")),
    ]

    # CWE-94 expression injection is WorkflowInjectionScanner (execution sinks + UntrustedContextPolicy).
    WORKFLOW_PATH_RE = re.compile(r"(^|/)\.github/(workflows/[^/]+|actions/.+/action)\.ya?ml$|(^|/)action\.ya?ml$")

    @classmethod
    def scan_text_for_secrets(cls, text: str) -> List[str]:
        return [name for name, pat in cls.SECRET_PATTERNS if pat.search(text)]

    @classmethod
    def _check_uses(cls, path: str, line: int, target: str) -> List[InlineFinding]:
        if target.startswith("./"):
            return []
        if target.startswith("docker://"):
            if not cls.DOCKER_DIGEST_RE.search(target):
                return [InlineFinding(path, line, Severity.MAJOR, "UNPINNED_DOCKER_IMAGE",
                                      f"`{target}` should be pinned by `@sha256:` digest.")]
            return []
        if "@" not in target:
            return [InlineFinding(path, line, Severity.CRITICAL, "UNPINNED_ACTION_SHA",
                                  f"`{target}` has no ref; pin to a 40-char commit SHA.")]
        slug, ref = target.rsplit("@", 1)
        if not cls.FULL_SHA_RE.match(ref):
            kind = "reusable workflow" if "/.github/workflows/" in slug else "Action"
            return [InlineFinding(path, line, Severity.CRITICAL, "UNPINNED_ACTION_SHA",
                                  f"Third-party {kind} `{slug}@{ref}` must be pinned to a 40-char commit SHA.")]
        return []

    @classmethod
    def audit_diff(cls, file_path: str, patch_text: str, post_image: Optional[str] = None) -> List[InlineFinding]:
        """Findings on the added lines of one file's unified diff.

        post_image: optional full text of the file after the change. It is used only to give the CWE-94
        rule the YAML context of each added line, and only when it is the patch's target (it hashes to the
        blob on the patch's `index` line, if there is one) and matches every context and added line of the
        patch; otherwise the rule works from the patch alone.
        """
        findings: List[InlineFinding] = []
        is_workflow = bool(cls.WORKFLOW_PATH_RE.search(file_path))
        adds = added_lines(patch_text)
        injection: Dict[int, InlineFinding] = {}
        if is_workflow:
            injection = {f.line: f for f in WorkflowInjectionScanner.findings(file_path, patch_text, post_image)}
        for pl in adds:
            line_no = max(1, pl.new_line or 1)
            for secret_type in cls.scan_text_for_secrets(pl.content):
                findings.append(InlineFinding(file_path, line_no, Severity.CRITICAL, f"SECRET_LEAK:{secret_type}",
                                              "Hardcoded credential detected in diff. Revoke and move to encrypted secrets."))
            if not is_workflow:
                continue
            m_uses = cls.USES_RE.match(pl.content)
            if m_uses:
                findings.extend(cls._check_uses(file_path, line_no, m_uses.group("target")))
            if line_no in injection:
                findings.append(injection.pop(line_no))
        if is_workflow:
            added_text = "\n".join(p.content for p in adds)
            if re.search(r"^\s*pull_request_target\s*:", added_text, re.M) or re.search(r"\bon:\s*\[?[^\n]*pull_request_target", added_text):
                head_checkout = re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", added_text)
                first = next((p.new_line for p in adds if "pull_request_target" in p.content), 1) or 1
                findings.append(InlineFinding(
                    file_path, first, Severity.CRITICAL if head_checkout else Severity.MAJOR, "PULL_REQUEST_TARGET",
                    "pull_request_target runs with write token and secrets"
                    + ("; checking out the PR head makes this a pwn-request." if head_checkout else "; never check out or execute PR head code.")))
            if re.search(r"^\s*permissions:\s*write-all\b", added_text, re.M):
                first = next((p.new_line for p in adds if "write-all" in p.content), 1) or 1
                findings.append(InlineFinding(file_path, first, Severity.MAJOR, "OVERBROAD_PERMISSIONS",
                                              "Use least-privilege `permissions:` per job instead of write-all."))
        return findings


# --------------------------------------------------------------------------- DeepSeek protocol layer

class ThinkStreamFilter:
    """Stateful <think> stripper for streamed text. Feed chunks, emit only visible text.

    Handles tags split across chunk boundaries and the template-prefilled case where the model
    emits reasoning first and only a closing </think> (set `assume_open=True`).
    """
    OPEN, CLOSE = "<think>", "</think>"
    # ASCII-only case fold: str.lower() can change length ("İ" -> "i̇"), which misaligned indices into buf.
    _FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

    def __init__(self, assume_open: bool = False) -> None:
        self.inside = assume_open
        self.buf = ""
        self.stripped_blocks = 0

    def feed(self, chunk: str) -> str:
        self.buf += chunk
        out: List[str] = []
        while True:
            low = self.buf.translate(self._FOLD)
            tag = self.CLOSE if self.inside else self.OPEN
            idx = low.find(tag)
            if idx >= 0:
                if not self.inside:
                    out.append(self.buf[:idx])
                else:
                    self.stripped_blocks += 1
                self.buf = self.buf[idx + len(tag):]
                self.inside = not self.inside
                continue
            keep = 0  # retain a possible partial tag at the end of the buffer
            for k in range(min(len(tag) - 1, len(self.buf)), 0, -1):
                if tag.startswith(low[-k:]):
                    keep = k
                    break
            emit, self.buf = self.buf[: len(self.buf) - keep], self.buf[len(self.buf) - keep:]
            if not self.inside:
                out.append(emit)
            return "".join(out)

    def flush(self) -> str:
        rest, self.buf = self.buf, ""
        if self.inside:
            self.stripped_blocks += 1
            return ""
        return rest


class DeepSeekProtocolSanitizer:
    """Hardens the LiteLLM <-> Fireworks DeepSeek bridge: reasoning leaks, pseudo tool calls, loops, budgets."""

    THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
    UNCLOSED_THINK_RE = re.compile(r"<think>.*$", re.DOTALL | re.IGNORECASE)
    ORPHAN_CLOSE_RE = re.compile(r"^.*?</think>", re.DOTALL | re.IGNORECASE)
    PSEUDO_XML_TOOL_RE = re.compile(
        r"<(?P<tag>bash|execute_bash|tool|tool_call|function_call)>(?P<body>.*?)</(?P=tag)>", re.DOTALL | re.IGNORECASE)
    # DeepSeek V3-family native tool-call special tokens leaking into text. VERIFY against the
    # V4.1 chat template before relying on this in production.
    NATIVE_TOOL_RE = re.compile(
        r"<｜tool▁call▁begin｜>\s*(?:function)?\s*<｜tool▁sep｜>\s*(?P<name>[\w.\-]+)\s*"
        r"(?:```(?:json)?\s*)?(?P<args>\{.*?\})\s*(?:```)?\s*<｜tool▁call▁end｜>", re.DOTALL)
    NATIVE_WRAPPER_RE = re.compile(r"<｜tool▁(?:calls|outputs?)▁(?:begin|end)｜>")

    _CFG = GemConfig.from_env()
    DEPLOYMENT_ID = _CFG.deployment_id
    BASE_MODEL = _CFG.base_model
    MAX_CONTEXT_TOKENS = _CFG.max_context_tokens
    INPUT_BUDGET_TOKENS = _CFG.input_budget_tokens
    OUTPUT_BUDGET_TOKENS = _CFG.output_budget_tokens

    # Current Claude Code names first; legacy names kept for old transcripts.
    LOW_COST_TOOLS = {"Read", "Grep", "Glob", "LS", "NotebookRead", "TodoWrite", "GlobTool", "GrepTool", "ViewFile"}
    HEAVY_REASONING_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit", "Bash", "Task", "Agent",
                             "FileEdit", "FileWrite", "Architect", "TRIZMutate"}
    SAFE_REPAIR_TOOLS = {"Read", "Grep", "Glob", "LS"}

    def __init__(self, max_identical_retries: int = 2, max_session_tokens: int = 500_000) -> None:
        self.max_identical_retries = max_identical_retries
        self.max_session_tokens = max_session_tokens
        self.cumulative_tokens = 0
        self.recent_call_hashes: Deque[str] = deque(maxlen=64)
        self._fail_streak: Dict[str, int] = {}

    @classmethod
    def strip_reasoning_tokens(cls, raw_output: str) -> Tuple[str, int]:
        matches = cls.THINK_BLOCK_RE.findall(raw_output)
        count = len(matches)
        cleaned = cls.THINK_BLOCK_RE.sub("", raw_output)
        low = cleaned.lower()
        if "</think>" in low and ("<think>" not in low or low.index("</think>") < low.index("<think>")):
            cleaned = cls.ORPHAN_CLOSE_RE.sub("", cleaned, count=1)
            count += 1
        if "<think>" in cleaned.lower():
            cleaned = cls.UNCLOSED_THINK_RE.sub("", cleaned)
            count += 1
        return cleaned.strip(), count

    @classmethod
    def repair_xml_tool_calls(cls, content: str, allowed_tools: Optional[Set[str]] = None) -> Tuple[str, List[Dict[str, Any]]]:
        """v5-compatible: returns (cleaned_text, repaired_allowlisted_calls)."""
        cleaned, repaired, _ = cls.repair_tool_calls_detailed(content, allowed_tools)
        return cleaned, repaired

    @classmethod
    def repair_tool_calls_detailed(cls, content: str, allowed_tools: Optional[Set[str]] = None
                                   ) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Convert leaked pseudo-XML / native-token tool calls into tool_use blocks.

        Only tools in `allowed_tools` (default: read-only SAFE_REPAIR_TOOLS) are repaired; the rest
        are returned as `rejected`, because turning free text into an executable call is a
        privilege boundary (probe P04). Callers should surface rejected calls, never run them.
        """
        allowed = cls.SAFE_REPAIR_TOOLS if allowed_tools is None else set(allowed_tools)
        repaired: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []

        def _emit(name: str, payload: Dict[str, Any], body: str) -> None:
            block = {"type": "tool_use",
                     "id": f"toolu_repaired_{len(repaired) + len(rejected)}_{hashlib.sha256(body.encode()).hexdigest()[:8]}",
                     "name": name, "input": payload}
            (repaired if name in allowed else rejected).append(block)

        for match in cls.PSEUDO_XML_TOOL_RE.finditer(content):
            tag, body = match.group("tag").lower(), match.group("body").strip()
            name = "Bash" if "bash" in tag else "ToolCall"
            payload: Dict[str, Any] = {"command": body} if name == "Bash" else {"raw": body}
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    name = str(parsed.get("name", name))
                    args = parsed.get("arguments", parsed.get("input", parsed))
                    payload = args if isinstance(args, dict) else {"raw": args}
            except (ValueError, TypeError):
                pass
            _emit(name, payload, body)
        for match in cls.NATIVE_TOOL_RE.finditer(content):
            try:
                args = json.loads(match.group("args"))
            except ValueError:
                args = {"raw": match.group("args")}
            _emit(match.group("name"), args if isinstance(args, dict) else {"raw": args}, match.group(0))

        cleaned = cls.PSEUDO_XML_TOOL_RE.sub("", content)
        cleaned = cls.NATIVE_TOOL_RE.sub("", cleaned)
        cleaned = cls.NATIVE_WRAPPER_RE.sub("", cleaned).strip()
        return cleaned, repaired, rejected

    def record_result(self, call_signature: str, success: bool) -> None:
        """Report the outcome of an executed call; success resets that signature's failure streak."""
        sig = hashlib.sha256(call_signature.encode("utf-8")).hexdigest()[:16]
        self._fail_streak[sig] = 0 if success else self._fail_streak.get(sig, 0) + 1

    def route_and_check_circuit_breaker(self, tool_name: str, prompt_tokens: int, call_signature: str) -> Dict[str, Any]:
        if prompt_tokens > self.INPUT_BUDGET_TOKENS:
            return {"allowed": False, "target_model": None,
                    "reason": f"Context budget exceeded: {prompt_tokens} > {self.INPUT_BUDGET_TOKENS} input cap."}
        if self.cumulative_tokens + prompt_tokens > self.max_session_tokens:
            return {"allowed": False, "target_model": None,
                    "reason": f"Financial circuit breaker tripped: cumulative tokens ({self.cumulative_tokens + prompt_tokens}) exceed cap ({self.max_session_tokens})."}
        sig = hashlib.sha256(call_signature.encode("utf-8")).hexdigest()[:16]
        self.recent_call_hashes.append(sig)
        if self._fail_streak.get(sig, 0) >= self.max_identical_retries:
            return {"allowed": False, "target_model": None,
                    "reason": f"Loop circuit breaker tripped: identical call failed {self._fail_streak[sig]} times in a row."}
        self.cumulative_tokens += prompt_tokens
        tier = "local-fast-tier" if tool_name in self.LOW_COST_TOOLS else f"openai/{self.DEPLOYMENT_ID}"
        return {"allowed": True, "reason": "PASS", "target_model": tier, "cumulative_tokens": self.cumulative_tokens}


# --------------------------------------------------------------------------- aTRIZ-SWE scoring

IDEALITY_MAX = 1e6  # finite, JSON-safe stand-in for "no cost, no harm"


@dataclass(frozen=True)
class TRIZMutationReceipt:
    improving_param: str
    worsening_param: str
    inventive_principle: str
    operator_name: str
    code_diff_sha256: str
    ideality_score: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


@dataclass(frozen=True)
class FMEARecord:
    failure_mode: str
    severity: int
    occurrence: int
    detection: int

    def __post_init__(self) -> None:
        for name in ("severity", "occurrence", "detection"):
            v = getattr(self, name)
            if not 1 <= v <= 10:
                raise ValueError(f"{name} must be in 1..10, got {v}")

    @property
    def rpn(self) -> int:
        return self.severity * self.occurrence * self.detection


class ATRIZInnovationEngine:
    """Deterministic scoring helpers for the aTRIZ-SWE protocol (contradiction lookup, RICE, FMEA, UCT, FI).

    Note: contradiction *extraction*, LATS tree search and SMT discharge are not implemented here;
    they are scoped as separate workflow units (see GRAPH.md).
    """

    CONTRADICTION_MATRIX: Dict[Tuple[str, str], Tuple[str, str]] = {
        ("deliberation_depth", "token_latency"): ("Principle 1 (Segmentation) & Principle 2 (Taking Out)",
                                                   "Sub-Graph Context Pruning & Modularization-of-Thought (MoT)"),
        ("perspective_diversity", "sycophancy_bloat"): ("Principle 13 (The Other Way Round) & Principle 17 (Another Dimension)",
                                                         "Blind Orthogonal Subspace Projection + RICE Pruning Gate"),
        ("execution_throughput", "memory_lock_contention"): ("Principle 10 (Preliminary Action) & Principle 15 (Dynamization)",
                                                              "Speculative Pre-Computation & Lock-Free State Sharding"),
        ("formal_correctness", "smt_solver_timeout"): ("Principle 7 (Nested Doll) & Principle 24 (Intermediary)",
                                                        "Hierarchical Lemma Nesting & SOVER Decomposition"),
        ("api_extensibility", "cyclomatic_complexity"): ("Principle 25 (Self-Service / Copy) & Principle 40 (Composite Structures)",
                                                          "Pure Functional Interface Wrapping & Shadow Proxy"),
    }

    @staticmethod
    def compute_ideality(benefits: List[float], costs: List[float], harms: List[float]) -> float:
        denom = sum(costs) + sum(harms)
        if denom <= 1e-9:
            return IDEALITY_MAX
        return round(min(IDEALITY_MAX, sum(benefits) / denom), 4)

    @staticmethod
    def compute_rice(reach: float, impact: float, confidence: float, effort: float) -> float:
        if effort <= 0:
            raise ValueError("Effort must be positive")
        return round((reach * impact * max(0.0, min(1.0, confidence))) / effort, 4)

    @staticmethod
    def compute_lats_uct(value: float, parent_visits: int, node_visits: int, exploration_weight: float = 1.414) -> float:
        if node_visits <= 0:
            return float("inf")  # unvisited nodes are explored first (search-internal, never serialized)
        if parent_visits <= 1:
            return value
        return round(value + exploration_weight * math.sqrt(math.log(parent_visits) / node_visits), 4)

    @staticmethod
    def compute_functional_information(qualifying_fraction: float) -> float:
        if qualifying_fraction <= 0.0 or qualifying_fraction > 1.0:
            raise ValueError("qualifying_fraction must be in (0, 1]")
        return round(-math.log2(qualifying_fraction), 4)

    @classmethod
    def synthesize_triza_mutation(cls, improving: str, worsening: str, code_patch: str,
                                  benefits: List[float], costs: List[float], harms: List[float]) -> TRIZMutationReceipt:
        principle, operator = cls.CONTRADICTION_MATRIX.get(
            (improving, worsening), ("UNMAPPED (no matrix entry)", "Manual principle selection required"))
        return TRIZMutationReceipt(improving, worsening, principle, operator,
                                   hashlib.sha256(code_patch.encode("utf-8")).hexdigest(),
                                   cls.compute_ideality(benefits, costs, harms))


# --------------------------------------------------------------------------- tech debt

@dataclass(frozen=True)
class TechnicalDebtReport:
    psc_score: float
    aup_score: float
    dur_score: float
    detected_debts: List[TechnicalDebtCategory]
    mitigation_actions: List[str]
    aup_measured: bool = False      # True only when an external API-plausibility checker supplied AUP
    smell_hits: int = 0
    deprecated_hits: int = 0
    policy_hits: int = 0            # house-policy discouraged calls (spec: `claude --print`, `os.system`)
    tests_passed: Optional[bool] = None


class LLMTechnicalDebtSensor:
    """Per-diff heuristics inspired by the metrics surveyed in arXiv:2606.14796 (MLR).

    Naming caveat, from the MLR itself: PSC (Velasco et al., CodeSmellEval) is a model-level
    *propensity* measured on a benchmark, and AUP / DUR (Wang et al., ReplaceAPI) are independent:
    AUP = share of API completions that are accurate, DUR = share of *plausible* completions that are
    deprecated. AUP is therefore NOT 1 - DUR. Here PSC = smell density per added lines, DUR uses added
    lines as a proxy denominator, and AUP stays UNMEASURED unless a resolver/type-checker supplies it.
    House-policy rules (discouraged but not deprecated) are counted separately as `policy_hits`.
    """

    # Curated, genuinely deprecated or removed APIs. Extend per stack via `extra_deprecated`.
    DEPRECATED_PATTERNS: List["re.Pattern[str]"] = [
        re.compile(r"\bdatetime\.utcnow\s*\("),            # Python 3.12
        re.compile(r"^\s*import\s+(?:imp|distutils)\b|^\s*from\s+distutils\b", re.M),
        re.compile(r"\bpkg_resources\b"),
        re.compile(r"\.(?:toUpperCase|toLowerCase)\s*\(\s*\)"),  # Kotlin 1.5 -> uppercase()/lowercase()
        re.compile(r"\bAsyncTask\s*<"),                     # Android API 30
        re.compile(r"\bstartActivityForResult\s*\("),
        re.compile(r"\bnew\s+Buffer\s*\("),                 # Node DEP0005
        re.compile(r"::set-output\s+name="),                # GitHub Actions workflow command
        re.compile(r"\btry!\s*\("),                         # Rust 2018+
    ]
    SMELL_PATTERNS: List["re.Pattern[str]"] = [
        re.compile(r"except\s*(?:Exception|BaseException)?\s*(?:as\s+\w+)?\s*:\s*pass\b"),
        # silent JSON parse catches (unified spec, section 5)
        re.compile(r"except\s*\(?[\w., ]*(?:JSONDecodeError|ValueError)[\w., ]*\)?\s*(?:as\s+\w+)?\s*:\s*(?:pass|continue|return(?:\s+None)?)\s*$", re.M),
        re.compile(r"catch\s*\([^)]*\)\s*\{\s*(?:/\*[^*]*\*/|//[^\n]*)?\s*\}"),
        re.compile(r"\bcatch\s*\{\s*\}"),
        re.compile(r"\.catch\(\s*\(?\s*\w*\s*\)?\s*=>\s*(?:\{\s*\}|null|undefined)\s*\)"),
        re.compile(r"TODO:\s*implement|FIXME"),
    ]
    # Discouraged by house policy (unified spec, section 5): prefer structured task/MCP dispatch.
    POLICY_PATTERNS: List["re.Pattern[str]"] = [
        re.compile(r"\bclaude\s+(?:--print|-p)\b"),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True"),
    ]

    @classmethod
    def evaluate_patch(cls, patch_text: str, has_tests: bool, has_prompt_versioning: bool,
                       has_provenance_receipt: bool, extra_deprecated: Iterable["re.Pattern[str]"] = (),
                       aup_score: Optional[float] = None, tests_passed: Optional[bool] = None,
                       policy_patterns: Optional[Iterable["re.Pattern[str]"]] = None) -> TechnicalDebtReport:
        adds = [p.content for p in added_lines(patch_text)]
        total = max(1, len(adds))
        joined = "\n".join(adds)
        smell_hits = sum(len(p.findall(joined)) for p in cls.SMELL_PATTERNS)
        dep_hits = sum(len(p.findall(joined)) for p in [*cls.DEPRECATED_PATTERNS, *extra_deprecated])
        pol = cls.POLICY_PATTERNS if policy_patterns is None else list(policy_patterns)
        policy_hits = sum(len(p.findall(joined)) for p in pol)

        psc = round(min(1.0, smell_hits / max(5.0, total / 10.0)), 4)
        dur = round(min(1.0, dep_hits / float(total)), 4)
        measured = aup_score is not None
        aup = round(max(0.0, min(1.0, aup_score)), 4) if measured else round(1.0 - dur, 4)

        debts: List[TechnicalDebtCategory] = []
        actions: List[str] = []
        if psc > 0.0:
            debts.append(TechnicalDebtCategory.CODE_DEBT)
            actions.append("Refactor broad exception swallows and placeholder stubs flagged by PSC sensor.")
        if dur > 0.0:
            debts.append(TechnicalDebtCategory.DESIGN_DEBT)
            actions.append("Replace deprecated APIs flagged by DUR sensor.")
        if measured and aup < 1.0:
            debts.append(TechnicalDebtCategory.DESIGN_DEBT)
            actions.append("Fix API calls that do not resolve against pinned dependency versions.")
        if policy_hits:
            debts.append(TechnicalDebtCategory.GOVERNANCE_DEBT)
            actions.append("Replace shell-string execution / headless CLI calls with structured task or MCP dispatch (house policy).")
        if not has_tests or tests_passed is False:
            debts.extend([TechnicalDebtCategory.TEST_DEBT, TechnicalDebtCategory.FAST_INTEGRATION_DEBT])
            actions.append("Block merge until a deterministic test suite exists and passes.")
        if not has_prompt_versioning:
            debts.append(TechnicalDebtCategory.PROMPT_DEBT)
            actions.append("Register system prompts and CLAUDE.md contracts in a versioned prompt registry.")
        if not has_provenance_receipt:
            if TechnicalDebtCategory.GOVERNANCE_DEBT not in debts:
                debts.append(TechnicalDebtCategory.GOVERNANCE_DEBT)
            debts.append(TechnicalDebtCategory.PROVENANCE_DEBT)
            actions.append("Attach a signed PreFlightGate receipt (git trailer) to the commit.")
        return TechnicalDebtReport(psc, aup, dur, debts, actions, measured, smell_hits, dep_hits, policy_hits, tests_passed)


# --------------------------------------------------------------------------- receipts

class ReceiptSigner:
    """HMAC-SHA256 signer. The key lives with the hook/gateway process, never in model context."""

    def __init__(self, key: Optional[bytes] = None) -> None:
        env_key = os.environ.get("GEM_RECEIPT_KEY")
        self.key = key if key is not None else (env_key.encode() if env_key else None)

    def sign(self, payload: Dict[str, Any]) -> Optional[str]:
        if not self.key:
            return None
        msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self.key, msg, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        expected = self.sign(payload)
        return bool(expected) and hmac.compare_digest(expected, signature)


@dataclass
class GateDecision:
    allowed: bool
    decision: str                 # PASS | WARN | BLOCK
    violations: List[str]
    tool_name: str
    target_branch: str
    mode: EnforcementMode
    facts: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    attestation: Optional[Dict[str, Any]] = None   # ForgeCore-signed evidence (ADR-007), when attested

    def payload(self) -> Dict[str, Any]:
        return {"tool": self.tool_name, "branch": self.target_branch, "decision": self.decision,
                "violations": self.violations, "mode": self.mode.value, "facts": self.facts}

    def to_xml(self) -> str:
        f = self.facts
        esc = lambda v: html.escape(str(v), quote=True)  # noqa: E731
        lines = [
            "<PreFlightGate generator=\"gemcore/%s\"%s%s>" % (
                __version__,
                f' signature="{self.signature}"' if self.signature else "",
                (f' signer="forgecore" attestation_id="{esc(self.attestation.get("attestation_id"))}"'
                 f' key_id="{esc(self.attestation.get("key_id"))}"') if self.attestation else ""),
            f"  <tool_name>{esc(self.tool_name)}</tool_name>",
            f"  <target_branch>{esc(self.target_branch)}</target_branch>",
            f"  <author_trust_level>{esc(f.get('author_trust'))}</author_trust_level>",
            f"  <injection_scan status=\"{'ALERT' if f.get('injection_alerts') else 'CLEAN'}\" alerts=\"{f.get('injection_alerts', 0)}\" />",
            f"  <workflow_security_scan status=\"{'ALERT' if f.get('critical_findings') else 'CLEAN'}\" alerts=\"{f.get('critical_findings', 0)}\" />",
            f"  <cross_boundary_symbols verified=\"{str(not f.get('unverified_symbols')).lower()}\">{esc(', '.join(f.get('required_symbols', [])))}</cross_boundary_symbols>",
        ]
        if "psc" in f:
            lines.append(f"  <tech_debt_metrics psc=\"{f['psc']:.2f}\" aup=\"{'%.2f' % f['aup'] if f.get('aup_measured') else 'UNMEASURED'}\" dur=\"{f['dur']:.2f}\" />")
        for v in self.violations:
            lines.append(f"  <violation>{esc(v)}</violation>")
        lines.append(f"  <gate_decision mode=\"{self.mode.value}\">{self.decision}</gate_decision>")
        lines.append("</PreFlightGate>")
        return "\n".join(lines)


# --------------------------------------------------------------------------- reference monitor

class ForgeCoreUnavailable(RuntimeError):
    """ForgeCore could not attest (unreachable, misconfigured, or rejected the claim)."""


class ForgeCoreAttestor:
    """Client for AutoDev's `/api/v1/gate/attest` (ADR-007). Stdlib only, so it runs under Termux.

    ForgeCore holds the signing key. This client sends the gate's *claims*; the kernel derives the
    decision, adds its own protected-ref check and signs. The client never sees the key.
    """

    def __init__(self, base_url: str, bearer_token: str, timeout_s: float = 5.0) -> None:
        if not base_url or not bearer_token:
            raise ValueError("ForgeCoreAttestor needs a base URL and an API bearer token")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout_s = timeout_s

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> Optional["ForgeCoreAttestor"]:
        e = dict(os.environ if env is None else env)
        url = e.get("GEM_FORGECORE_URL") or e.get("AUTODEV_URL")
        token = e.get("AUTODEV_API_BEARER_TOKEN")
        return cls(url, token) if url and token else None

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            self.base_url + path, data=json.dumps(body).encode(), method="POST",
            headers={"content-type": "application/json", "authorization": f"Bearer {self.bearer_token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310 (operator-configured URL)
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise ForgeCoreUnavailable(f"HTTP {exc.code} from ForgeCore: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ForgeCoreUnavailable(f"ForgeCore unreachable: {exc}") from exc

    def attest(self, request: Dict[str, Any]) -> Dict[str, Any]:
        att = self._post("/api/v1/gate/attest", request)
        if att.get("decision") not in {"PASS", "WARN", "BLOCK"} or not att.get("signature"):
            raise ForgeCoreUnavailable("ForgeCore returned a malformed attestation")
        return att

    def verify(self, attestation: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/api/v1/gate/verify", attestation)


class StatefulGitHubOpsMonitor:
    """Stateful reference monitor: quarantine, ABI receipts, phase guard, and the write gate."""

    # gemcore tool names → ForgeCore's branch-write vocabulary (ADR-007)
    FORGECORE_TOOL_NAMES = {"push_files": "push_files", "create_or_update_file": "create_or_update_file",
                            "delete_file": "delete_file", "git_push": "git_push", "git_force_push": "git_force_push"}

    PROTECTED_BRANCH_PATTERNS = [
        re.compile(r"^(main|master|production|prod|trunk)$", re.I),
        re.compile(r"^(release|hotfix)([/-].*)?$", re.I),
    ]
    REF_PREFIX_RE = re.compile(r"^(?:refs/heads/|refs/remotes/[^/]+/|heads/|origin/|upstream/)", re.I)

    HOMOGLYPH_MAP = str.maketrans({
        "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "А": "A", "В": "B", "Е": "E", "І": "I", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "Х": "X",
    })
    INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\U000e0000-\U000e007f]")
    INJECTION_PATTERNS = [
        re.compile(r"<!--.*?(ignore|override|system|instruction|execute|workflow|approve|merge).*?-->", re.I | re.S),
        re.compile(r"\[//\]:\s*#\s*\(.*?(ignore|override|system|instruction|execute|approve|merge).*?\)", re.I | re.S),
        re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|earlier|above|all|system)\b[^.\n]{0,20}"
                   r"\b(instructions?|rules|prompts?|guidelines|directions)\b", re.I),
        re.compile(r"(system prompt override|new system instruction|you are now (?:in )?\w+ mode|act as (?:the )?(?:maintainer|admin|owner|root))", re.I),
        INVISIBLE_RE,
    ]
    CROSS_BOUNDARY_PATTERNS = [
        re.compile(r"\bextern\s+(?:\"C(?:-unwind)?\"\s+)?fn\s+([A-Za-z0-9_]+)"),
        re.compile(r"\b(?:expect|actual)\s+(?:(?:suspend|inline|internal|public|data|value|sealed|abstract|open)\s+)*"
                   r"(?:fun|class|interface|object|val|var|typealias)\s+(?:`)?([A-Za-z0-9_]+)"),
        re.compile(r"\bexternal\s+fun\s+([A-Za-z0-9_]+)"),
        re.compile(r"\bJNIEXPORT\s+[^\n]+?\s+JNICALL\s+(Java_[A-Za-z0-9_]+)"),
        re.compile(r"@CName\(\s*\"([A-Za-z0-9_]+)\"\s*\)"),
        re.compile(r"@_cdecl\(\s*\"([A-Za-z0-9_]+)\"\s*\)"),
        re.compile(r"#\[wasm_bindgen[^\]]*\]\s*pub\s+(?:async\s+)?fn\s+([A-Za-z0-9_]+)"),
    ]
    WRITE_TOOLS = {"push_files", "create_or_update_file", "delete_file", "create_pull_request", "update_pull_request",
                   "merge_pull_request", "create_branch", "run_workflow", "update_pull_request_branch",
                   "git_push", "git_force_push"}
    # Same vocabulary as ForgeCore's BRANCH_WRITE_TOOLS (ADR-007): MCP writes and shell `git push`.
    BRANCH_WRITE_TOOLS = {"push_files", "create_or_update_file", "delete_file", "git_push", "git_force_push"}
    REVIEW_TOOLS = {"merge_pull_request", "create_pull_request_review", "pull_request_review_write"}
    TAINT_BLOCKED_TOOLS = {"push_files", "create_or_update_file", "delete_file", "create_pull_request",
                           "merge_pull_request", "run_workflow", "create_branch", "git_push", "git_force_push"}

    def __init__(self, author_trust: TrustLevel = TrustLevel.COLLABORATOR, config: Optional[GemConfig] = None,
                 signer: Optional[ReceiptSigner] = None, psc_block_threshold: float = 0.0,
                 fast_integration_policy: str = "strict", attestor: Optional[ForgeCoreAttestor] = None,
                 repository: Optional[str] = None, session_id: Optional[str] = None) -> None:
        self.attestor = attestor if attestor is not None else ForgeCoreAttestor.from_env()
        self.repository = repository or os.environ.get("GEM_REPOSITORY", "unknown/unknown")
        self.session_id = session_id or os.environ.get("GEM_SESSION_ID") or hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        if fast_integration_policy not in {"strict", "smell"}:
            raise ValueError("fast_integration_policy must be 'strict' (unified spec) or 'smell' (v5 SKILL.md)")
        self.fast_integration_policy = fast_integration_policy
        self.config = config or GemConfig.from_env()
        self.signer = signer or ReceiptSigner()
        self.phase: WorkflowPhase = WorkflowPhase.DISCOVER
        self.author_trust = author_trust
        self.injection_alerts: List[str] = []
        self.supply_chain_findings: List[InlineFinding] = []
        self.required_symbols: Set[str] = set()
        self.verified_symbols: Set[str] = set()
        self.abi_receipts: List[Dict[str, Any]] = []
        self.file_patches: Dict[str, str] = {}
        self.retry_budget: int = 1
        self.psc_block_threshold = psc_block_threshold
        self.deepseek_sanitizer = DeepSeekProtocolSanitizer()

    # ---- helpers
    @classmethod
    def normalize_branch(cls, ref: str) -> str:
        return cls.REF_PREFIX_RE.sub("", (ref or "").strip())

    @classmethod
    def is_protected_branch(cls, ref: str) -> bool:
        name = cls.normalize_branch(ref)
        return any(p.match(name) for p in cls.PROTECTED_BRANCH_PATTERNS)

    @classmethod
    def _decode_unicode_tags(cls, text: str) -> str:
        return "".join(chr(ord(ch) - 0xE0000) if 0xE0020 <= ord(ch) <= 0xE007E else ch for ch in text)

    # ---- stage 2
    def sanitize_text(self, raw_text: str, source_tag: str) -> str:
        if self.phase == WorkflowPhase.DISCOVER:
            self.phase = WorkflowPhase.INGEST
        for pattern in self.INJECTION_PATTERNS:
            if pattern.search(raw_text):
                self.injection_alerts.append(f"Raw injection match in {source_tag}: {pattern.pattern[:60]}")
        normalized = unicodedata.normalize("NFKC", self._decode_unicode_tags(raw_text)).translate(self.HOMOGLYPH_MAP)
        for pattern in self.INJECTION_PATTERNS[:4]:
            if pattern.search(normalized):
                alert = f"Normalized injection match in {source_tag}: {pattern.pattern[:60]}"
                if alert not in self.injection_alerts:
                    self.injection_alerts.append(alert)
        cleaned = re.sub(r"<!--.*?-->", "[STRIPPED_HTML_COMMENT]", raw_text, flags=re.S)
        cleaned = re.sub(r"\[//\]:\s*#\s*\(.*?\)", "[STRIPPED_MD_COMMENT]", cleaned, flags=re.S)
        cleaned = self.INVISIBLE_RE.sub("", cleaned)
        return (f'<untrusted_github_payload source="{html.escape(source_tag)}" executable="false">\n'
                f"{html.escape(cleaned, quote=False)}\n</untrusted_github_payload>")

    def ingest_pull_request_files(self, files_payload: List[Dict[str, Any]]) -> None:
        for file_obj in files_payload:
            path, patch = str(file_obj.get("filename", "")), str(file_obj.get("patch", ""))
            if not (path and patch):
                continue
            self.file_patches[path] = patch
            for pl in iter_patch_lines(patch):
                if pl.kind == "ctx":
                    continue
                for pattern in self.CROSS_BOUNDARY_PATTERNS:
                    self.required_symbols.update(pattern.findall(pl.content))
            self.supply_chain_findings.extend(SupplyChainAndSecretScanner.audit_diff(path, patch))
        self.phase = WorkflowPhase.GRAPH if (self.required_symbols - self.verified_symbols) else WorkflowPhase.ANALYZE

    # ---- stage 3
    def record_symbol_search(self, query: str, results: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        """Record a code search. A symbol is verified only when the search RESULTS were recorded
        (an empty list is valid evidence of zero consumers) and the symbol is a whole word of the query."""
        newly: List[str] = []
        if results is None:
            return newly
        digest = hashlib.sha256(json.dumps(results, sort_keys=True, default=str).encode()).hexdigest()
        for sym in sorted(self.required_symbols):
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(sym)}(?![A-Za-z0-9_])", query):
                self.verified_symbols.add(sym)
                newly.append(sym)
                self.abi_receipts.append({"symbol": sym, "query": query, "result_count": len(results), "results_sha256": digest})
        if self.required_symbols.issubset(self.verified_symbols):
            self.phase = WorkflowPhase.ANALYZE
        return newly

    # ---- stage 5
    def evaluate_write(self, tool_name: str, target_branch: str, action_event: Optional[str] = None,
                       payload_text: Optional[str] = None, debt_report: Optional[TechnicalDebtReport] = None,
                       today: Optional[_dt.date] = None,
                       extra_violations: Optional[List[str]] = None) -> GateDecision:
        mode = self.config.effective_mode(today)
        v: List[str] = list(extra_violations or [])
        unverified = sorted(self.required_symbols - self.verified_symbols)
        privileged = tool_name in {"merge_pull_request"} or action_event == "APPROVE"

        if tool_name in self.BRANCH_WRITE_TOOLS and self.is_protected_branch(target_branch):
            v.append(f"Direct write to protected branch '{self.normalize_branch(target_branch)}' is forbidden.")
        if privileged and not self.file_patches:
            v.append("Review/merge action without ingested PR evidence (phase guard).")
        if unverified and (privileged or tool_name in {"push_files", "git_push", "git_force_push"}):
            v.append(f"Unverified cross-boundary ABI symbols: {', '.join(unverified)}")
        critical = [f for f in self.supply_chain_findings if f.severity == Severity.CRITICAL]
        if critical and privileged:
            v.append(f"Critical supply-chain/secret findings ({', '.join(sorted({f.category for f in critical}))}).")
        if payload_text and tool_name in self.WRITE_TOOLS | {"create_pull_request_review", "add_issue_comment"}:
            leaked = SupplyChainAndSecretScanner.scan_text_for_secrets(payload_text)
            if leaked:
                v.append(f"Outbound payload contains credential pattern(s): {', '.join(leaked)}.")
        if self.injection_alerts and (privileged or tool_name in self.TAINT_BLOCKED_TOOLS):
            v.append(f"Active prompt-injection alert ({len(self.injection_alerts)}) taints privileged write.")
        if action_event == "APPROVE" and self.author_trust not in {TrustLevel.OWNER, TrustLevel.MEMBER, TrustLevel.COLLABORATOR}:
            v.append(f"Auto-approval forbidden for untrusted role {self.author_trust.value}.")
        if debt_report is not None and privileged:
            fast = TechnicalDebtCategory.FAST_INTEGRATION_DEBT in debt_report.detected_debts
            smelly = debt_report.psc_score > self.psc_block_threshold or debt_report.dur_score > 0.0
            if fast and (self.fast_integration_policy == "strict" or smelly):
                why = "failing tests" if debt_report.tests_passed is False else "no tests"
                v.append(f"Fast-integration debt: PSC={debt_report.psc_score:.2f} DUR={debt_report.dur_score:.2f} with {why}.")
            if debt_report.policy_hits:
                v.append(f"House-policy calls in patch ({debt_report.policy_hits}): use structured task/MCP dispatch.")

        facts: Dict[str, Any] = {
            "author_trust": self.author_trust.value, "injection_alerts": len(self.injection_alerts),
            "critical_findings": len(critical), "required_symbols": sorted(self.required_symbols),
            "unverified_symbols": unverified, "phase_before": self.phase.value,
        }
        if debt_report is not None:
            facts.update(psc=debt_report.psc_score, dur=debt_report.dur_score, aup=debt_report.aup_score,
                         aup_measured=debt_report.aup_measured)
        if not v:
            decision, allowed = "PASS", True
        elif mode == EnforcementMode.WARN:
            decision, allowed = "WARN", True
        else:
            decision, allowed = "BLOCK", False
        self.phase = WorkflowPhase.COMMIT if allowed else WorkflowPhase.GATE
        if self.attestor is None:
            gd = GateDecision(allowed, decision, v, tool_name, target_branch, mode, facts)
            gd.signature = self.signer.sign(gd.payload())   # local HMAC: dev fallback, not trusted evidence
            return gd

        # ADR-007: ForgeCore derives the decision and signs. Our verdict above is only the claim.
        claim = {
            "repository": self.repository,
            "tool": self.FORGECORE_TOOL_NAMES.get(tool_name, tool_name),
            "target_ref": target_branch or "unknown",
            "mode": mode.value.lower(),
            "session_id": self.session_id,
            "violations": v[:64],
            "payload_sha256": hashlib.sha256(payload_text.encode()).hexdigest() if payload_text else None,
            "facts": facts,
        }
        try:
            att = self.attestor.attest(claim)
        except ForgeCoreUnavailable as exc:
            facts["attestation"] = "unavailable"
            writes = privileged or tool_name in self.WRITE_TOOLS
            if mode == EnforcementMode.ENFORCE and writes:
                v.append(f"ForgeCore attestation unavailable, failing closed: {exc}")
                self.phase = WorkflowPhase.GATE
                return GateDecision(False, "BLOCK", v, tool_name, target_branch, mode, facts)
            v.append(f"ForgeCore attestation unavailable (WARN mode): {exc}")
            return GateDecision(True, "WARN" if decision == "PASS" else decision, v, tool_name, target_branch, mode, facts)

        kernel_v = [str(x) for x in att.get("kernel_violations", [])]
        kdecision = att["decision"]
        allowed = kdecision != "BLOCK"
        self.phase = WorkflowPhase.COMMIT if allowed else WorkflowPhase.GATE
        gd = GateDecision(allowed, kdecision, v + kernel_v, tool_name, target_branch, mode, facts,
                          signature=att.get("signature"), attestation=att)
        return gd

    def verify_and_gate_write(self, tool_name: str, target_branch: str, action_event: Optional[str] = None,
                              payload_text: Optional[str] = None,
                              debt_report: Optional[TechnicalDebtReport] = None) -> Tuple[bool, str]:
        """v5-compatible wrapper around evaluate_write()."""
        gd = self.evaluate_write(tool_name, target_branch, action_event, payload_text, debt_report)
        if gd.decision == "PASS":
            return True, "PASS"
        return gd.allowed, f"{gd.decision}: " + " | ".join(gd.violations)

    # ---- CI logs
    ERROR_MARKER_RE = re.compile(
        r"(error\[E\d+\]|^\s*error(?:\[[^\]]*\])?:|:\d+:\d+:\s*(?:fatal\s+)?error:|error TS\d+|npm ERR!|^e:\s|"
        r"FAILURE:|BUILD FAILED|Exception in thread|Traceback \(most recent call last\)|panicked at|"
        r"^FAILED\s|fatal:|exit code [1-9]|ld: symbol\(s\) not found|undefined reference to|Execution failed for task)",
        re.I | re.M,
    )

    @classmethod
    def truncate_ci_log(cls, raw_log: str, max_total_lines: int = 220, tail_lines: int = 40) -> str:
        """Window a CI log: FIRST error window (root cause) first, then later windows, then the tail."""
        lines = [ln[:-1] if ln.endswith("\r") else ln for ln in raw_log.split("\n")]
        if lines and lines[-1] == "":
            lines.pop()
        if len(lines) <= max_total_lines:
            return raw_log
        intervals: List[List[int]] = []
        for idx, line in enumerate(lines):
            if cls.ERROR_MARKER_RE.search(line):
                start, end = max(0, idx - 15), min(len(lines), idx + 35)
                if intervals and start <= intervals[-1][1]:
                    intervals[-1][1] = max(intervals[-1][1], end)
                else:
                    intervals.append([start, end])
        tail_start = max(0, len(lines) - tail_lines)
        if not intervals:
            return f"[... {len(lines) - max_total_lines} earlier lines elided ...]\n" + "\n".join(lines[-max_total_lines:])

        budget = max_total_lines - tail_lines - 1  # one line reserved for the elision marker before the tail
        chosen: List[Tuple[int, int]] = []
        used = 0
        order = [intervals[0]] + intervals[1:][::-1]  # root cause first, then most recent
        for start, end in order:
            end = min(end, tail_start)
            if start >= end:
                continue
            take = min(end - start, budget - used - 1)  # each window may need its own marker
            if take <= 5:
                break
            chosen.append((start, start + take))
            used += take + 1
        chosen.sort()
        out: List[str] = []
        cursor = 0
        for start, end in chosen + [(tail_start, len(lines))]:
            if start > cursor:
                out.append(f"[... {start - cursor} lines elided ...]")
            out.extend(lines[max(start, cursor):end])
            cursor = max(cursor, end)
        return "\n".join(out)


# --------------------------------------------------------------------------- self-test

if __name__ == "__main__":
    cfg = GemConfig(deployment_id="accounts/demo/deployments/demo", mode=EnforcementMode.ENFORCE)
    mon = StatefulGitHubOpsMonitor(author_trust=TrustLevel.COLLABORATOR, config=cfg)
    mon.ingest_pull_request_files([{"filename": "native/bridge.cpp", "patch":
        "@@ -10,2 +10,2 @@\n-JNIEXPORT jint JNICALL Java_com_app_Core_step(JNIEnv* e)\n+JNIEXPORT jlong JNICALL Java_com_app_Core_step(JNIEnv* e)\n"}])
    ok, msg = mon.verify_and_gate_write("merge_pull_request", "feat/jni")
    assert not ok and "Java_com_app_Core_step" in msg
    mon.record_symbol_search("Java_com_app_Core_step")              # no results recorded -> not verified
    assert not mon.verify_and_gate_write("merge_pull_request", "feat/jni")[0]
    mon.record_symbol_search("Java_com_app_Core_step", results=[{"path": "app/src/Core.kt"}])
    assert mon.verify_and_gate_write("merge_pull_request", "feat/jni")[0]

    ds = DeepSeekProtocolSanitizer(max_identical_retries=2)
    cleaned, count = ds.strip_reasoning_tokens("<think>internal trace</think>{\"status\":\"ok\"}")
    assert count == 1 and "<think>" not in cleaned
    _, calls = ds.repair_xml_tool_calls("Running check:\n<execute_bash>git status -sb</execute_bash>", allowed_tools={"Bash"})
    assert len(calls) == 1 and calls[0]["name"] == "Bash" and calls[0]["input"]["command"] == "git status -sb"
    _, calls, rejected = ds.repair_tool_calls_detailed("<execute_bash>git status -sb</execute_bash>")
    assert calls == [] and rejected[0]["name"] == "Bash"
    assert ds.route_and_check_circuit_breaker("Grep", 1200, "grep_foo")["target_model"] == "local-fast-tier"
    assert "deployments" in ds.route_and_check_circuit_breaker("Edit", 8000, "edit_bar")["target_model"]

    receipt = ATRIZInnovationEngine.synthesize_triza_mutation("perspective_diversity", "sycophancy_bloat",
                                                              "+val sandbox = OrthogonalSubspace()", [10.0, 8.0], [2.0], [0.5])
    assert receipt.ideality_score == 7.2
    assert ATRIZInnovationEngine.compute_rice(100, 3.0, 0.9, 2.0) == 135.0
    assert ATRIZInnovationEngine.compute_lats_uct(0.85, 20, 4) > 1.0
    assert FMEARecord("Unstripped <think> corrupts tool JSON", 9, 6, 4).rpn == 216

    td = LLMTechnicalDebtSensor.evaluate_patch("@@ -1,2 +1,4 @@\n+except Exception:\n+    pass\n+datetime.utcnow()\n", False, True, True)
    assert td.psc_score > 0 and td.dur_score > 0 and TechnicalDebtCategory.FAST_INTEGRATION_DEBT in td.detected_debts
    print(f"gemcore {__version__} self-tests passed.")
