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
"""

from __future__ import annotations

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

    # Attacker-controllable contexts (GitHub security hardening guide + common sinks).
    UNTRUSTED_CONTEXT_RE = re.compile(
        r"github\.head_ref"
        r"|github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment"
        r"|commits|head_commit|pages|workflow_run|merge_group)\b[^}]*"
        r"(?:title|body|message|ref|label|name|email|head_branch|page_name|default_branch)",
        re.IGNORECASE,
    )
    EXPRESSION_RE = re.compile(r"\$\{\{(?P<expr>.*?)\}\}")
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
    def audit_diff(cls, file_path: str, patch_text: str) -> List[InlineFinding]:
        findings: List[InlineFinding] = []
        is_workflow = bool(cls.WORKFLOW_PATH_RE.search(file_path))
        adds = added_lines(patch_text)
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
            stripped = pl.content.strip().lstrip("- ")
            if stripped.startswith(("if:", "name:")):
                continue  # expressions in if:/name: are not shell-interpolated
            for em in cls.EXPRESSION_RE.finditer(pl.content):
                if cls.UNTRUSTED_CONTEXT_RE.search(em.group("expr")):
                    findings.append(InlineFinding(
                        file_path, line_no, Severity.CRITICAL, "CWE-94_WORKFLOW_INJECTION",
                        f"Untrusted context `${{{{{em.group('expr').strip()}}}}}` interpolated inline. Bind it via `env:` and quote the variable."))
                    break
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

    def __init__(self, assume_open: bool = False) -> None:
        self.inside = assume_open
        self.buf = ""
        self.stripped_blocks = 0

    def feed(self, chunk: str) -> str:
        self.buf += chunk
        out: List[str] = []
        while True:
            low = self.buf.lower()
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
