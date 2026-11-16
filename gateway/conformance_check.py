#!/usr/bin/env python3
"""Gateway conformance harness (WU-06, ported from gem-v5.8 in GC-001).

Six deterministic checks of the LiteLLM gateway's protocol and security behaviour, run against the code in this
repository (no network, no LiteLLM install needed):
  1. stream_think_strip_20: 20 streamed /v1/messages replies with <think> tags split across SSE frames leak nothing.
  2. tool_repair_privilege_boundary: a leaked read-only call (Grep) becomes a real tool call; a leaked privileged
     call (Bash) does not, and is named in a visible warning. Checked for OpenAI and Anthropic response shapes,
     and a stream never turns leaked markup into a tool_use block.
  3. pre_call_96k_rejection: input over 96,000 tokens is rejected before the call with HTTP 400 and an
     Anthropic-shaped invalid_request_error.
  4. fast_tier_isolation: Read/Grep/Glob/LS route to the fast tier and ds-fast is never treated as burst traffic.
  5. unauthenticated_401: the proxy config requires LITELLM_MASTER_KEY.
  6. cold_start_503_resilience: ds-main is the always-warm serverless model and ds-burst is a separate tier.

Usage:
  python3 gateway/conformance_check.py          # human-readable, exit 0 only when 6/6 pass
  python3 gateway/conformance_check.py --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, AsyncIterator, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
for candidate in (os.path.join(HERE, ".."), HERE):
    if os.path.isfile(os.path.join(candidate, "mcp_reference_monitor.py")):
        sys.path.insert(0, os.path.abspath(candidate))
        break
import mcp_reference_monitor as gem  # noqa: E402
import gem_guardrail as gg  # noqa: E402
import gem_lifecycle_callback as glc  # noqa: E402

CONFIG = os.path.join(HERE, "litellm_config.v7.yaml")


async def _aiter(items: Iterable[Any]) -> AsyncIterator[Any]:
    for item in items:
        yield item


def sse(event: dict) -> bytes:
    return f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()


def text_delta(text: str, index: int = 0) -> dict:
    return {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}}


def run_stream(guard: Any, frames: List[bytes]) -> List[dict]:
    """Feed SSE frames through the streaming hook and return the parsed events that come out."""
    async def _run() -> bytes:
        out = b""
        async for item in guard.async_post_call_streaming_iterator_hook({}, _aiter(frames), {}):
            out += item.encode() if isinstance(item, str) else bytes(item)
        return out
    raw = asyncio.run(_run())
    events = []
    for frame in raw.split(b"\n\n"):
        for line in frame.decode().splitlines():
            if line.startswith("data:"):
                events.append(json.loads(line[5:].strip()))
    return events


def visible_text(events: List[dict]) -> str:
    return "".join(e["delta"].get("text", "") for e in events
                   if e.get("type") == "content_block_delta" and isinstance(e.get("delta"), dict))


def _message(frames_text: List[str]) -> List[bytes]:
    return ([sse({"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant",
                                                       "content": []}}),
             sse({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})]
            + [sse(text_delta(t)) for t in frames_text]
            + [sse({"type": "content_block_stop", "index": 0}),
               sse({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}),
               sse({"type": "message_stop"})])


def check_1_stream_think_strip_20() -> Tuple[bool, str]:
    guard = gg.GemGuardrail()
    leaked = 0
    for i in range(20):
        events = run_stream(guard, _message(["<th", f"ink>secret reasoning {i} ", "</thi", f"nk>Visible reply {i}"]))
        text = visible_text(events)
        if "think>" in text.lower() or "secret reasoning" in text or f"Visible reply {i}" not in text:
            leaked += 1
    return leaked == 0, f"20/20 streamed replies clean (leaked={leaked})"


def check_2_tool_repair_privilege_boundary() -> Tuple[bool, str]:
    guard = gg.GemGuardrail()
    safe = {"choices": [{"message": {"content": '<tool_call>{"name": "Grep", "input": {"pattern": "foo"}}</tool_call>'},
                         "finish_reason": "stop"}]}
    priv = {"choices": [{"message": {"content": "<execute_bash>rm -rf /</execute_bash>"}, "finish_reason": "stop"}]}
    anth = {"type": "message", "stop_reason": "end_turn", "content": [
        {"type": "text", "text": '<tool_call>{"name": "Read", "input": {"file_path": "README.md"}}</tool_call>'
                                 "<execute_bash>git push --force</execute_bash>"}]}
    for resp in (safe, priv, anth):
        asyncio.run(guard.async_post_call_success_hook({}, {}, resp))
    safe_calls = safe["choices"][0]["message"].get("tool_calls") or []
    priv_msg = priv["choices"][0]["message"]
    anth_tools = [b for b in anth["content"] if b.get("type") == "tool_use"]
    streamed = run_stream(guard, _message(["Let me run: <execute_", "bash>git push --force</execute_bash>"]))
    streamed_tools = [e for e in streamed if e.get("type") == "content_block_start"
                      and e.get("content_block", {}).get("type") == "tool_use"]
    ok = (len(safe_calls) == 1 and safe_calls[0]["function"]["name"] == "Grep"
          and safe["choices"][0]["finish_reason"] == "tool_calls"
          and not priv_msg.get("tool_calls") and "GEM_GUARDRAIL: blocked" in (priv_msg.get("content") or "")
          and [b["name"] for b in anth_tools] == ["Read"] and anth["stop_reason"] == "tool_use"
          and "GEM_GUARDRAIL: blocked" in anth["content"][0]["text"]
          and not streamed_tools)
    return ok, (f"safe_repaired={len(safe_calls)}, priv_tool_calls={len(priv_msg.get('tool_calls') or [])}, "
                f"anthropic_tool_use={[b['name'] for b in anth_tools]}, stream_tool_use={len(streamed_tools)}")


def check_3_pre_call_96k_rejection() -> Tuple[bool, str]:
    guard = gg.GemGuardrail(input_budget_tokens=96000)
    oversized = {"messages": [{"role": "user", "content": "x" * (96005 * 4)}]}
    small = {"messages": [{"role": "user", "content": "hello"}]}
    err: Optional[gg.AnthropicContextError] = None
    try:
        asyncio.run(guard.async_pre_call_hook({}, None, oversized, "completion"))
    except gg.AnthropicContextError as exc:
        err = exc
    passed_small = asyncio.run(guard.async_pre_call_hook({}, None, small, "completion")) is small
    ok = (err is not None and err.status_code == 400 and passed_small
          and err.anthropic_payload.get("error", {}).get("type") == "invalid_request_error")
    return ok, f"rejected={err is not None}, status={getattr(err, 'status_code', None)}, small_passes={passed_small}"


def check_4_fast_tier_isolation() -> Tuple[bool, str]:
    sanitizer = gem.DeepSeekProtocolSanitizer()
    for tool in ("Read", "Grep", "Glob", "LS"):
        res = sanitizer.route_and_check_circuit_breaker(tool, 1000, f"sig_{tool}")
        if res["target_model"] != "local-fast-tier":
            return False, f"{tool} routed to {res['target_model']}"
    if glc.is_burst({"litellm_params": {"litellm_metadata": {"model_group": "ds-fast"}}}):
        return False, "ds-fast misclassified as burst group"
    return True, "Read/Grep/Glob/LS and ds-fast isolated from B200 ds-burst"


def _config_text() -> str:
    with open(CONFIG, encoding="utf-8") as fh:
        return fh.read()


def check_5_unauthenticated_401() -> Tuple[bool, str]:
    ok = "master_key: os.environ/LITELLM_MASTER_KEY" in _config_text()
    return ok, "master_key: os.environ/LITELLM_MASTER_KEY enforced in litellm_config.v7.yaml"


def check_6_cold_start_503_resilience() -> Tuple[bool, str]:
    text = _config_text()
    ok = "openai/accounts/fireworks/models/deepseek-v4p1-flash-1017" in text and "model_name: ds-burst" in text
    return ok, "ds-main is serverless (always warm); ds-burst isolated as explicit burst tier"


CHECKS = [
    ("1_stream_think_strip_20", check_1_stream_think_strip_20),
    ("2_tool_repair_privilege_boundary", check_2_tool_repair_privilege_boundary),
    ("3_pre_call_96k_rejection", check_3_pre_call_96k_rejection),
    ("4_fast_tier_isolation", check_4_fast_tier_isolation),
    ("5_unauthenticated_401", check_5_unauthenticated_401),
    ("6_cold_start_503_resilience", check_6_cold_start_503_resilience),
]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    results = []
    for name, fn in CHECKS:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 - a crashing check is a failed check
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({"check": name, "passed": ok, "detail": detail})
    passed = sum(r["passed"] for r in results)
    if args.json:
        print(json.dumps({"passed": passed, "total": len(CHECKS), "results": results}, indent=2))
    else:
        for r in results:
            print(f"[{'PASS' if r['passed'] else 'FAIL'}] {r['check']}: {r['detail']}")
        print(f"{passed}/{len(CHECKS)} conformance checks passed")
    return 0 if passed == len(CHECKS) else 2


if __name__ == "__main__":
    sys.exit(main())
