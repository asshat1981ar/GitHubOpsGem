"""Input budget, tool-call repair and the conformance harness (gem-v5.8 additions ported in GC-001).

Runs without LiteLLM: the pre-call hook, dict-shaped responses and Anthropic SSE byte streams need no LiteLLM types.
"""
import asyncio
import os
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)

import conformance_check as cc  # noqa: E402
import gem_guardrail as gg  # noqa: E402


def pre(guard, data):
    return asyncio.run(guard.async_pre_call_hook({}, None, data, "completion"))


def post(guard, response):
    return asyncio.run(guard.async_post_call_success_hook({}, {}, response))


# ---------------------------------------------------------------- pre-call budget and loop breaker

def test_pre_call_rejects_over_budget_with_anthropic_error():
    guard = gg.GemGuardrail(input_budget_tokens=96000)
    with pytest.raises(gg.AnthropicContextError, match="Context budget exceeded") as info:
        pre(guard, {"messages": [{"role": "user", "content": "a" * (96010 * 4)}]})
    assert info.value.status_code == 400
    assert info.value.anthropic_payload["error"]["type"] == "invalid_request_error"
    assert guard.rejected_requests == 1


def test_pre_call_counts_system_and_tools_and_content_blocks():
    guard = gg.GemGuardrail(input_budget_tokens=1000)
    data = {"system": "s" * 2000, "tools": [{"name": "Read", "description": "d" * 1000}],
            "messages": [{"role": "user", "content": [{"type": "text", "text": "t" * 1200}]}]}
    with pytest.raises(gg.AnthropicContextError):
        pre(guard, data)


def test_pre_call_passes_small_request_through_unchanged():
    guard = gg.GemGuardrail(input_budget_tokens=96000)
    data = {"messages": [{"role": "user", "content": "short prompt"}], "_gem_call_signature": "sig1"}
    assert pre(guard, data) is data


def test_pre_call_loop_breaker_trips_after_two_identical_failures():
    guard = gg.GemGuardrail(input_budget_tokens=96000)
    guard.sanitizer.record_result("sig_fail", False)
    guard.sanitizer.record_result("sig_fail", False)
    with pytest.raises(gg.AnthropicContextError, match="Loop circuit breaker tripped"):
        pre(guard, {"messages": [], "_gem_call_signature": "sig_fail"})


def test_input_budget_comes_from_env(monkeypatch):
    monkeypatch.setenv("GEM_INPUT_BUDGET_TOKENS", "10")
    guard = gg.GemGuardrail()
    assert guard.input_budget_tokens == 10
    monkeypatch.setenv("GEM_INPUT_BUDGET_TOKENS", "not-a-number")
    assert gg.GemGuardrail().input_budget_tokens == gg.DEFAULT_INPUT_BUDGET_TOKENS


# ---------------------------------------------------------------- tool-call repair (non-streaming)

def test_openai_response_repairs_allowlisted_tool_only():
    guard = gg.GemGuardrail()
    resp = {"choices": [{"message": {"content": 'Searching. <tool_call>{"name": "Grep", "input": {"pattern": "foo"}}'
                                                "</tool_call>"}, "finish_reason": "stop"}]}
    post(guard, resp)
    msg = resp["choices"][0]["message"]
    assert msg["content"] == "Searching."
    assert [c["function"]["name"] for c in msg["tool_calls"]] == ["Grep"]
    assert msg["tool_calls"][0]["type"] == "function"
    assert resp["choices"][0]["finish_reason"] == "tool_calls"


def test_openai_response_never_emits_privileged_tool():
    guard = gg.GemGuardrail()
    resp = {"choices": [{"message": {"content": "<execute_bash>rm -rf /</execute_bash>"}, "finish_reason": "stop"}]}
    post(guard, resp)
    msg = resp["choices"][0]["message"]
    assert not msg.get("tool_calls")
    assert "GEM_GUARDRAIL: blocked" in msg["content"] and "Bash" in msg["content"]
    assert "rm -rf" not in msg["content"]
    assert resp["choices"][0]["finish_reason"] == "stop"
    assert guard.blocked_repairs == 1


def test_anthropic_message_gets_tool_use_block_after_think_strip():
    guard = gg.GemGuardrail()
    resp = {"type": "message", "stop_reason": "end_turn", "content": [
        {"type": "text", "text": '<think>plan</think>ok <tool_call>{"name": "Read", "input": {"file_path": "a"}}'
                                 "</tool_call>"}]}
    post(guard, resp)
    assert resp["content"][0]["text"] == "ok"
    assert resp["content"][1]["type"] == "tool_use" and resp["content"][1]["name"] == "Read"
    assert resp["stop_reason"] == "tool_use"


def test_plain_text_is_left_exactly_as_is():
    guard = gg.GemGuardrail()
    resp = {"choices": [{"message": {"content": "  plain text, no markup  "}}]}
    assert post(guard, resp) is None
    assert resp["choices"][0]["message"]["content"] == "  plain text, no markup  "


def test_repair_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("GEM_GUARDRAIL_TOOL_REPAIR", "0")
    guard = gg.GemGuardrail()
    text = '<tool_call>{"name": "Grep", "input": {"pattern": "foo"}}</tool_call>'
    resp = {"choices": [{"message": {"content": text}}]}
    post(guard, resp)
    assert resp["choices"][0]["message"]["content"] == text
    assert not resp["choices"][0]["message"].get("tool_calls")


# ---------------------------------------------------------------- streaming never promotes text to a tool call

def test_stream_keeps_leaked_tool_markup_as_text():
    events = cc.run_stream(gg.GemGuardrail(), cc._message(["Run: <execute_", "bash>git push --force</execute_bash>"]))
    assert not [e for e in events if e.get("type") == "content_block_start"
                and e.get("content_block", {}).get("type") == "tool_use"]
    assert "git push --force" in cc.visible_text(events)


# ---------------------------------------------------------------- harness

def test_conformance_harness_passes_6_of_6():
    assert cc.main([]) == 0


def test_harness_check_1_catches_a_leak():
    class NoStrip(gg.GemGuardrail):
        def __init__(self):
            super().__init__()
            self.filter_cls = None
    original = cc.gg.GemGuardrail
    cc.gg.GemGuardrail = NoStrip
    try:
        ok, _ = cc.check_1_stream_think_strip_20()
    finally:
        cc.gg.GemGuardrail = original
    assert ok is False


def test_harness_cli_exit_code():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "gateway", "conformance_check.py"), "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert '"passed": 6' in r.stdout
