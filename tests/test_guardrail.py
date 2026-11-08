"""Tests for the WU-05 think-strip guardrail (gateway/gem_guardrail.py) against real LiteLLM 1.108.2 types."""
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

litellm = pytest.importorskip("litellm")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)

import gem_guardrail as gg  # noqa: E402
import mcp_reference_monitor as m  # noqa: E402
from litellm.llms.anthropic.pass_through.adapters.handler import ANTHROPIC_ADAPTER  # noqa: E402
from litellm.types.utils import (  # noqa: E402
    ChatCompletionMessageToolCall, Choices, Delta, Message, ModelResponse, ModelResponseStream, StreamingChoices)

CONFIG = os.path.join(ROOT, "gateway", "litellm_config.v7.yaml")


# ---------------------------------------------------------------- helpers

class Upstream:
    """Async iterable over fixed items; optionally raises after them (an upstream failure)."""

    def __init__(self, items, error=None):
        self.items, self.error = list(items), error

    def __aiter__(self):
        async def gen():
            for item in self.items:
                yield item
            if self.error is not None:
                raise self.error
        return gen()


def chunk(content=None, finish=None, index=0, **delta):
    return ModelResponseStream(id="chatcmpl-1", model="ds-main", created=1, choices=[
        StreamingChoices(index=index, delta=Delta(content=content, **delta), finish_reason=finish)])


def text_chunks(text, size):
    return [chunk(text[i:i + size]) for i in range(0, len(text), size)]


def run(guard, items):
    async def go():
        return [c async for c in guard.async_post_call_streaming_iterator_hook(None, Upstream(items), {})]
    return asyncio.run(go())


def content_of(chunks, index=0):
    return "".join(c.delta.content or "" for ch in chunks for c in ch.choices if c.index == index)


def args_of(chunks, call_index):
    return "".join(t.function.arguments or "" for ch in chunks for c in ch.choices
                   for t in (c.delta.tool_calls or []) if t.index == call_index)


def sse_events(chunks):
    raw = b"".join(c if isinstance(c, bytes) else c.encode() for c in chunks)
    out = []
    for frame in raw.split(b"\n\n"):
        if frame.strip():
            lines = frame.decode().split("\n")
            name = next(line[7:] for line in lines if line.startswith("event: "))
            data = json.loads(next(line[6:] for line in lines if line.startswith("data: ")))
            assert name == data["type"]
            out.append(data)
    return out


def sse_text(events, kind="text_delta", field="text"):
    by_index = {}
    for ev in events:
        if ev["type"] == "content_block_delta" and ev["delta"]["type"] == kind:
            by_index[ev["index"]] = by_index.get(ev["index"], "") + ev["delta"][field]
    return by_index


def assert_well_formed(events):
    open_blocks, stopped = set(), False
    for ev in events:
        assert not stopped, "frame after message_stop"
        if ev["type"] == "content_block_start":
            open_blocks.add(ev["index"])
        elif ev["type"] == "content_block_delta":
            assert ev["index"] in open_blocks
        elif ev["type"] == "content_block_stop":
            open_blocks.remove(ev["index"])
        elif ev["type"] == "message_stop":
            stopped = True
    assert not open_blocks and stopped


def anthropic_stream(chat_chunks):
    """The exact /v1/messages transformation LiteLLM 1.108.2 applies to an OpenAI-format backend."""
    async def go():
        return [c async for c in ANTHROPIC_ADAPTER.translate_completion_output_params_streaming(
            Upstream(chat_chunks), model="ds-main")]
    return asyncio.run(go())


class ExplodingFilter(m.ThinkStreamFilter):
    calls = 0

    def feed(self, chunk):
        ExplodingFilter.calls += 1
        if ExplodingFilter.calls == 3:
            raise RuntimeError("boom")
        return super().feed(chunk)


@pytest.fixture
def guard():
    return gg.GemGuardrail()


# ---------------------------------------------------------------- gemcore ThinkStreamFilter fix

def test_filter_case_fold_keeps_indices_aligned():
    # str.lower() turns "İ" into two code points, which used to leak "<think>SECRE" and eat the visible tail.
    text = "İ" * 12 + "<think>SECRET plan</think> ok"
    for size in (1, 3, len(text)):
        f = m.ThinkStreamFilter()
        out = "".join(f.feed(text[i:i + size]) for i in range(0, len(text), size)) + f.flush()
        assert out == "İ" * 12 + " ok" and f.stripped_blocks == 1


# ---------------------------------------------------------------- OpenAI-format streams

SPLIT_TEXT = "<think>plan the edit</think>Hello <think>more\nthought</think>world!"


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, len(SPLIT_TEXT)])
def test_split_tags_across_chunk_boundaries(guard, size):
    items = text_chunks(SPLIT_TEXT, size) + [chunk(finish="stop")]
    out = run(guard, items)
    assert content_of(out) == "Hello world!"
    assert len(out) == len(items)                    # one chunk out per chunk in, nothing withheld or invented
    assert guard.stripped_blocks == 2 and guard.errors == 0


def test_mixed_case_tags(guard):
    out = run(guard, text_chunks("a<THINK>x</Think>b<tHiNk>y</THINK>c", 2) + [chunk(finish="stop")])
    assert content_of(out) == "abc"


def test_multiple_blocks_in_one_stream(guard):
    text = "".join(f"<think>t{i}</think>v{i} " for i in range(5))
    out = run(guard, text_chunks(text, 4) + [chunk(finish="stop")])
    assert content_of(out) == "v0 v1 v2 v3 v4 " and guard.stripped_blocks == 5


def test_think_block_at_stream_start(guard):
    out = run(guard, [chunk("<think>", role="assistant"), chunk("reasoning"), chunk("</think>"), chunk("Answer"),
                      chunk(finish="stop")])
    assert [c.choices[0].delta.content for c in out] == ["", "", "", "Answer", None]
    assert out[0].choices[0].delta.role == "assistant"


def test_never_holds_more_than_a_partial_tag(guard):
    text = "visible <b> " * 10 + "<think>" + "hidden " * 20 + "</think>" + "after " * 20
    stream = gg._Stream(guard)
    emitted = ""
    for i, ch in enumerate(text):
        emitted += stream.process(chunk(ch))[0].choices[0].delta.content
        ideal = re.sub(r"<think>.*?(</think>|$)", "", text[: i + 1], flags=re.S | re.I)  # all visible so far
        assert ideal.startswith(emitted) and len(ideal) - len(emitted) <= len("</think>") - 1
    assert emitted + content_of(stream.finish()) == "visible <b> " * 10 + "after " * 20


def test_partial_tag_tail_goes_out_with_finish_chunk(guard):
    out = run(guard, [chunk("price <"), chunk(finish="stop")])
    assert content_of(out) == "price <" and out[-1].choices[0].finish_reason == "stop"


def test_partial_tag_tail_without_finish_gets_its_own_chunk(guard):
    out = run(guard, [chunk("a <thi")])
    assert content_of(out) == "a <thi" and len(out) == 2 and out[1].id == "chatcmpl-1"


def test_unclosed_think_block_is_dropped_at_stream_end(guard):
    out = run(guard, [chunk("ok <think>never closed"), chunk(finish="stop")])
    assert content_of(out) == "ok " and guard.stripped_blocks == 1


def test_tool_call_deltas_and_reasoning_pass_through_unchanged(guard):
    items = [
        chunk(role="assistant", reasoning_content="<think>native reasoning</think>"),
        chunk(tool_calls=[{"index": 0, "id": "call_1", "type": "function",
                           "function": {"name": "Bash", "arguments": ""}}]),
        chunk(tool_calls=[{"index": 0, "function": {"arguments": '{"command": "ls -la'}}]),
        chunk(tool_calls=[{"index": 0, "function": {"arguments": ' < in.txt"}'}}]),
        chunk(finish="tool_calls"),
    ]
    before = [c.model_dump() for c in items]
    out = run(guard, items)
    assert [c.model_dump() for c in out] == before
    assert out[0].choices[0].delta.reasoning_content == "<think>native reasoning</think>"
    assert args_of(out, 0) == '{"command": "ls -la < in.txt"}' and out[1].choices[0].delta.tool_calls[0].id == "call_1"


def test_think_inside_tool_arguments_stripped_per_call(guard):
    items = [
        chunk(tool_calls=[{"index": 0, "id": "a", "type": "function", "function": {"name": "Read", "arguments": '{"p": "x<thi'}},
                          {"index": 1, "id": "b", "type": "function", "function": {"name": "Grep", "arguments": '{"q": "y<'}}]),
        chunk(tool_calls=[{"index": 0, "function": {"arguments": 'nk>zz</think>1"}'}},
                          {"index": 1, "function": {"arguments": 'think>w</think>2"}'}}]),
        chunk(finish="tool_calls"),
    ]
    out = run(guard, items)
    assert json.loads(args_of(out, 0)) == {"p": "x1"} and json.loads(args_of(out, 1)) == {"q": "y2"}
    assert guard.stripped_blocks == 2


def test_tool_argument_stripping_can_be_disabled(monkeypatch):
    monkeypatch.setenv("GEM_GUARDRAIL_TOOL_ARGS", "0")
    out = run(gg.GemGuardrail(), [chunk(tool_calls=[{"index": 0, "id": "a", "type": "function",
                                                     "function": {"name": "Bash", "arguments": '{"c": "<think>"}'}}])])
    assert args_of(out, 0) == '{"c": "<think>"}'


def test_stream_is_never_stalled(guard):
    """Each upstream chunk is answered before the next one exists."""
    async def go():
        queue = asyncio.Queue()

        async def upstream():
            while (item := await queue.get()) is not None:
                yield item
        hook = guard.async_post_call_streaming_iterator_hook(None, upstream(), {}).__aiter__()
        got = []
        for piece in ["<thi", "nk>x</th", "ink>vis", "ible"]:
            await queue.put(chunk(piece))
            got.append((await asyncio.wait_for(hook.__anext__(), 1)).choices[0].delta.content)
        await queue.put(None)
        return got + [c.choices[0].delta.content async for c in hook]
    assert asyncio.run(go()) == ["", "", "vis", "ible"]


# ---------------------------------------------------------------- Anthropic /v1/messages streams

def anthropic_fixture():
    return [
        chunk("<think>plan</think>Hel", role="assistant"),
        chunk("lo <THI"), chunk("NK>more</think>there <"),
        chunk(reasoning_content="<think>structured</think>"),
        chunk(tool_calls=[{"index": 0, "id": "toolu_1", "type": "function", "function": {"name": "Bash", "arguments": ""}}]),
        chunk(tool_calls=[{"index": 0, "function": {"arguments": '{"command": "ls <thi'}}]),
        chunk(tool_calls=[{"index": 0, "function": {"arguments": 'nk>no</think>-la"}'}}]),
        chunk(finish="tool_calls"),
    ]


def test_anthropic_messages_sse_bytes(guard):
    upstream = anthropic_stream(anthropic_fixture())
    assert all(isinstance(c, bytes) for c in upstream)                  # 1.108.2: one SSE frame per bytes chunk
    events = sse_events(run(guard, upstream))
    assert_well_formed(events)
    assert sse_text(events) == {0: "Hello there <"}
    assert sse_text(events, "thinking_delta", "thinking") == {1: "<think>structured</think>"}
    assert json.loads(sse_text(events, "input_json_delta", "partial_json")[2]) == {"command": "ls -la"}
    assert not [e for e in events if e["type"] == "content_block_delta"
                and (e["delta"].get("text") == "" or e["delta"].get("partial_json") == "")]
    assert guard.stripped_blocks == 3


def test_anthropic_sse_tail_flushed_before_block_stop(guard):
    events = sse_events(run(guard, anthropic_stream([chunk("a <"), chunk(finish="stop")])))
    kinds = [(e["type"], e.get("delta", {}).get("text")) for e in events]
    assert kinds.index(("content_block_delta", "<")) == kinds.index(("content_block_stop", None)) - 1


def test_anthropic_sse_frames_split_across_byte_chunks(guard):
    raw = b"".join(anthropic_stream(anthropic_fixture()))
    pieces = [raw[i:i + 7] for i in range(0, len(raw), 7)]
    events = sse_events(run(guard, pieces))
    assert_well_formed(events)
    assert sse_text(events) == {0: "Hello there <"}


def test_anthropic_dict_events(guard):
    events = [{"type": "message_start", "message": {"content": []}},
              {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
              {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "<think>x</th"}},
              {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ink>Done"}},
              {"type": "content_block_stop", "index": 0}, {"type": "message_stop"}]
    out = run(guard, events)
    assert all(isinstance(e, dict) for e in out) and sse_text(out) == {0: "Done"}
    assert events[3]["delta"]["text"] == "ink>Done"                     # originals are not mutated


# ---------------------------------------------------------------- fail open

def test_filter_exception_passes_original_chunks_through(guard):
    ExplodingFilter.calls = 0
    guard.filter_cls = ExplodingFilter
    items = [chunk("<think>a"), chunk("b</think>c"), chunk("<think>d</think>"), chunk("e"), chunk(finish="stop")]
    snapshot = [c.choices[0].delta.content for c in items]
    out = run(guard, items)
    assert [c.choices[0].delta.content for c in out[2:]] == snapshot[2:]   # untouched from the failing chunk on
    assert out[2] is items[2] and guard.errors == 1


def test_filter_exception_on_sse_route_passes_bytes_through(guard):
    ExplodingFilter.calls = 0
    guard.filter_cls = ExplodingFilter
    upstream = anthropic_stream([chunk("<think>a"), chunk("b</think>c"), chunk("<think>d</think>"), chunk("e"),
                                 chunk(finish="stop")])
    out = run(guard, upstream)
    assert b"".join(out).endswith(b"".join(upstream[4:])) and guard.errors == 1
    assert_well_formed(sse_events(out))


def test_upstream_errors_still_propagate(guard):
    async def go():
        async for _ in guard.async_post_call_streaming_iterator_hook(None, Upstream([chunk("x")], ValueError("up")), {}):
            pass
    with pytest.raises(ValueError, match="up"):
        asyncio.run(go())


# ---------------------------------------------------------------- non-streaming

def test_non_streaming_chat_response(guard):
    resp = ModelResponse(choices=[Choices(index=0, finish_reason="tool_calls", message=Message(
        role="assistant", content="<think>why</think>Answer <THINK>b</think>done",
        reasoning_content="<think>native</think>",
        tool_calls=[ChatCompletionMessageToolCall(id="c1", type="function", function={
            "name": "Bash", "arguments": '{"command": "ls<think>no</think> -la"}'})]))])
    out = asyncio.run(guard.async_post_call_success_hook({}, None, resp))
    msg = out.choices[0].message
    assert msg.content == "Answer done" and msg.reasoning_content == "<think>native</think>"
    assert msg.tool_calls[0].function.arguments == '{"command": "ls -la"}' and guard.stripped_blocks == 3


def test_non_streaming_anthropic_message(guard):
    resp = {"id": "msg_1", "type": "message", "role": "assistant", "content": [
        {"type": "thinking", "thinking": "<think>keep</think>", "signature": ""},
        {"type": "text", "text": "<think>plan</think>Hi"},
        {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls <think>x</think>-la"}}]}
    out = asyncio.run(guard.async_post_call_success_hook({}, None, resp))
    assert [b.get("text") or b.get("thinking") or b.get("input") for b in out["content"]] == [
        "<think>keep</think>", "Hi", {"command": "ls -la"}]


def test_non_streaming_untouched_and_fail_open(guard):
    clean = ModelResponse(choices=[Choices(index=0, message=Message(role="assistant", content="plain"))])
    assert asyncio.run(guard.async_post_call_success_hook({}, None, clean)) is None
    ExplodingFilter.calls = 2
    guard.filter_cls = ExplodingFilter
    dirty = ModelResponse(choices=[Choices(index=0, message=Message(role="assistant", content="<think>x</think>y"))])
    assert asyncio.run(guard.async_post_call_success_hook({}, None, dirty)) is None
    assert dirty.choices[0].message.content == "<think>x</think>y" and guard.errors == 1


# ---------------------------------------------------------------- end to end through litellm.Router

def _router():
    return litellm.Router(model_list=[{"model_name": "ds-main", "litellm_params": {
        "model": "openai/accounts/fireworks/models/deepseek-v4p1-flash-1017", "api_key": "x",
        "mock_response": "<think>plan A</think>Hello world, <THINK>b</think>done"}}], num_retries=0)


def test_end_to_end_router_stream_through_hook(guard):
    async def go():
        stream = await _router().acompletion(model="ds-main", messages=[{"role": "user", "content": "hi"}], stream=True)
        raw = []

        async def tee():
            async for c in stream:
                raw.append(c.choices[0].delta.content if c.choices else None)
                yield c
        out = [c async for c in guard.async_post_call_streaming_iterator_hook(None, tee(), {})]
        return raw, out
    raw, out = asyncio.run(go())
    assert "<th" in "".join(r or "" for r in raw) and len(raw) > 5           # mock streamed the tags in pieces
    assert content_of(out) == "Hello world, done" and guard.stripped_blocks == 2


def test_end_to_end_router_stream_as_anthropic_messages(guard):
    async def go():
        stream = await _router().acompletion(model="ds-main", messages=[{"role": "user", "content": "hi"}], stream=True)
        sse = ANTHROPIC_ADAPTER.translate_completion_output_params_streaming(stream, model="ds-main")
        return [c async for c in guard.async_post_call_streaming_iterator_hook(None, sse, {})]
    events = sse_events(asyncio.run(go()))
    assert_well_formed(events)
    assert sse_text(events) == {0: "Hello world, done"}


# ---------------------------------------------------------------- proxy config loading

def test_config_loads_both_callbacks_through_proxy_resolver():
    yaml = pytest.importorskip("yaml")
    from litellm.integrations.custom_logger import CustomLogger
    from litellm.proxy.types_utils.utils import get_instance_fn

    with open(CONFIG) as fh:
        callbacks = yaml.safe_load(fh)["litellm_settings"]["callbacks"]
    assert callbacks == ["gem_lifecycle_callback.proxy_handler_instance", "gem_guardrail.proxy_handler_instance"]
    loaded = [get_instance_fn(value=c, config_file_path=CONFIG) for c in callbacks]
    assert all(isinstance(cb, CustomLogger) for cb in loaded)
    guard = loaded[1]
    assert type(guard).__name__ == "GemGuardrail" and guard.filter_cls is not None
    # proxy/utils.py only wraps streams for callbacks whose own class defines the iterator hook
    assert "async_post_call_streaming_iterator_hook" in type(guard).__dict__
    assert "async_post_call_success_hook" in type(guard).__dict__


@pytest.mark.parametrize("with_gemcore", [True, False])
def test_deployed_layout_next_to_config(tmp_path, with_gemcore):
    shutil.copy(os.path.join(ROOT, "gateway", "gem_guardrail.py"), tmp_path)
    if with_gemcore:
        shutil.copy(os.path.join(ROOT, "mcp_reference_monitor.py"), tmp_path)
    code = ("import asyncio; from litellm.proxy.types_utils.utils import get_instance_fn\n"
            "g = get_instance_fn('gem_guardrail.proxy_handler_instance', config_file_path='config.yaml')\n"
            "async def up():\n    yield b'event: x\\ndata: {\"type\": \"ping\"}\\n\\n'\n"
            "async def go():\n    return [c async for c in g.async_post_call_streaming_iterator_hook(None, up(), {})]\n"
            "print(g.filter_cls is not None, asyncio.run(go()))\n")
    env = {k: v for k, v in os.environ.items() if k not in ("GEM_CORE_PATH", "PYTHONPATH")}
    env["GEM_HOME"] = str(tmp_path / "no-gem-home")
    r = subprocess.run([sys.executable, "-I", "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == f"{with_gemcore} [b'event: x\\ndata: {{\"type\": \"ping\"}}\\n\\n']"
    if not with_gemcore:
        assert "stripping is OFF" in r.stderr
