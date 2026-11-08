"""LiteLLM proxy callback that strips DeepSeek <think>...</think> reasoning from model output (WU-05).

Put it next to the LiteLLM config, with gemcore (mcp_reference_monitor.py) in the same directory, its parent,
$GEM_HOME/lib or $GEM_CORE_PATH:

  litellm_settings:
    callbacks: [gem_lifecycle_callback.proxy_handler_instance, gem_guardrail.proxy_handler_instance]

Hooks, verified against the LiteLLM 1.108.2 source:
  * async_post_call_streaming_iterator_hook(user_api_key_dict, response, request_data) wraps every proxied stream.
    /chat/completions yields ModelResponseStream chunks (choices[].delta.content / .tool_calls). /v1/messages on an
    OpenAI-format backend (our Fireworks deployments) yields bytes, one Anthropic SSE frame per chunk
    ("event: content_block_delta\\ndata: {json}\\n\\n"). Anthropic event dicts and str frames are handled the same
    way, and a frame split across chunks is reassembled before it is parsed.
  * async_post_call_success_hook(data, user_api_key_dict, response) for non-streaming responses: a ModelResponse
    (/chat/completions) or an Anthropic message dict (/v1/messages).

Every text choice / text block and every tool call gets its own gemcore ThinkStreamFilter, so at most a partial
tag is held back. reasoning_content and thinking blocks are left alone. GEM_GUARDRAIL_TOOL_ARGS=0 stops stripping
inside tool-call arguments. An error inside the guardrail is logged once and that stream (or response) then passes
through unmodified; upstream errors propagate untouched. `proxy_handler_instance.stripped_blocks` counts removed
blocks for metrics, `errors` counts fail-open events.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    from litellm.integrations.custom_logger import CustomLogger
except Exception:  # noqa: BLE001 - importable for tests without LiteLLM
    class CustomLogger:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

try:
    from litellm.types.utils import ChatCompletionDeltaToolCall, Delta, Function, ModelResponseStream, StreamingChoices
except Exception:  # noqa: BLE001
    ChatCompletionDeltaToolCall = Delta = Function = ModelResponseStream = StreamingChoices = None  # type: ignore

try:
    from litellm._logging import verbose_proxy_logger as _log
except Exception:  # noqa: BLE001
    _log = logging.getLogger("gem_guardrail")


def _load_think_filter() -> Optional[type]:
    """gemcore's ThinkStreamFilter: already imported, next to this file, its parent, $GEM_HOME/lib, $GEM_CORE_PATH."""
    mod = sys.modules.get("mcp_reference_monitor")
    if mod is not None and hasattr(mod, "ThinkStreamFilter"):
        return mod.ThinkStreamFilter
    here = os.path.dirname(os.path.abspath(__file__))
    gem_home = os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem"))
    for cand in (os.environ.get("GEM_CORE_PATH", ""), here, os.path.dirname(here), os.path.join(gem_home, "lib")):
        path = cand if cand.endswith(".py") else os.path.join(cand, "mcp_reference_monitor.py")
        if not cand or not os.path.isfile(path):
            continue
        try:
            spec = importlib.util.spec_from_file_location("mcp_reference_monitor", path)
            mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            sys.modules["mcp_reference_monitor"] = mod     # dataclasses need the module registered
            spec.loader.exec_module(mod)                    # type: ignore[union-attr]
            return mod.ThinkStreamFilter
        except Exception:  # noqa: BLE001
            sys.modules.pop("mcp_reference_monitor", None)
    try:
        from mcp_reference_monitor import ThinkStreamFilter
        return ThinkStreamFilter
    except Exception:  # noqa: BLE001
        return None


_SSE_FIELDS = (b"event:", b"data:", b":", b"id:", b"retry:")
_MAX_SSE_FRAME = 1 << 20          # a partial frame larger than this is passed on raw instead of held


def _get(obj: Any, key: str, default: Any = None) -> Any:
    return obj.get(key, default) if isinstance(obj, Mapping) else getattr(obj, key, default)


def _set(obj: Any, key: str, value: Any) -> None:
    if isinstance(obj, MutableMapping):
        obj[key] = value
    else:
        setattr(obj, key, value)


def _split_frames(buf: bytes) -> Tuple[List[bytes], bytes]:
    frames: List[bytes] = []
    while True:
        cut = [(i, n) for i, n in ((buf.find(b"\n\n"), 2), (buf.find(b"\r\n\r\n"), 4)) if i >= 0]
        if not cut:
            return frames, buf
        i, n = min(cut)
        frames.append(buf[: i + n])
        buf = buf[i + n:]


def _parse_frame(frame: bytes) -> Optional[Tuple[Optional[str], dict]]:
    try:
        text = frame.decode("utf-8")
    except UnicodeDecodeError:
        return None
    name: Optional[str] = None
    data: List[str] = []
    for line in text.splitlines():
        if line.startswith("event:"):
            name = line[6:].strip()
        elif line.startswith("data:"):
            value = line[5:]
            data.append(value[1:] if value.startswith(" ") else value)
    if not data:
        return None
    try:
        event = json.loads("\n".join(data))
    except ValueError:
        return None
    return (name, event) if isinstance(event, dict) else None


def _encode_frame(name: Optional[str], event: dict) -> bytes:
    head = f"event: {name}\n" if name else ""
    return f"{head}data: {json.dumps(event)}\n\n".encode()


class _Stream:
    """State for one stream: a filter per chat choice, per tool call and per Anthropic content block."""

    def __init__(self, owner: "GemGuardrail") -> None:
        self.owner = owner
        self.chat_text: Dict[int, Any] = {}
        self.chat_tool: Dict[Tuple[int, int], Any] = {}
        self.blocks: Dict[Any, Tuple[str, Any]] = {}     # Anthropic block index -> ("text" | "tool", filter)
        self.sse_buf = b""
        self.sse_str = False
        self.last_chunk: Any = None
        self.broken = False

    # ------------------------------------------------------------------ filter plumbing
    def _new(self) -> Any:
        return self.owner.filter_cls()

    def _filter(self, table: Dict[Any, Any], key: Any) -> Any:
        f = table.get(key)
        if f is None:
            f = table[key] = self._new()
        return f

    def _feed(self, f: Any, text: str) -> str:
        before = f.stripped_blocks
        out = f.feed(text)
        self.owner.stripped_blocks += f.stripped_blocks - before
        return out

    def _flush(self, f: Any) -> str:
        before = f.stripped_blocks
        out = f.flush()
        self.owner.stripped_blocks += f.stripped_blocks - before
        return out

    def _fail(self) -> None:
        self.broken = True
        self.sse_buf = b""
        self.owner.errors += 1
        _log.warning("gem_guardrail: error while stripping <think>; passing this stream through unmodified",
                     exc_info=True)

    # ------------------------------------------------------------------ entry points
    def process(self, item: Any) -> List[Any]:
        if self.broken:
            return [item]
        raw = [item]
        try:
            if isinstance(item, (bytes, bytearray, str)):
                if self.sse_buf:
                    pending = self.sse_buf + (item.encode() if isinstance(item, str) else bytes(item))
                    raw = [pending.decode("utf-8", "replace") if isinstance(item, str) else pending]
                return self._sse(item)
            if isinstance(item, Mapping):
                return [ev for ev, _ in self._anthropic(item)]
            if getattr(item, "choices", None) is not None:
                return self._chat(item)
            return [item]
        except Exception:  # noqa: BLE001 - fail open
            self._fail()
            return raw

    def finish(self) -> List[Any]:
        if self.broken:
            return []
        rest = self.sse_buf
        try:
            out: List[Any] = []
            if rest:
                self.sse_buf = b""
                frame = rest if rest.endswith((b"\n\n", b"\r\n\r\n")) else rest + b"\n\n"
                out.append(self._frame(frame) if _parse_frame(frame) else rest)
            tail = b"".join(_encode_frame("content_block_delta", ev) for ev, _ in self._close_blocks())
            if tail:
                out.append(tail)
            out = [o.decode("utf-8", "replace") if self.sse_str else o for o in out if o]
            return out + self._chat_finish()
        except Exception:  # noqa: BLE001 - fail open
            self._fail()
            return [rest.decode("utf-8", "replace") if self.sse_str else rest] if rest else []

    # ------------------------------------------------------------------ OpenAI chat chunks
    def _chat(self, chunk: Any) -> List[Any]:
        plan: List[Tuple[Any, str, Any]] = []            # applied only once every choice was processed
        for choice in list(chunk.choices or ()):
            ci = getattr(choice, "index", 0) or 0
            delta = getattr(choice, "delta", None)
            if delta is None:
                continue
            content = getattr(delta, "content", None)
            text = content
            if isinstance(content, str) and content:
                text = self._feed(self._filter(self.chat_text, ci), content)
            calls = list(getattr(delta, "tool_calls", None) or ())
            if self.owner.strip_tool_args:
                for call in calls:
                    fn = getattr(call, "function", None)
                    args = getattr(fn, "arguments", None)
                    if isinstance(args, str) and args:
                        new = self._feed(self._filter(self.chat_tool, (ci, getattr(call, "index", 0) or 0)), args)
                        if new != args:
                            plan.append((fn, "arguments", new))
            if getattr(choice, "finish_reason", None):
                tail, extra = self._close_choice(ci)
                if tail:
                    text = (text or "") + tail
                if extra:
                    plan.append((delta, "tool_calls", calls + extra))
            if text != content:
                plan.append((delta, "content", text))
        for obj, attr, value in plan:
            setattr(obj, attr, value)
        self.last_chunk = chunk
        return [chunk]

    def _close_choice(self, ci: int) -> Tuple[str, List[Any]]:
        f = self.chat_text.pop(ci, None)
        tail = self._flush(f) if f is not None else ""
        extra = []
        for key in sorted(k for k in self.chat_tool if k[0] == ci):
            args = self._flush(self.chat_tool.pop(key))
            if args:
                extra.append(ChatCompletionDeltaToolCall(index=key[1], function=Function(arguments=args)))
        return tail, extra

    def _chat_finish(self) -> List[Any]:
        out = []
        for ci in sorted({*self.chat_text, *(k[0] for k in self.chat_tool)}):
            tail, extra = self._close_choice(ci)
            if tail or extra:
                last = self.last_chunk
                out.append(ModelResponseStream(
                    id=getattr(last, "id", None), created=getattr(last, "created", None),
                    model=getattr(last, "model", None),
                    choices=[StreamingChoices(index=ci, delta=Delta(content=tail or None, tool_calls=extra or None))]))
        return out

    # ------------------------------------------------------------------ Anthropic /v1/messages
    def _sse(self, item: Any) -> List[Any]:
        self.sse_str = isinstance(item, str)
        data = item.encode() if self.sse_str else bytes(item)
        if not self.sse_buf and not data.lstrip(b"\r\n").startswith(_SSE_FIELDS):
            return [item]                                  # not SSE: leave it alone
        frames, rest = _split_frames(self.sse_buf + data)
        out = b"".join(self._frame(fr) for fr in frames)
        if len(rest) > _MAX_SSE_FRAME:
            out, rest = out + rest, b""
        self.sse_buf = rest
        if not out:
            return []
        return [out.decode("utf-8", "replace") if self.sse_str else out]

    def _frame(self, frame: bytes) -> bytes:
        parsed = _parse_frame(frame)
        if parsed is None:
            return frame
        name, event = parsed
        out = []
        for ev, changed in self._anthropic(event):
            if not changed:
                out.append(frame)
            else:                                           # keep the original event name for a rewritten event
                out.append(_encode_frame(name if ev.get("type") == event.get("type") else ev.get("type"), ev))
        return b"".join(out)

    def _anthropic(self, ev: Mapping) -> List[Tuple[Any, bool]]:
        kind = ev.get("type")
        if kind == "content_block_start":
            block = ev.get("content_block")
            btype = block.get("type") if isinstance(block, Mapping) else None
            if btype == "text":
                f = self._new()
                self.blocks[ev.get("index")] = ("text", f)
                text = block.get("text")
                if isinstance(text, str) and text:
                    new = self._feed(f, text)
                    if new != text:
                        return [({**ev, "content_block": {**block, "text": new}}, True)]
            elif btype in ("tool_use", "server_tool_use") and self.owner.strip_tool_args:
                self.blocks[ev.get("index")] = ("tool", self._new())
            return [(ev, False)]
        if kind == "content_block_delta":
            delta = ev.get("delta")
            dtype = delta.get("type") if isinstance(delta, Mapping) else None
            if dtype == "text_delta":
                want, field = "text", "text"
            elif dtype == "input_json_delta" and self.owner.strip_tool_args:
                want, field = "tool", "partial_json"
            else:
                return [(ev, False)]
            value = delta.get(field)
            if not isinstance(value, str) or not value:
                return [(ev, False)]
            entry = self.blocks.get(ev.get("index"))
            if entry is None or entry[0] != want:
                entry = self.blocks[ev.get("index")] = (want, self._new())
            new = self._feed(entry[1], value)
            if new == value:
                return [(ev, False)]
            if not new:
                return []                                   # nothing visible in this delta: drop the frame
            return [({**ev, "delta": {**delta, field: new}}, True)]
        if kind == "content_block_stop":
            return list(self._close_blocks(ev.get("index"))) + [(ev, False)]
        if kind in ("message_delta", "message_stop"):
            return list(self._close_blocks()) + [(ev, False)]
        return [(ev, False)]

    def _close_blocks(self, index: Any = ...) -> Iterator[Tuple[dict, bool]]:
        keys = list(self.blocks) if index is ... else [index] if index in self.blocks else []
        for key in keys:
            kind, f = self.blocks.pop(key)
            tail = self._flush(f)
            if tail:
                delta = {"type": "text_delta", "text": tail} if kind == "text" else \
                        {"type": "input_json_delta", "partial_json": tail}
                yield {"type": "content_block_delta", "index": key, "delta": delta}, True


class GemGuardrail(CustomLogger):
    """Strips <think>...</think> from visible text (and tool-call arguments) on every proxied response."""

    def __init__(self, filter_cls: Optional[type] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.filter_cls = filter_cls or _load_think_filter()
        self.strip_tool_args = os.environ.get("GEM_GUARDRAIL_TOOL_ARGS", "1") != "0"
        self.stripped_blocks = 0
        self.errors = 0
        if self.filter_cls is None:
            _log.error("gem_guardrail: gemcore ThinkStreamFilter not found (put mcp_reference_monitor.py next to "
                       "gem_guardrail.py or set GEM_CORE_PATH); <think> stripping is OFF")

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data):
        if self.filter_cls is None:
            async for item in response:
                yield item
            return
        stream = _Stream(self)
        async for item in response:                       # upstream errors propagate unchanged
            for out in stream.process(item):
                yield out
        for out in stream.finish():
            yield out

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        if self.filter_cls is None:
            return None
        try:
            plan = self._plan_response(response)
        except Exception:  # noqa: BLE001 - fail open
            self.errors += 1
            _log.warning("gem_guardrail: error while stripping <think>; response passed through unmodified",
                         exc_info=True)
            return None
        if not plan:
            return None
        for target, key, value, blocks in plan:
            _set(target, key, value)
            self.stripped_blocks += blocks
        return response

    # ------------------------------------------------------------------ non-streaming
    def _strip(self, text: str) -> Tuple[str, int]:
        f = self.filter_cls()
        return f.feed(text) + f.flush(), f.stripped_blocks

    def _plan_response(self, response: Any) -> List[Tuple[Any, str, Any, int]]:
        """Work out every change first, so a failure part-way leaves the response untouched."""
        plan: List[Tuple[Any, str, Any, int]] = []
        choices = _get(response, "choices")
        if isinstance(choices, list):                      # OpenAI ModelResponse
            for choice in choices:
                msg = _get(choice, "message")
                if msg is None:
                    continue
                content = _get(msg, "content")
                if isinstance(content, str) and content:
                    new, n = self._strip(content)
                    if new != content:
                        plan.append((msg, "content", new, n))
                for call in (_get(msg, "tool_calls") or []) if self.strip_tool_args else []:
                    fn = _get(call, "function")
                    args = _get(fn, "arguments") if fn is not None else None
                    if isinstance(args, str) and args:
                        new, n = self._strip(args)
                        if new != args:
                            plan.append((fn, "arguments", new, n))
            return plan
        blocks = _get(response, "content")
        if isinstance(blocks, list):                       # Anthropic message
            for block in blocks:
                btype = _get(block, "type")
                if btype == "text":
                    text = _get(block, "text")
                    if isinstance(text, str) and text:
                        new, n = self._strip(text)
                        if new != text:
                            plan.append((block, "text", new, n))
                elif btype in ("tool_use", "server_tool_use") and self.strip_tool_args:
                    args = _get(block, "input")
                    if isinstance(args, (dict, list)):
                        raw = json.dumps(args, ensure_ascii=False)
                        new, n = self._strip(raw)
                        if new != raw:
                            try:
                                plan.append((block, "input", json.loads(new), n))
                            except ValueError:
                                pass                         # stripping broke the JSON: keep the original input
        return plan


proxy_handler_instance = GemGuardrail()
