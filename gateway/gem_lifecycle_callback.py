"""LiteLLM callback that feeds the B200 lifecycle controller (WU-07). Put it next to the LiteLLM config.

  litellm_settings:
    callbacks: gem_lifecycle_callback.proxy_handler_instance

What it reports (to GEM_LIFECYCLE_URL, default http://127.0.0.1:8090, bearer GEM_LIFECYCLE_TOKEN):
  * ds-burst request start/end  -> POST /touch      (keeps the B200 awake while it is serving; idle clock)
  * ds-main / ds-fast 429       -> POST /signal/429 (three within two minutes wake the B200)

It never blocks or fails a request: posts go out on a daemon thread with a 1 s timeout, and every error is
swallowed. Verified against LiteLLM 1.108.2: CustomLogger.log_pre_api_call(model, messages, kwargs) and
async_log_{success,failure}_event(kwargs, response_obj, start_time, end_time); router metadata lives in
litellm_params["litellm_metadata"] on new routes such as /v1/messages, or litellm_params["metadata"].
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from typing import Any, Optional

try:
    from litellm.integrations.custom_logger import CustomLogger
except Exception:  # noqa: BLE001 - importable for tests without LiteLLM
    class CustomLogger:  # type: ignore[no-redef]
        pass

try:
    from litellm.litellm_core_utils.core_helpers import get_litellm_metadata_from_kwargs as _litellm_md
except Exception:  # noqa: BLE001
    _litellm_md = None

BURST_GROUPS = {g.strip() for g in os.environ.get("GEM_BURST_GROUPS", "ds-burst").split(",") if g.strip()}
MAIN_GROUPS = {g.strip() for g in os.environ.get("GEM_MAIN_GROUPS", "ds-main,ds-fast").split(",") if g.strip()}
SYNC = os.environ.get("GEM_LIFECYCLE_SYNC") == "1"   # tests: post inline instead of on a thread


def _metadata(kwargs: dict) -> dict:
    if _litellm_md is not None:
        try:
            md = _litellm_md(kwargs)
            if isinstance(md, dict):
                return md
        except Exception:  # noqa: BLE001
            pass
    lp = kwargs.get("litellm_params") or {}
    return lp.get("litellm_metadata") or lp.get("metadata") or kwargs.get("metadata") or {}


def model_group(kwargs: dict) -> str:
    return str(_metadata(kwargs).get("model_group") or kwargs.get("model_group") or "")


def is_burst(kwargs: dict) -> bool:
    group = model_group(kwargs)
    if group:
        return group in BURST_GROUPS
    return "/deployments/" in str(kwargs.get("model", ""))      # direct call to a dedicated deployment


def status_code(exc: Any) -> Optional[int]:
    for obj in (exc, getattr(exc, "response", None)):
        code = getattr(obj, "status_code", None)
        if isinstance(code, int):
            return code
    return None


def _post(path: str, body: dict) -> None:
    token = os.environ.get("GEM_LIFECYCLE_TOKEN", "")
    if not token:
        return
    url = os.environ.get("GEM_LIFECYCLE_URL", "http://127.0.0.1:8090").rstrip("/") + path

    def send() -> None:
        try:
            req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                         headers={"Authorization": f"Bearer {token}",
                                                  "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=1.0):  # noqa: S310 - loopback controller
                pass
        except Exception:  # noqa: BLE001 - never affect the request path
            pass

    if SYNC:
        send()
    else:
        threading.Thread(target=send, name="gem-lifecycle-post", daemon=True).start()


class GemLifecycleCallback(CustomLogger):
    def log_pre_api_call(self, model, messages, kwargs):  # noqa: D401 - LiteLLM hook
        try:
            if is_burst(kwargs):
                _post("/touch", {"event": "start", "call_id": str(kwargs.get("litellm_call_id", ""))})
        except Exception:  # noqa: BLE001
            pass

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            if is_burst(kwargs):
                _post("/touch", {"event": "end", "call_id": str(kwargs.get("litellm_call_id", ""))})
        except Exception:  # noqa: BLE001
            pass

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        try:
            if is_burst(kwargs):
                _post("/touch", {"event": "end", "call_id": str(kwargs.get("litellm_call_id", ""))})
            elif model_group(kwargs) in MAIN_GROUPS and status_code(kwargs.get("exception")) == 429:
                _post("/signal/429", {"model_group": model_group(kwargs)})
        except Exception:  # noqa: BLE001
            pass


proxy_handler_instance = GemLifecycleCallback()
