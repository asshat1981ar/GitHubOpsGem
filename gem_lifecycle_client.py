"""Client for the B200 lifecycle controller (gemctl heavy, Claude Code session hooks). Stdlib only, Termux-safe.

Reads GEM_LIFECYCLE_URL (default http://127.0.0.1:8090, reached through the awsbox tunnel) and
GEM_LIFECYCLE_TOKEN (the controller's bearer; not the Fireworks key, which never leaves awsbox).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional, Tuple

DEFAULT_URL = "http://127.0.0.1:8090"


class LifecycleUnavailable(Exception):
    pass


def base_url() -> str:
    return os.environ.get("GEM_LIFECYCLE_URL", DEFAULT_URL).rstrip("/")


def configured() -> bool:
    return bool(os.environ.get("GEM_LIFECYCLE_TOKEN"))


def call(method: str, path: str, body: Optional[dict] = None, timeout: float = 5.0) -> Tuple[int, dict]:
    token = os.environ.get("GEM_LIFECYCLE_TOKEN", "")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base_url() + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - operator-configured URL
            return r.status, _json(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json(exc.read())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LifecycleUnavailable(f"lifecycle controller unreachable at {base_url()}: {exc}") from None


def _json(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8", "replace") or "{}")
        return obj if isinstance(obj, dict) else {"value": obj}
    except ValueError:
        return {"raw": raw[:200].decode("utf-8", "replace")}
