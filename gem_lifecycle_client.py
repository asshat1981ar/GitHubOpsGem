"""Client for the B200 lifecycle controller (gemctl heavy, Claude Code session hooks). Stdlib only, Termux-safe.

Reads GEM_LIFECYCLE_URL (default http://127.0.0.1:8090, reached through the awsbox tunnel). Each caller uses the
token of its own role (none of them is the Fireworks key, which never leaves awsbox):

  operator  GEM_LIFECYCLE_TOKEN if set, else $GEM_HOME/operator.token (default ~/.gem, mode 0600). gemctl heavy.
  session   GEM_LIFECYCLE_SESSION_TOKEN. The Claude Code hooks: register/unregister sessions, read status.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.error
import urllib.request
from typing import Optional, Tuple

DEFAULT_URL = "http://127.0.0.1:8090"


class LifecycleUnavailable(Exception):
    pass


class TokenError(Exception):
    """The operator token file exists but must not be used (other users can read it, or it is unreadable)."""


def base_url() -> str:
    return os.environ.get("GEM_LIFECYCLE_URL", DEFAULT_URL).rstrip("/")


def operator_token_path() -> str:
    return os.path.join(os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem")), "operator.token")


def _operator_file() -> str:
    path = operator_token_path()
    try:
        with open(path, encoding="utf-8") as fh:
            mode = stat.S_IMODE(os.fstat(fh.fileno()).st_mode)
            if mode & 0o077:
                raise TokenError(f"{path} is readable by other users (mode {mode:o}); run: chmod 600 {path}")
            return fh.read().strip()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise TokenError(f"cannot read {path}: {exc}") from None


def token(role: str) -> str:
    if role == "session":
        return os.environ.get("GEM_LIFECYCLE_SESSION_TOKEN", "").strip()
    if role == "operator":
        return os.environ.get("GEM_LIFECYCLE_TOKEN", "").strip() or _operator_file()
    raise ValueError(f"unknown role {role!r}")


def configured(role: str) -> bool:
    try:
        return bool(token(role))
    except TokenError:
        return False


def call(method: str, path: str, body: Optional[dict] = None, timeout: float = 5.0,
         role: str = "operator") -> Tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base_url() + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token(role)}", "Content-Type": "application/json"})
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
