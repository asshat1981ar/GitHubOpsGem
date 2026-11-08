#!/usr/bin/env python3
"""GitHubOpsGem SessionStart hook (WU-08). Stdout becomes model context for the session.

Tells the model which enforcement mode is active, when it flips, and whether ForgeCore is reachable.
Never fails the session: any error degrades to a one-line notice.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (os.path.join(HERE, ".."), os.path.join(os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem")), "lib")):
    if os.path.isfile(os.path.join(candidate, "mcp_reference_monitor.py")):
        sys.path.insert(0, os.path.abspath(candidate))
        break


def _hook_input() -> dict:
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return {}
        data = json.loads(sys.stdin.read() or "{}")
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def lifecycle_note(session_id: str) -> str:
    """Register the session with the B200 controller (WU-07) and describe the burst tier in one clause.

    Uses the SESSION token only (GEM_LIFECYCLE_SESSION_TOKEN): it can register sessions and read status, not wake
    the B200."""
    try:
        import gem_lifecycle_client as lc
    except ImportError:
        return ""
    if not lc.configured("session"):
        return ""
    try:
        code, b = lc.call("POST", "/session/start", {"session_id": session_id}, timeout=2.0, role="session")
    except lc.LifecycleUnavailable:
        return " B200 controller unreachable: stay on ds-main (serverless)."
    if code != 200:
        return ""
    cap = f"GPU spend today ${b.get('spend_day_usd')} of ${b.get('cap_day_usd')}"
    if b.get("wake_disabled"):
        return f" B200 burst disabled by its deployment guard ({cap}); use ds-main."
    if b.get("capped") == "ledger":
        return " B200 burst disabled until the weekly rollover (its spend ledger was lost); use ds-main."
    if b.get("capped"):
        return f" B200 burst capped for the {b['capped']} ({cap}); use ds-main."
    return f" B200 burst {b.get('b200')} ({cap}); ds-main is the default, the user runs `gemctl heavy on` for burst."


def main() -> int:
    note = ""
    try:
        note = lifecycle_note(str(_hook_input().get("session_id", "")))
    except Exception:  # noqa: BLE001
        note = ""
    try:
        import mcp_reference_monitor as gem
        cfg = gem.GemConfig.from_env()
        mode = cfg.effective_mode().value
        flip = f" until {cfg.enforce_after.isoformat()}, then ENFORCE" if cfg.enforce_after and mode == "WARN" else ""
        url = os.environ.get("GEM_FORGECORE_URL") or os.environ.get("AUTODEV_URL")
        signer = "local only (no AUTODEV_URL): verdicts are not evidence"
        if url:
            try:
                with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=2) as r:  # noqa: S310
                    ok = json.loads(r.read().decode()).get("status") == "ok"
                signer = "ForgeCore reachable: every gate verdict is decided and signed by ForgeCore" if ok else "ForgeCore unhealthy"
            except Exception:  # noqa: BLE001
                signer = ("ForgeCore UNREACHABLE: GitHub writes will " +
                          ("be blocked (fail closed)" if mode == "ENFORCE" else "warn only"))
        print(f"GitHubOpsGem {gem.__version__}: mode {mode}{flip}. {signer}. "
              "Direct pushes to main/master/prod*/trunk/release*/hotfix* are always blocked; "
              "work on feat/<slug> or fix/<issue>-<slug> branches and open PRs." + note)
    except Exception as exc:  # noqa: BLE001
        print(f"GitHubOpsGem hook could not start ({exc}); GitHub writes are not being gated this session.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
