#!/usr/bin/env python3
"""GitHubOpsGem SessionEnd hook (WU-07/08). Tells the B200 lifecycle controller this session is over.

When the last registered session ends, the controller schedules the B200 to scale to zero 45 s later,
unless a new session starts or traffic arrives first. Prints nothing and always exits 0, so it can never
hold up Claude Code's exit. Uses the SESSION token (GEM_LIFECYCLE_SESSION_TOKEN); without it, it does nothing.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (os.path.join(HERE, ".."), os.path.join(os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem")), "lib")):
    if os.path.isfile(os.path.join(candidate, "gem_lifecycle_client.py")):
        sys.path.insert(0, os.path.abspath(candidate))
        break


def main() -> int:
    try:
        data = {}
        if sys.stdin is not None and not sys.stdin.isatty():
            data = json.loads(sys.stdin.read() or "{}")
        import gem_lifecycle_client as lc
        if lc.configured("session"):
            lc.call("POST", "/session/end", {"session_id": str((data or {}).get("session_id", ""))}, timeout=3.0,
                    role="session")
    except Exception:  # noqa: BLE001 - never block exit
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
