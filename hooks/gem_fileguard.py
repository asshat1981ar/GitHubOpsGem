#!/usr/bin/env python3
"""GitHubOpsGem fast PreToolUse guard for file tools (WU-07 review #10). Stdlib only, no gemcore import.

Keeps the model's Read/Grep/Glob/Edit/Write/NotebookEdit away from the B200 operator credentials
(~/.gem/operator.token and /etc/gem/lifecycle.env). Bash is covered by hooks/gem_pretool.py. Always enforced.
"""
import json
import re
import sys

PATHS = re.compile(r"operator\.token|/etc/gem/lifecycle\.env")


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    ti = event.get("tool_input") or {}
    target = " ".join(str(ti.get(k, "")) for k in ("file_path", "path", "pattern", "notebook_path"))
    if PATHS.search(target):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "GEM: the B200 operator credentials are off limits to the model; "
                                        "ask the user to run `gem heavy on` themselves."}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
