#!/usr/bin/env python3
"""Install GitHubOpsGem hooks for Claude Code (user level, repo-agnostic). Stdlib only; works in Termux.

  python3 install_hooks.py            install / update (idempotent, backs up settings.json first)
  python3 install_hooks.py --remove   remove the GitHubOpsGem hook entries again
  python3 install_hooks.py --dry-run  print the merged settings without writing

Copies gemcore + gemctl to $GEM_HOME/lib and the hooks to $GEM_HOME/hooks (default ~/.gem), then merges
three hook entries (PreToolUse, SessionStart, SessionEnd) into
~/.claude/settings.json. Entries are tagged by their command path, so re-running
replaces them instead of duplicating, and every other setting is left untouched.

It never copies or creates the B200 controller's operator token. Put that token in $GEM_HOME/operator.token
yourself (see TOKEN_HELP); the hooks only use GEM_LIFECYCLE_SESSION_TOKEN.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys

SRC = os.path.dirname(os.path.abspath(__file__))
MARK = "/.gem/hooks/gem_"   # identifies entries this installer owns
TOKEN_HELP = """B200 controller tokens (on awsbox: sudo grep '^GEM_LIFECYCLE_' /etc/gem/lifecycle.env):
  session   export GEM_LIFECYCLE_SESSION_TOKEN=<value> before sourcing gateway/claude-gem.env (hooks use it)
  operator  never exported; paste it into {path} for `gem heavy`:
              (umask 077; cat > {path})        # paste the GEM_LIFECYCLE_TOKEN value, Enter, Ctrl-D
              chmod 600 {path}"""


def hook_entries(gem_home: str) -> dict:
    py = sys.executable or "python3"
    pre = f'{py} "{os.path.join(gem_home, "hooks", "gem_pretool.py")}"'
    start = f'{py} "{os.path.join(gem_home, "hooks", "gem_session_start.py")}"'
    end = f'{py} "{os.path.join(gem_home, "hooks", "gem_session_end.py")}"'
    return {
        "PreToolUse": {"matcher": "Bash|mcp__.*github.*",
                       "hooks": [{"type": "command", "command": pre, "timeout": 15}]},
        "SessionStart": {"hooks": [{"type": "command", "command": start, "timeout": 10}]},
        "SessionEnd": {"hooks": [{"type": "command", "command": end, "timeout": 10}]},
    }


def _owned(group: dict) -> bool:
    return any(MARK in str(h.get("command", "")) or "gem_pretool.py" in str(h.get("command", ""))
               or "gem_session_start.py" in str(h.get("command", ""))
               or "gem_session_end.py" in str(h.get("command", "")) for h in group.get("hooks", []))


def merge(settings: dict, gem_home: str, remove: bool = False) -> dict:
    hooks = settings.setdefault("hooks", {})
    for event, entry in hook_entries(gem_home).items():
        groups = [g for g in hooks.get(event, []) if not _owned(g)]
        if not remove:
            groups.append(entry)
        if groups:
            hooks[event] = groups
        else:
            hooks.pop(event, None)
    if not hooks:
        settings.pop("hooks", None)
    return settings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remove", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--settings", default=os.path.expanduser("~/.claude/settings.json"))
    ap.add_argument("--gem-home", default=os.path.expanduser(os.environ.get("GEM_HOME", "~/.gem")))
    a = ap.parse_args()

    settings = {}
    if os.path.exists(a.settings):
        with open(a.settings, encoding="utf-8") as fh:
            settings = json.load(fh)
    merged = merge(settings, a.gem_home, remove=a.remove)
    if a.dry_run:
        print(json.dumps(merged, indent=2))
        return 0

    if not a.remove:
        for sub, names in (("lib", ["mcp_reference_monitor.py", "gemctl.py", "gem_lifecycle_client.py"]),
                           ("hooks", ["hooks/gem_pretool.py", "hooks/gem_session_start.py",
                                      "hooks/gem_session_end.py"])):
            os.makedirs(os.path.join(a.gem_home, sub), exist_ok=True)
            for n in names:
                shutil.copy2(os.path.join(SRC, n), os.path.join(a.gem_home, sub, os.path.basename(n)))
    os.makedirs(os.path.dirname(a.settings), exist_ok=True)
    if os.path.exists(a.settings):
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(a.settings, f"{a.settings}.bak-{stamp}")
    tmp = a.settings + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, a.settings)
    print(("Removed" if a.remove else "Installed") + f" GitHubOpsGem hooks ({a.settings}; files in {a.gem_home}).")
    if not a.remove:
        print("Set GEM_ENFORCEMENT / GEM_ENFORCE_AFTER and AUTODEV_URL / AUTODEV_API_BEARER_TOKEN "
              "(see gateway/claude-gem.env), then restart Claude Code and run /hooks to confirm.")
        print(TOKEN_HELP.format(path=os.path.join(a.gem_home, "operator.token")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
