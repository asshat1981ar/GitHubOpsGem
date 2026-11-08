#!/usr/bin/env bash
# apply_rulesets.sh — create or update this repo's rulesets from ci/rulesets/*.json. Idempotent.
#
#   ./ci/apply_rulesets.sh [owner/repo]        default: asshat1981ar/GitHubOpsGem
#
# Run it as the repo owner with the GitHub CLI logged in (`gh auth login`; Termux: `pkg install gh`).
# Rulesets on a PRIVATE repo are enforced only on GitHub Pro/Team/Enterprise; on the Free plan they are
# enforced on public repos only. No GitHub CLI? Settings → Rules → Rulesets → New ruleset → Import a ruleset,
# and pick each JSON file.
set -euo pipefail
REPO="${1:-asshat1981ar/GitHubOpsGem}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v gh >/dev/null || { echo "install the GitHub CLI first (Termux: pkg install gh)" >&2; exit 1; }
for f in "$HERE"/rulesets/*.json; do
  name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$f")"
  id="$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$name\") | .id" | head -1)"
  if [[ -n "$id" ]]; then
    gh api -X PUT "repos/$REPO/rulesets/$id" --input "$f" --jq '"updated: \(.name) (id \(.id), \(.enforcement))"'
  else
    gh api -X POST "repos/$REPO/rulesets" --input "$f" --jq '"created: \(.name) (id \(.id), \(.enforcement))"'
  fi
done
gh api "repos/$REPO/rules/branches/main" --jq '"rules now active on main: " + ([.[].type] | join(", "))'
