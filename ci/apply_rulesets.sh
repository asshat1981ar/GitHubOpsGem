#!/usr/bin/env bash
# apply_rulesets.sh — create or update this repo's rulesets from ci/rulesets/*.json. Idempotent.
#
#   ./ci/apply_rulesets.sh [owner/repo]        default: asshat1981ar/GitHubOpsGem
#
# Run it as the repo owner with the GitHub CLI logged in (`gh auth login`; Termux: `pkg install gh`).
# Rulesets on a PRIVATE repo are enforced only on GitHub Pro/Team/Enterprise; on the Free plan they are
# enforced on public repos only.
# A ruleset with "enforcement": "disabled" (agent-approval.json ships that way) is created/updated as
# disabled and enforces nothing. After a green agent-approval-check run, activate it without editing the
# committed file:   ACTIVATE=agent-approval ./ci/apply_rulesets.sh
# (ACTIVATE takes a space-separated list of ruleset file names without .json.)
# Once a ruleset is active on GitHub, later runs keep it active even though the file says disabled, so a
# plain re-run never switches enforcement off. To turn one off again: DEACTIVATE=agent-approval ./ci/apply_rulesets.sh
# No GitHub CLI? Settings → Rules → Rulesets → New ruleset → Import a ruleset, and pick each JSON file.
set -euo pipefail
REPO="${1:-asshat1981ar/GitHubOpsGem}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v gh >/dev/null || { echo "install the GitHub CLI first (Termux: pkg install gh)" >&2; exit 1; }
ACTIVATE="${ACTIVATE:-}"
DEACTIVATE="${DEACTIVATE:-}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
set_enf() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["enforcement"]=sys.argv[3]; json.dump(d,open(sys.argv[2],"w"))' "$1" "$2" "$3"; }
for src in "$HERE"/rulesets/*.json; do
  f="$src"
  stem="$(basename "$src" .json)"
  name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$src")"
  id="$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$name\") | .id" | head -1)"
  file_enf="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("enforcement","active"))' "$src")"
  if [[ " $ACTIVATE " == *" $stem "* && " $DEACTIVATE " == *" $stem "* ]]; then
    echo "$stem is in both ACTIVATE and DEACTIVATE; pick one" >&2; exit 1
  elif [[ " $ACTIVATE " == *" $stem "* ]]; then
    f="$TMP/$stem.json"; set_enf "$src" "$f" active
  elif [[ " $DEACTIVATE " == *" $stem "* ]]; then
    f="$TMP/$stem.json"; set_enf "$src" "$f" disabled
  elif [[ -n "$id" && "$file_enf" == "disabled" ]]; then
    remote_enf="$(gh api "repos/$REPO/rulesets/$id" --jq .enforcement)"
    if [[ "$remote_enf" != "disabled" ]]; then
      f="$TMP/$stem.json"; set_enf "$src" "$f" "$remote_enf"
      echo "keeping $name $remote_enf on GitHub (set DEACTIVATE=$stem to turn it off)"
    fi
  fi
  enf="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("enforcement","active"))' "$f")"
  echo "ruleset: $name (enforcement: $enf)"
  if [[ -n "$id" ]]; then
    gh api -X PUT "repos/$REPO/rulesets/$id" --input "$f" --jq '"updated: \(.name) (id \(.id), \(.enforcement))"'
  else
    gh api -X POST "repos/$REPO/rulesets" --input "$f" --jq '"created: \(.name) (id \(.id), \(.enforcement))"'
  fi
done
gh api "repos/$REPO/rules/branches/main" --jq '"rules now active on main: " + ([.[].type] | join(", "))'
