# Claude automation: how to turn it on

Four workflows run Claude Code on this repository. No Claude workflow is a required check (Claude jobs fail when the subscription limit is hit). The required checks stay `gem-review / scan` and `pytest`.

| Workflow | Trigger | What it does |
|---|---|---|
| `claude.yml` | `@claude` in an issue, PR comment or review (owner only) | Implements on a `fix/<issue>-<slug>` branch with file edits and commits only. It runs no tests, scripts or package managers; CI runs on its pushes without secrets. Cross-repository PRs are refused |
| `claude-review.yml` | Non-draft same-repo PRs to `main` touching code, CI or `CLAUDE.md` | Read-only multi-lens review (`/review-pr`) of the diff; does not read PR comments |
| `claude-gem-verdict.yml` | `gem-review` fails on a PR | The deterministic CRITICAL count from `gem-review.json` is the verdict; Claude adds a typed tp/fp explanation and a regression test idea, and the job labels `gem-review:fp-candidate`. Empty Claude output gives a WARN, never a pass |
| `agent-approval-check.yml` | PR events and comments | Requires one human approval on PRs with agent-authored commits |

## Turn-on steps

1. Add the repository secret `CLAUDE_CODE_OAUTH_TOKEN`.
2. Install the Claude GitHub App (https://github.com/apps/claude) on this repository. `claude.yml` and `claude-review.yml` use it, so comments come from claude[bot] and its pushes trigger CI.
3. Create the label `gem-review:fp-candidate` once.
4. Optional variables:
   - `CLAUDE_MODEL`: overrides the model in every workflow (defaults: `claude-opus-5-5` for `claude.yml`, `claude-sonnet-5-5` elsewhere).
   - `CLAUDE_RUNNER=ubuntu-24.04-firewall` once the egress-firewall runner is enrolled (`.github/egress-firewall.yaml`).
   - `CLAUDE_PAUSE=true` pauses every Claude job (kill switch).
5. `ci/rulesets/agent-approval.json` ships with `"enforcement": "disabled"`, so `ci/apply_rulesets.sh` creates it inert. After one green run of `agent-approval-check`, change it to `"active"` and re-run the script. Do not activate it earlier: a required check that never reports blocks every merge.

## Commands

- `@claude <task>` in an issue or PR.
- `/approve <head-sha>` as a PR comment to approve a PR that contains agent commits.

## Notes

- CI-side Claude has no ForgeCore, so its commits carry no `Gem-Gate:` trailer. Gate locally before merge.
- `agent-approval-check` uses `pull_request_target`, so gem-review reports one MAJOR `PULL_REQUEST_TARGET` finding. It is justified: the job has no checkout and never runs PR code.
- When the subscription limit is hit, Claude jobs fail. Nothing required depends on them.

## Residual risks

- `claude.yml` is tag mode: it may check out a same-repository PR branch and the Claude process holds the OAuth token and the App token. Cross-repository PRs are refused, and no build, test or repo-script tool is allowlisted, but Claude still reads the branch content as data. Treat prompt injection through a branch you own as possible.
- `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` scrubs subprocess environments; the App token is also in `.git/config`, which `.claude/settings.json` denies Claude from reading.
- `.claude/settings.json` has an empty `allow` list. Each workflow grants its own tools through `--allowedTools`; settings and flags are merged, so nothing broader is added by settings.
- Agent-mode jobs (`claude-review.yml`, `claude-gem-verdict.yml`) cannot filter comments by author, so they are told not to read PR comments and do not allowlist `gh pr view` or `gh api`.
- On the PR that introduces these files, review commands come from the base branch, so the first `claude-review` run has no `/review-pr` command.
