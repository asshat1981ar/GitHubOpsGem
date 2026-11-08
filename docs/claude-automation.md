# Claude automation: how to turn it on

Four workflows run Claude Code on this repository. None is a required check; the required check stays `gem-review / scan`.

| Workflow | Trigger | What it does |
|---|---|---|
| `claude.yml` | `@claude` in an issue, PR comment or review (owner only) | Implements on a `fix/<issue>-<slug>` branch; runs pytest, probes and the lifecycle dry run |
| `claude-review.yml` | Non-draft same-repo PRs to `main` touching code, CI or `CLAUDE.md` | Read-only multi-lens review (`/review-pr`) |
| `claude-gem-verdict.yml` | `gem-review` fails on a PR | Typed tp/fp verdict per CRITICAL finding plus a regression test idea; labels `gem-review:fp-candidate`. Falls back to a WARN summary when Claude returns nothing |
| `agent-approval-check.yml` | PR events and comments | Requires one human approval on PRs with agent-authored commits |

## Turn-on steps

1. Add the repository secret `CLAUDE_CODE_OAUTH_TOKEN`.
2. Install the Claude GitHub App (https://github.com/apps/claude) on this repository. `claude.yml` and `claude-review.yml` use it, so comments come from claude[bot] and its pushes trigger CI.
3. Create the label `gem-review:fp-candidate` once.
4. Optional variables:
   - `CLAUDE_MODEL`: overrides the model in every workflow (defaults: `claude-opus-5-5` for `claude.yml`, `claude-sonnet-5-5` elsewhere).
   - `CLAUDE_RUNNER=ubuntu-24.04-firewall` once the egress-firewall runner is enrolled (`.github/egress-firewall.yaml`).
   - `CLAUDE_PAUSE=true` pauses every Claude job (kill switch).
5. After one green run of `agent-approval-check`, apply `ci/rulesets/agent-approval.json` with `ci/apply_rulesets.sh`.

## Commands

- `@claude <task>` in an issue or PR.
- `/approve <head-sha>` as a PR comment to approve a PR that contains agent commits.

## Notes

- CI-side Claude has no ForgeCore, so its commits carry no `Gem-Gate:` trailer. Gate locally before merge.
- `agent-approval-check` uses `pull_request_target`, so gem-review reports one MAJOR `PULL_REQUEST_TARGET` finding. It is justified: the job has no checkout and never runs PR code.
- When the subscription limit is hit, Claude jobs fail. Nothing required depends on them.
