# Inventory: code, CI, tools, skills, agents

Snapshot of what exists and what can be used to work on it. Line counts are `wc -l` at the time of writing and
are informational (the test only checks that every module is listed). Agent names below are the ones
`state/ASSIGNMENTS.yaml` may use; `tests/test_assignments.py` reads the "Agent types" list from this file.

Status key: **usable** · **needs-auth** (a human must authorize it, the agent cannot) · **failed** (configured but
did not connect in the session this was written) · **out-of-scope** (reachable only for other repositories).

## Code modules

| Module | Lines | Role |
|---|---|---|
| `mcp_reference_monitor.py` | 3033 | gemcore: scanners, gate (`evaluate_write`), ForgeCore client, enforcement mode |
| `lifecycle/gem_lifecycle.py` | 1615 | B200 lifecycle controller: wake/sleep, GPU-second meter, $26/day and $78/week caps |
| `lifecycle/deploy_awsbox.sh` | 527 | Idempotent awsbox install/upgrade/uninstall |
| `gem_trailers.py` | 452 | `Gem-Gate` commit trailers and `refs/notes/gem-gate` attestations |
| `gateway/gem_guardrail.py` | 443 | LiteLLM guardrail: `<think>` stripping, budgets |
| `ci/gem_review_steps.py` | 370 | Steps of the reusable gem-review workflow |
| `gemctl.py` | 330 | CLI: `scan-diff`, `debt`, `gate`, `ci-window`, `strip`, `verify`, `heavy`, `trailer`, `version` |
| `hooks/gem_pretool.py` | 330 | Claude Code PreToolUse gate for pushes, merges and GitHub MCP writes |
| `probes.py` | 221 | 19 adversarial probes |
| `gateway/gem_lifecycle_callback.py` | 123 | LiteLLM callback: burst traffic keeps the B200 awake |
| `install_hooks.py` | 118 | Installs hooks into `~/.gem` and `~/.claude/settings.json` |
| `hooks/gem_session_start.py` | 89 | Reports mode, flip date, ForgeCore reachability, B200 state |
| `gem_lifecycle_client.py` | 86 | Client for `gemctl heavy` and the session hooks |
| `e2e_forgecore.py` | 44 | End-to-end check against a running autodev-server |
| `hooks/gem_session_end.py` | 37 | Tells the controller the session ended |
| `hooks/gem_fileguard.py` | 30 | Fast guard: file tools never touch B200 operator credentials |
| `ci/apply_rulesets.sh` | 23 | Applies `ci/rulesets/*.json` with `gh` |

Tests live in `tests/` (about 500 cases; CI's `pytest` check is the count of record).

## CI and policy

| Item | Detail |
|---|---|
| Required checks on `main` | `gem-review / scan`, `pytest` (`ci/rulesets/main.json`) |
| Workflows | `.github/workflows/tests.yml`, `gem-review.yml`, `gem-review-pr.yml` |
| Code owner | `@asshat1981ar` for everything; `.github/`, `ci/`, `hooks/`, `lifecycle/`, `mcp_reference_monitor.py` listed explicitly |
| Gate paths | `mcp_reference_monitor.py`, `lifecycle/`, `hooks/`, `ci/`, `.github/`: implementer and reviewer must differ |

## Tools (this environment)

| Tool group | Status | Use |
|---|---|---|
| Bash, Read, Edit, Write, Glob, Grep | usable | All repo work |
| GitHub MCP for this repo (PRs, checks, files) | usable | Draft PRs, CI status |
| Agent, TaskCreate/Update, Skill | usable | Delegation, tracking |
| ReadNotifications, PR subscription | usable | CI and review events |
| WebSearch, WebFetch, Firecrawl, Tavily, Context7 | usable | Research; read current docs before using an external API |
| Other repos (AutoDev, GitOPS, coderabbit-control-plane) | out-of-scope | Git reads only; no API |
| Linear | failed | Needed by WU-18; reconnect is a human step |
| Cloudflare Developer Platform | failed | Not used by this repo |
| Slack, Datadog, PagerDuty, HubSpot, BigQuery, Hex, and other OAuth connectors | needs-auth | Not required by any open unit |

## Agent types

Names are exact `subagent_type` values.

- `general-purpose`
- `Explore`
- `Plan`
- `agent-protocols:code-reviewer`
- `agent-protocols:security-auditor`
- `agent-protocols:test-engineer`
- `agent-protocols:documentation-specialist`
- `agent-protocols:release-engineer`
- `agent-protocols:spec-analyst`
- `agent-protocols:performance-engineer`

Not used here: `vercel:*`, `statusline-setup`, `claude-code-guide`, `agent-protocols:accessibility-specialist`.

## Skills used by the assignment rules

| Skill | Used for |
|---|---|
| `agent-protocols:test-driven-development` | Failing-first implementation (default) |
| `agent-protocols:documentation-and-adrs` | CLAUDE.md, handoff and decision text |
| `agent-protocols:research-spike-and-poc` | v2 backlog items (spike before build) |
| `agent-protocols:security-and-hardening` | Reviews of gate-path changes |
| `agent-protocols:shipping-and-launch` | Delivery and DoD reporting |
| `agent-protocols:spec-driven-development` | Single-source spec work |
| `code-review`, `security-review`, `simplify` | Review passes on a diff |

Other installed skills (`vercel:*`, `ui-ux-behaves:*`, `huggingface-skills:*`, `marketing:*`, `data:*`, and similar) do
not apply to this repository.

## Human-only gates

See `state/ASSIGNMENTS.yaml` (`human_gates`). They are decisions or actions on Aaron's machines that no agent may
take: the enforce date, ForgeCore deployment (AutoDev PRs #55/#56), the awsbox deploy, the Termux hook install,
and the Linear reconnect.
