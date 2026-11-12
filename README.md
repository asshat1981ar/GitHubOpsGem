# GitHubOpsGem v5.7 (GC-007)

| Path | What |
|---|---|
| `mcp_reference_monitor.py` | gemcore v5.4 (v5.1 audit fixes, v5.2 unified-spec rules, v5.3 ForgeCore client, v5.4 shell-push coverage) |
| `tests/` | 379 tests — `python3 -m pytest -q` (the deploy end-to-end tests need root) |
| `gemctl.py` | CLI: `scan-diff`, `debt`, `gate`, `ci-window`, `strip`, `verify`, `heavy on/off/status`, `trailer add/note/verify/install-hook`, `version`; JSON out, exit 2 = BLOCK |
| `gem_trailers.py` | `Gem-Gate:` commit trailers + `refs/notes/gem-gate` attestations, verified against ForgeCore (WU-09b) |
| `hooks/gem_pretool.py` | Claude Code PreToolUse gate for `git push`, `gh pr merge` and GitHub MCP writes; always denies the model operating the B200 |
| `hooks/gem_fileguard.py` | Fast stdlib guard: file tools never touch the B200 operator credentials |
| `hooks/gem_session_start.py` | Tells each session its mode, flip date, ForgeCore reachability and B200 state; registers the session |
| `hooks/gem_session_end.py` | Tells the lifecycle controller the session ended (B200 sleeps 45 s after the last one) |
| `lifecycle/gem_lifecycle.py` | WU-07 controller (awsbox): wake/sleep, GPU-second meter, $26/day + $78/week caps, auto-delete guard; `dryrun` replays the gate |
| `lifecycle/deploy_awsbox.sh` | One-command, idempotent install/upgrade/uninstall on awsbox (ShellCheck-clean, tested end to end) |
| `lifecycle/gem-lifecycle.service`, `lifecycle/lifecycle.env.example` | systemd unit (hardened) and its environment file |
| `gateway/gem_lifecycle_callback.py` | LiteLLM callback: ds-burst traffic keeps the B200 awake, ds-main 429 storms wake it |
| `gateway/gem_guardrail.py` | LiteLLM guardrail: strips `<think>` from streamed and non-streamed output on `/v1/messages` and `/chat/completions` (WU-05) |
| `.github/workflows/gem-review.yml`, `gem-review-pr.yml` | Reusable server-side review (scan-diff + debt, read-only, SHA-pinned) and this repo's own PR check |
| `ci/requirements-gem-review.txt` | The review workflow's one PyPI dependency (PyYAML, exact version, sha256 of every wheel); installed with `pip --require-hashes`. The CWE-94 scanner parses whole workflow files with it and falls back to fail-closed line heuristics without it |
| `ci/rulesets/*.json`, `ci/apply_rulesets.sh` | Branch + tag rulesets; the owner applies them with `gh` |
| `state/SELF_PROMPT.md` | Standing directive for autonomous runs (loop, guardrails, self-correction checklist) |
| `gem_lifecycle_client.py` | Client used by `gemctl heavy` and the session hooks |
| `install_hooks.py` | Installs into `~/.gem` and merges the hooks into `~/.claude/settings.json` (idempotent, backup, `--remove`) |
| `probes.py` | 19 adversarial probes — `python3 -I probes.py <module.py>` |
| `probe_results.json` / `probe_results_v5.2.json` | 19/19 defects on v5, 0/19 on v5.2+ |
| `gateway/litellm_config.v7.yaml` | DRAFT gateway config: serverless-first, B200 burst, $10/day serverless budget (not yet run against LiteLLM) |
| `e2e_forgecore.py` | End-to-end check against a running autodev-server (ADR-007, AutoDev PR #55) |
| `gateway/claude-gem.env` | Claude Code client env for Termux |
| `CLAUDE.md` | v5.1 operational profile (repo-agnostic) |
| `state/GOAL_CONTRACT.yaml`, `state/GRAPH.md`, `tasks/QUEUE.md` | workflow-kernel state — resume from GRAPH.md |
| `pm/backlog.csv`, `pm/rice_report.txt` | RICE inputs and output |
| `learning/gateway_learning_hooks.md` | event schema, failure taxonomy, per-rule graduation |

Required env on any host using the library: `GEM_DEPLOYMENT_ID`, `GEM_ENFORCEMENT` (WARN|ENFORCE),
optional `GEM_ENFORCE_AFTER` (YYYY-MM-DD). For ForgeCore signing: `AUTODEV_URL` + `AUTODEV_API_BEARER_TOKEN`
(and `GEM_REPOSITORY`). `GEM_RECEIPT_KEY` is a local dev fallback only and never counts as evidence.

## Install on Termux

```bash
unzip gem-v5.4.zip -d ~/gem-src && cd ~/gem-src
python3 install_hooks.py            # copies to ~/.gem, merges hooks, backs up settings.json
source gateway/claude-gem.env       # mode, flip date, ForgeCore URL + bearer
claude                              # then run /hooks to confirm both hooks are listed
```

## Deploy the B200 controller on awsbox (WU-07)

```bash
unzip gem-v5.6.zip -d ~/gem-src && cd ~/gem-src/gem
sudo ./lifecycle/deploy_awsbox.sh --litellm-dir <your LiteLLM config dir>   # first run: DRY mode
```

The script is idempotent: preflight (Python 3.9+, tz data, systemd, a 9/9 self-test on this host), `gem` service user,
`/opt/gem`, `/etc/gem/lifecycle.env` (0640 root:gem; prompts for the Fireworks key, generates the controller token,
never prints either), a live check of the deployment, the hardened systemd unit, a health and status probe, and the
LiteLLM callback. It asks once about auto-delete, which the Fireworks API can't report:

- `--autodelete-off` — the deployment was created with `--unused-auto-delete-duration 0`
- `--accept-autodelete-risk` — it may auto-delete after 7 idle days; wakes allowed, status shows days since last use
- neither — the controller refuses wakes (sleep and caps still work)

`--fix-window` sets Fireworks' backstop to 5 min through your `firectl`; `--live` leaves DRY mode after a few days of
logs (`journalctl -u gem-lifecycle -f`); `--uninstall [--purge]` removes it. Re-run any time to upgrade in place.
From Termux: `gem heavy on` (waits until ready, then `/model ds-burst`), `gem heavy off`, `gem heavy status`.

Remove with `python3 install_hooks.py --remove`. Events go to `~/.gem/events.jsonl` (one line per gated write,
no prompt text or diffs) for the 2026-11-14 per-rule graduation report.
