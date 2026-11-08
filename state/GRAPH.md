# Workflow Graph — GC-007: GitHubOpsGem v5 → enforced runtime

> Living document. Update after EVERY node completion or failure.
> Status legend: ⬜ pending · 🟢 runnable · 🟡 in-progress · 🔵 blocked · ✅ done · ❌ failed-escalated

## Status Board

| ID | Name | Binding | Depends on | Gate | Status |
|----|------|---------|-----------|------|--------|
| WU-01 | Adversarial audit with executable probes | github-ops-orchestrator + bash | — | probes.py runs; every finding has a probe | ✅ |
| WU-02 | gemcore v5.1 patch + regression suite | bash/pytest | WU-01 | 80 tests pass; probes 0/19 on v5.1, 19/19 on v5 | ✅ |
| WU-03 | Gateway config v6 + client env (draft) | bash | WU-01 | YAML parses; aliases cover every CLAUDE tier; conformance (WU-06) | 🟡 |
| WU-04 | `gemctl` CLI | bash/pytest | WU-02 | subcommands JSON/exit-code tested; stdlib only | ✅ |
| WU-05 | LiteLLM `gem_guardrail.py` plugin | bash + Context7 (LiteLLM docs) | WU-02, WU-03 | unit tests with mocked streams; litellm boots with guardrail | 🟢 |
| WU-06 | Gateway conformance harness (= PRO-78 open criterion: live smoke on AutoDev + Chimera worktrees) | bash on awsbox (human runs) | WU-03, WU-05 | 6/6 checks green against live gateway on both worktrees | ⬜ |
| WU-07 | Deployment lifecycle controller | bash + systemd + LiteLLM callback | WU-04 | dry-run: idle 3m→sleep, SessionEnd+45s→sleep, cap trips, auto-delete guard | ✅ (dry-run 9/9; live run on awsbox pending) |
| WU-08 | Claude Code policy hooks (Termux) | bash | WU-04, WU-07 | hook tests: push main WARN/BLOCK, MCP write gated, wake/sleep fired | ⬜ |
| WU-09 | ForgeCore-signed verdicts (ADR-007) → git trailers | AutoDev PR #55 + bash | WU-08 | kernel attest/verify live; trailer carries attestation_id; /verify rejects tampered | 🟡 (PR #55 draft; trailers pending) |
| WU-10 | Server-side gem-review workflow + rulesets | github MCP + github-ops-orchestrator | WU-04 | required check on pilot repo; workflow passes its own scanner | ⬜ (needs confirm) |
| WU-11 | Warn-week telemetry → per-rule graduation | self-improving-proactive-agent | WU-08 (+7 days) | report with hits/FP per rule; graduated rules listed | ⬜ |
| WU-12 | Skill & CLAUDE.md repair | skill-creator / propose_skills | WU-02 | no control chars; current tool names; no dangling refs | 🟢 |
| WU-13 | Opal Gem → report-only UI | bash | WU-04 | dashboard renders only computed fields; label v5.1 | ⬜ |
| WU-14 | Tech-debt sensor v2 (real DUR/AUP) | bash + language toolchains | WU-04 | DUR from compiler/linter output; AUP from symbol resolution | ⬜ |
| WU-15 | aTRIZ-SWE v2 advisory engine | agent-swarm / bash | WU-05, WU-14 | schema-validated contradiction JSON; FMEA register | ⬜ (v2) |
| WU-16 | Delivery: DoD verification report | workflow-kernel | WU-06..WU-12, WU-17 | every DoD item has artifact evidence | ⬜ |
| WU-17 | Single-source spec → generated CLAUDE.md / SKILL.md / ledger / Gem intent | bash + skill-creator | WU-12 | one `spec.yaml`; 5 views regenerate byte-identical; no version drift | 🟢 |
| WU-18 | Evidence sync to Linear (PRO-78, Deployment Ledger) | Linear MCP (writes need your OK) | WU-06, WU-09 | each gate/conformance result posted with receipt hash | ⬜ |

Critical path: WU-02 → WU-04 → WU-07 → WU-08 → WU-11 (the warn-week clock starts when WU-08 ships).
Parallel now: WU-04 ∥ WU-05 ∥ WU-12.

## Workflow Units

```yaml
workflow_unit:
  id: WU-04
  name: gemctl CLI + package layout
  binding: sdlc-forge:phase-3 (implementation), bash
  inputs:
    - {artifact: gem/mcp_reference_monitor.py, from: WU-02}
  outputs:
    - artifact: gemcore/ package (sanitize, diff, scanners, abi, ci_log, debt, atriz, gate, receipts) + gemctl entrypoint
  gate:
    - "gemctl scan-diff --json < fixture.patch matches golden output"
    - "gemctl gate --tool push_files --branch refs/heads/main exits 2 in ENFORCE, 0 + warning in WARN"
    - "stdlib-only import check passes (Termux)"
  on_fail: retry(2) → reflect → auto-forge → escalate
  parallelizable_with: [WU-05, WU-12]
  est_tool_calls: 12   # >5 → planning-with-files breakdown first
```

```yaml
workflow_unit:
  id: WU-05
  name: LiteLLM gem_guardrail plugin
  binding: bash; Context7 for current LiteLLM CustomGuardrail signatures
  inputs:
    - {artifact: gem/mcp_reference_monitor.py (ThinkStreamFilter, repair_tool_calls_detailed), from: WU-02}
    - {artifact: gem/gateway/litellm_config.v6.yaml, from: WU-03}
  outputs:
    - artifact: gateway/gem_guardrail.py
    - artifact: gateway/tests/test_guardrail.py
  gate:
    - "async_pre_call_hook rejects >96k-token requests with an Anthropic-shaped context error"
    - "async_post_call_streaming_iterator_hook removes split <think> tags across chunks (fixtures)"
    - "rejected privileged repairs are surfaced as text, never as tool_use"
    - "litellm boots with the guardrail enabled (local, mock model)"
  on_fail: retry(2) → reflect → auto-forge → escalate
  parallelizable_with: [WU-04, WU-12]
  est_tool_calls: 15
```

```yaml
workflow_unit:
  id: WU-07
  name: Deployment lifecycle controller
  binding: bash, docker skill (systemd unit on awsbox)
  inputs:
    - {artifact: gemcore package, from: WU-04}
  outputs:
    - artifact: controller/gemctl_lifecycle.py (POST /wake, POST /sleep?delay=45, GET /status)
    - artifact: controller/gem-lifecycle.service
  gate:
    - "dry-run clock: no traffic 180 s → scale-down issued"
    - "SessionEnd signal → scale-down at +45 s unless a new session wakes it"
    - "GPU-second meter × configured $/GPU-hour × 4 GPUs trips the daily cap and refuses /wake"
    - "startup check fails loudly if unused-auto-delete is not disabled"
  on_fail: retry(2) → reflect → auto-forge → escalate
  parallelizable_with: [WU-05]
  est_tool_calls: 14
```

```yaml
workflow_unit:
  id: WU-08
  name: Claude Code policy hooks (user-level, Termux)
  binding: bash
  inputs:
    - {artifact: gemctl, from: WU-04}
    - {artifact: lifecycle controller /wake /sleep, from: WU-07}
  outputs:
    - artifact: hooks/pretool_gate.py, hooks/session_wake.sh, hooks/session_sleep.sh, settings.snippet.json
  gate:
    - "Bash: git push [--force] to protected ref → WARN (exit 0 + stderr) / BLOCK (exit 2)"
    - "mcp__github__push_files|create_or_update_file|merge_pull_request routed through gemctl gate"
    - "SessionStart prints enforcement mode into context; SessionEnd schedules sleep"
  on_fail: retry(2) → reflect → auto-forge → escalate
  parallelizable_with: [WU-10]
  est_tool_calls: 12
```

```yaml
workflow_unit:
  id: WU-10
  name: Server-side enforcement
  binding: github MCP (create_branch, create_or_update_file, create_pull_request), github-ops-orchestrator
  inputs:
    - {artifact: gemctl, from: WU-04}
  outputs:
    - artifact: .github/workflows/gem-review.yml (reusable, workflow_call, pull_request trigger, read-only permissions, SHA-pinned)
    - artifact: PR on pilot repo adding the caller workflow
  gate:
    - "gem-review.yml passes gemctl scan-diff on itself (0 CRITICAL)"
    - "ruleset requires the check on the default branch (human confirms — external, hard to reverse)"
  on_fail: retry(2) → reflect → escalate
  parallelizable_with: [WU-08]
  est_tool_calls: 10
```

## Checkpoint Log

| When | Node | Event | State vector |
|------|------|-------|--------------|
| 2026-11-07 | WU-01 | done: 19/19 probes confirm defects in v5 | `Kernel: GC-007 GitHubOpsGem runtime — done WU-01..02, active WU-03 (draft), runnable WU-04/05/12` |
| 2026-11-07 | WU-02 | done: v5.1, 80 tests, probes 0/19 | ↑ |
| 2026-11-07 | WU-07 | awsbox deploy script (idempotent, DRY-first, auto-delete choice recorded, ShellCheck clean, 5 e2e tests); corrected: auto-delete is create-time only and unreadable via API; 190 tests | `Kernel: GC-007 — done WU-01..04, 07 (+deploy), 08, 09a; next: human deploy on awsbox, then WU-05` |
| 2026-11-07 | WU-07 | lifecycle controller v1.0 (Fireworks `:scale` API, GPU-second meter, $26/day + $78/week caps, idle 180 s, SessionEnd +45 s, 429-storm wake, stray-wake undo, auto-delete/min-replica guard), LiteLLM callback verified on LiteLLM 1.108.2 Router, `gemctl heavy`, SessionEnd hook; dry-run 9/9; 181 tests | `Kernel: GC-007 — done WU-01..04, 07, 08, 09a; next WU-05, then WU-06 live (awsbox), WU-11 on 2026-11-14` |
| 2026-11-07 | WU-04/08 | gemctl + hooks + installer, 125 tests; e2e: main push denied+signed, feature push PASS, force push WARN, all attested; AutoDev PR #56 CI fix (Kotlin green), ported to #55 | `Kernel: GC-007 — done WU-01..04, 08, 09a; next WU-07, WU-05, WU-11 (2026-11-14)` |
| 2026-11-07 | WU-09a | ForgeCore attestation: kernel module + routes, 14 Rust tests, gemcore v5.3 client, 5/5 e2e; AutoDev PR #55 (draft) | `Kernel: GC-007 — done WU-01..02b, WU-09a; active WU-03; runnable WU-04/05/12/17` |
| 2026-11-07 | WU-02b | done: v5.2 encodes unified-spec rules (strict fast-integration, policy calls, JSON-catch smells); 93 tests | `Kernel: GC-007 — done WU-01..02b, active WU-03 (draft), runnable WU-04/05/12/17` |

## Handoff Note

- **Done:** WU-01 audit, WU-02/02b gemcore, WU-04 gemctl, WU-07 lifecycle controller (dry-run 9/9), WU-08 hooks
  (PreToolUse, SessionStart, SessionEnd) + installer, WU-09a ForgeCore attestation (AutoDev PR #55, draft).
- **Next runnable:** WU-05 LiteLLM guardrail (stream think-strip). Human: deploy WU-07 on awsbox in DRY mode,
  install hooks on Termux (starts the warn week), merge AutoDev #56 then review #55.
- **Exact resume point:** `gateway/gem_guardrail.py` — `async_post_call_streaming_iterator_hook` wrapping
  `gemcore.ThinkStreamFilter`; test against LiteLLM 1.108.2 (installed in the workspace) like WU-07's callback.
- **Open assumptions:** $13/GPU-hour B200 rate; GEM_ENFORCE_AFTER=2026-11-14; the REST deployment response may
  omit the auto-delete field (operator sets GEM_AUTODELETE_VERIFIED=1 after `firectl get deployment`).
- **Pending gate failures:** WU-03 cannot pass until WU-06 runs against the live gateway; WU-07's live gate
  (B200 reaches zero within the window after a heavy run) needs the awsbox deployment.
