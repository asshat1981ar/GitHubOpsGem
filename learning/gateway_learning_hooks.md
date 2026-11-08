# Gateway Learning Hooks — self-improving layer for the DeepSeek B200 gateway

Every guardrail event becomes a structured record; records drive three feedback loops:
rule tuning, prompt (CLAUDE.md) repair, and per-rule fail-closed graduation.

## 1. Event schema (one JSON line per event → `~/.gem/events.jsonl` on each side)

```json
{"ts":"2026-11-08T14:02:11Z","side":"gateway|hook|ci","rule":"THINK_LEAK","decision":"WARN|BLOCK|PASS|REPAIRED|REJECTED",
 "session":"<claude session id>","model":"ds-main","tool":"Bash","repo":"owner/name","detail_sha256":"…","user_override":false}
```
Never log prompt text, diffs, or secrets — only rule id, decision, and a hash of the triggering span.

## 2. Failure taxonomy → route

| Rule / signal | Failure class | What it teaches | Route |
|---|---|---|---|
| THINK_LEAK (stream filter stripped reasoning) | Configuration | Template prefill differs from assumption | If >0 per day with `assume_open=False`, flip default; record model build |
| TOOL_REPAIRED (pseudo-XML/native tokens fixed) | Knowledge gap (model) | DeepSeek ignoring JSON tool schema | >5% of turns → CLAUDE.md patch candidate (prompt debt) + check LiteLLM tool-parser version |
| TOOL_REJECTED (privileged call in text) | Security signal | Model echoed or invented a privileged call | Always surface; 2+ in a session → mark session tainted, require human for writes |
| LOOP_TRIP (same call failed N times) | Capability gap | Missing dependency / wrong command | Write tool-pattern entry; if same signature trips on 3 days → auto-forge task |
| CONTEXT_REJECT (>96k pre-call) | Configuration | Auto-compact threshold too high | Lower CLAUDE_CODE_AUTO_COMPACT_WINDOW by 8k, re-measure |
| COLD_START_HOLD (>60 s) | Transient | Wake latency | Track p50/p95; if p95 > 5 min, raise pre-warm priority (escalation E2) |
| GATE_WARN / GATE_BLOCK | Policy | Rule precision | Feeds graduation (section 3) |
| USER_OVERRIDE (you approved past a WARN) | Possible false positive | Rule too broad | Counts against the rule's precision |

## 3. Per-rule graduation on 2026-11-14 (instead of one global flip)

For each rule after the warn week:
- `hits` = WARN events, `fp` = hits you overrode or marked wrong, `precision = 1 − fp/hits`.
- **Graduate to ENFORCE** if `hits ≥ 3 and precision ≥ 0.9`, or `hits == 0` and the rule is in the
  always-enforce set (protected-branch push, secret in outbound payload, privileged repair).
- **Stay WARN one more week** if `precision < 0.9` → open a tuning task with the top 3 hashed triggers.
- **Never auto-graduate** rules with `hits < 3` outside the always-enforce set — not enough evidence.

This keeps the decision you already made (warn first, then fail closed) and makes the flip data-driven
per rule, so one noisy heuristic (e.g., injection phrasing) cannot force you to roll everything back.

## 4. Session reflection (this analysis)

```
TASK: Digest the v5 bundle, find gaps, engineer fixes, feed the four skills
APPROACH: read every file → executable probes → patch + tests → compile graph → RICE → reflect
OUTCOME: success — 19/19 defects confirmed on v5, 0/19 on v5.1, 80 tests passing
TOOL ISSUES:
  - Probe P08 first returned a false "cleared": its fixture used `error:` lines the v5 regex never matched.
    LESSON: every probe must first assert its fixture actually triggers the code path under test.
  - Adding elision markers pushed CI output to 225 lines (>220 cap); caught by a cap assertion.
    LESSON: when adding annotations to a bounded output, budget for them explicitly.
  - Drafted `fireworks_ai/os.environ/...` in YAML; LiteLLM only substitutes whole `os.environ/VAR` values.
    LESSON: never splice env references inside a string in LiteLLM config.
ROUTE: tool-patterns (all three) — confirmed by direct observation this session
```

## 5. Session reflection — WU-07 lifecycle controller (2026-11-07)

```
TASK: Build the B200 wake/sleep controller with GPU spend caps (WU-07)
APPROACH: research Fireworks + LiteLLM APIs → stdlib controller with injectable client/clock → 9 simulated
          gate scenarios → real-LiteLLM Router integration test → self-review of money paths
OUTCOME: success — dry-run 9/9, 181 tests, callback verified on LiteLLM 1.108.2
CORRECTION (knowledge gap, mine): I had stated Fireworks has no force-scale command. It does:
  PATCH /v1/{deployment}:scale {replicaCount} and `firectl deployment scale --replica-count N`.
  LESSON: before declaring a capability absent, search the API reference index (llms.txt) for the verb,
  not just the CLI flags of the command you already know.
TOOL ISSUES:
  - Cap scenarios overshot by $0.02-$0.07: tripping with one poll interval of headroom ignores the interval
    the deployment bills while draining. LESSON: a hard spend cap needs margin = (poll + drain) intervals,
    and the simulation must assert meter >= simulated bill, not just "stopped near the cap".
  - /status read "unknown" before the first poll (race found by the HTTP test). LESSON: seed state from
    the startup read; key restart-gap logic on "first tick of this process", not "no snapshot yet".
  - Self-review found a single LiteLLM fallback could wake the cold B200 through Fireworks' autoscaler
    (~$2.60 each), violating "heavy or 429 storm only". LESSON: enumerate every path that can start a
    billable resource, including the provider's own autoscaler, and give each an owner.
ROUTE: tool-patterns (all three) + this file; the :scale correction also went into GOAL_CONTRACT evidence
```

New events from the controller (journald JSON, same no-secrets rule): `scale`, `cap_tripped`, `cap_cleared`,
`wake_refused`, `unrequested_wake`, `resumed`, `sleep_skipped`, `check_failed`, `unmetered_gap`. Graduation
input for WU-11: `wake_refused` with `why=cap_*` counts how often the caps bind; if they bind most days the
caps (not the model) are the throughput limit, which is a decision for you, not an automatic change.

## 6. Session reflection — awsbox deploy script (2026-11-07)

```
TASK: One-command awsbox install for the WU-07 controller
OUTCOME: success — deploy_awsbox.sh, ShellCheck clean, 5 end-to-end tests in a scratch root (fake Fireworks +
         stand-in systemctl running the rendered unit as user gem); 190 tests total
CORRECTION #2 (knowledge gap, mine): I told Aaron to run `firectl update deployment <id> --unused-auto-delete-duration 0`.
  `firectl deployment update` has no such flag (create-time only), and the Fireworks SDK/REST Deployment model has no
  auto-delete field at all, so nothing can read or change it after creation.
  LESSON: before handing over a command that mutates a provider resource, check that exact subcommand's flag list,
  not the flags of a sibling command (create != update). Where a setting is unreadable, make the operator's answer
  an explicit, recorded choice (verified / risk accepted / wakes off) instead of a silent assumption.
TOOL ISSUES:
  - Scratch-root installs under umask 027 left intermediate dirs 0750, so the service user could not reach its own
    files; production paths (/opt, /etc) already exist. LESSON: when a test prefix replaces system directories,
    create the replaced parents with system permissions or the test proves less than it seems.
ROUTE: tool-patterns + GOAL_CONTRACT evidence; doc's "Do today" command corrected
```

## 7. Independent review of WU-07 money paths (2026-11-07)

A fresh sub-agent that had not written the code found 3 high, 5 medium and 2 low defects in code that passed
190 of my own tests and a 9/9 simulation. Confirmed by reproduction:
- systemd `EnvironmentFile=` keeps inline `# comments` in values → controller crash-loop under real systemd. My
  test stub loaded the file with `sh`, which strips them, so the test agreed with the bug.
- restart gap: last replica count not persisted → GPU time while the controller was down went unmetered.
- unreadable ledger reset both caps to $0; no fsync before rename.
- uninstall left the B200 up; wake during drain reported ready and was lost; restarts dropped in-flight leases.

LESSONS (route: tool-patterns + this file):
1. A stand-in must reproduce the real component's parsing, not a convenient approximation (systemd ≠ sh).
2. For anything that meters money: persist every input the meter needs across restarts, fsync, and fail toward
   "capped", never toward "zero spent".
3. Self-tests confirm the author's model of the world; an independent adversarial reviewer tests the world.
   Keep "fresh-eyes review for money, secrets, merges" as a non-optional step (now in state/SELF_PROMPT.md).

## 8. Re-review of the WU-07 fixes (2026-11-08)

All 10 original findings verified fixed by the same reviewer; two regressions found in the fix itself:
- R1: LiteLLM retries reuse the call id, so "remember ended ids to ignore late starts" also ignored legitimate
  retries and the idle rule could kill them mid-generation. LESSON: a dedupe rule must be keyed on what the
  upstream actually guarantees (ids are per request, not per attempt); check the producer's retry semantics.
- R2: billing the whole restart gap at the last replica count locked the B200 out for a week after a routine
  uninstall/reinstall ($2,496 metered vs $0.45 billed). LESSON: "fail toward capped" still needs a bound when
  the last known state proves the resource was already going down.
Process: fixer and reviewer were different agents; the reviewer re-ran its own repros against the fix. Keep that
pairing for anything that controls money.
