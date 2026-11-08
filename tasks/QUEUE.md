# Task Queue — GC-007 (mirrors state/GRAPH.md for the autonomy kit loop)

## 🟢 Ready
- [ ] Deploy WU-07 on awsbox (human): `sudo ./lifecycle/deploy_awsbox.sh --litellm-dir <dir>` (DRY first), `--live` after a few days of logs
- [ ] WU-05 LiteLLM gem_guardrail plugin (stream think-strip, allowlisted repair, budgets, cold-start hold)
- [ ] WU-12 Repair SKILL.md / CLAUDE.md (control chars, tool names, dangling scripts/, repo-agnostic)
- [ ] WU-17 Single-source spec: one spec.yaml generating CLAUDE.md, SKILL.md, knowledge pack, Linear ledger, Gem intent

## 🟡 In progress
- [ ] WU-03 Gateway config v6 + client env — blocked on live conformance (WU-06)

## ⬜ Waiting on dependencies
- [ ] WU-06 Conformance harness (needs live gateway on awsbox — human runs)
- [ ] Install WU-08 hooks on Termux (`python3 install_hooks.py`) — starts the warn-week clock
- [ ] WU-09b Git trailers carrying ForgeCore attestation_id (needs WU-08); merge AutoDev PR #55 after CI
- [ ] WU-10 Server-side gem-review workflow (needs WU-04; confirm before rulesets)
- [ ] WU-11 Warn-week graduation report (needs WU-08 + 7 days)
- [ ] WU-13 Opal Gem → report-only UI
- [ ] WU-14 Tech-debt sensor v2
- [ ] WU-18 Evidence sync to Linear PRO-78 + Deployment Ledger (writes need confirmation)
- [ ] WU-16 Delivery / DoD report

## 🧊 v2 backlog
- [ ] WU-15 aTRIZ-SWE advisory engine (schema-validated contradictions, FMEA register)
- [ ] LATS search over candidate patches with test-runner value function
- [ ] Z3/SMT invariant discharge for arithmetic/bounds properties

## ✅ Done
- [x] WU-01 Adversarial audit — 19 probes, 19 confirmed on v5
- [x] WU-02 gemcore v5.1 — 80 tests, 0/19 probes on v5.1
- [x] WU-02b gemcore v5.2 — unified-spec rules, 93 tests
- [x] WU-04 gemctl CLI (stdlib, JSON, exit 2 = BLOCK)
- [x] WU-08 Claude Code hooks + installer, e2e against real autodev-server (SessionEnd hook added with WU-07)
- [x] WU-07 deploy script `lifecycle/deploy_awsbox.sh` — idempotent install/upgrade/uninstall, 5 e2e tests; 190 tests
- [x] WU-07 Lifecycle controller v1.0 — dry-run 9/9 (idle, SessionEnd, daily/weekly caps, stray wakes, 429 storm, guard); 181 tests
- [x] AutoDev PR #56: CI setup-android fix (ported to #55)
- [x] WU-09a ForgeCore attestation (ADR-007) — AutoDev PR #55 draft, gemcore v5.3 client, 5/5 e2e
- [x] Decisions: serverless-first fast tier, no-wait cold starts, $10/day serverless + $26/day / $78/week B200 caps
