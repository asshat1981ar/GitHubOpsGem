# GitHubOpsGem v5.7.0 — Operational Knowledge Pack (Generated from state/spec.yaml)

## 1. Gateway & Lifecycle Architecture
- **Fast / Default Tiers (`ds-main`, `ds-fast`)**: `openai/accounts/fireworks/models/deepseek-v4p1-flash-1017` ($10/day LiteLLM cap).
- **Burst Tier (`ds-burst`)**: Dedicated 4xB200 controlled by `lifecycle/gem_lifecycle.py` ($26/day, $78/week caps; 180s idle sleep; 45s post-session sleep).
- **Streaming Guardrail (`gateway/gem_guardrail.py`)**: Rejects input over 96,000 tokens before the call, strips split `<think>` tags via `ThinkStreamFilter`, and repairs leaked tool calls in non-streaming responses only for `Read`, `Grep`, `Glob`, `LS`; streams are never repaired.

## 2. Enforcement & Attestation
- **Warn-Week Flip Date**: `GEM_ENFORCE_AFTER` (`WARN` -> `ENFORCE`), set in `gateway/claude-gem.env`; never copied into generated files.
- **ForgeCore Authority**: `autodev-server` signs gate verdicts (`ADR-007`); `gemctl trailer` embeds and verifies `Gem-Gate:` git commit trailers.
