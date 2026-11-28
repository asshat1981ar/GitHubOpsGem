# Architecture Decision Records (ADRs 001–003) — Unified Framework v5

## ADR-001: Stateful Protocol Sanitizer & Hybrid Tier Router for DeepSeek V4.1 B200
- **Status**: Accepted (2026-11-09)
- **Context**: Claude Code communicates via Anthropic `/v1/messages`, while Fireworks AI (`accounts/YOUR_ACCOUNT/deployments/YOUR_DEPLOYMENT`) serves `deepseek-v4p1-flash-1017` (755B FP4 on 4x NVIDIA B200 180GB) over OpenAI `/v1/chat/completions`.
- **Decision**: Interpose `DeepSeekProtocolSanitizer` and `litellm_fireworks_config.yaml` to strip `<think>` tokens, repair XML tool tags into JSON `tool_use` blocks, route `LS`/`GlobTool`/`GrepTool` to `local-fast-tier`, and enforce a 2-retry loop circuit breaker.

## ADR-002: Zero-Shared-Context Subspaces & Typed TRIZa Code Mutations
- **Status**: Accepted (2026-11-09)
- **Context**: Multi-agent deliberation in shared context windows suffers from sycophancy and feature bloat.
- **Decision**: Run Six Thinking Hats in isolated sandboxes, log SHA-256 `TRIZMutationReceipt` records prior to AST mutation, and prune via `RICE` and `FMEA RPN <= 120`.

## ADR-003: Pre-Flight Technical Debt & Diff-Hunk Partitioning Gate
- **Status**: Accepted (2026-11-09)
- **Context**: Rapid LLM code integration introduces Fast-Integration Debt, deprecated API drift (`claude --print`), and HTTP 422 review failures on out-of-hunk lines.
- **Decision**: Enforce `LLMTechnicalDebtSensor` (`PSC == 0.00`, `DUR == 0.00`, `AUP == 1.00`) and `DiffHunkValidator` inside Stage 5 (`<PreFlightGate>`).
