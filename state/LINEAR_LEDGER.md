# Linear Deployment Ledger — GitHubOpsGem v5.7.0 (Generated from state/spec.yaml)

- **Version**: `5.7.0`
- **Enforce Flip Date**: `GEM_ENFORCE_AFTER` in `gateway/claude-gem.env`
- **Serverless Cap**: `$10/day` (`openai/accounts/fireworks/models/deepseek-v4p1-flash-1017`)
- **Dedicated B200 Caps**: `$26/day`, `$78/week`
- **Active Enforcement Points**:
  1. `gateway/gem_guardrail.py` (`GemGuardrail` pre-call, success and streaming iterator hooks; `gateway/conformance_check.py` 6/6)
  2. `hooks/gem_pretool.py`, `hooks/gem_session_start.py`, `hooks/gem_session_end.py`
  3. `lifecycle/gem_lifecycle.py` + `gateway/gem_lifecycle_callback.py`
  4. `.github/workflows/gem-review.yml` (SHA-pinned server-side check)
