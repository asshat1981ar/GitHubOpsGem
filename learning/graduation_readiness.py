#!/usr/bin/env python3
"""
Pre-Flight awsbox Deployment & 2026-11-14 Warn-Week Graduation Readiness Check (P-18).
1. Validates `lifecycle/deploy_awsbox.sh` syntax (`bash -n`).
2. Validates `gateway/litellm_config.v7.yaml` required aliases (`ds-main`, `ds-fast`, `ds-burst`) and master_key.
3. Simulates the `2026-11-14` (`GEM_ENFORCE_AFTER=2026-11-14`) warn-week flip using `mcp_reference_monitor.py`.
"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path
import subprocess
import sys

GEM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GEM_ROOT))
import mcp_reference_monitor as m  # noqa: E402


def check_readiness() -> dict:
    # 1. Validate deploy_awsbox.sh syntax
    deploy_sh = GEM_ROOT / "lifecycle/deploy_awsbox.sh"
    r_sh = subprocess.run(["bash", "-n", str(deploy_sh)], capture_output=True, text=True, timeout=15)
    sh_ok = r_sh.returncode == 0

    # 2. Validate litellm_config.v7.yaml structure
    cfg_text = (GEM_ROOT / "gateway/litellm_config.v7.yaml").read_text(encoding="utf-8")
    yaml_ok = all(tok in cfg_text for tok in ("model_name: ds-main", "model_name: ds-fast", "model_name: ds-burst", "master_key: os.environ/LITELLM_MASTER_KEY"))

    # 3. Verify GEM_ENFORCE_AFTER=2026-11-14 flips WARN -> ENFORCE on/after 2026-11-14
    cfg = m.GemConfig.from_env({"GEM_ENFORCEMENT": "WARN", "GEM_ENFORCE_AFTER": "2026-11-14"})
    mode_before = cfg.effective_mode(today=_dt.date(2026, 11, 12))
    mode_on_flip = cfg.effective_mode(today=_dt.date(2026, 11, 14))
    flip_ok = (mode_before == m.EnforcementMode.WARN and mode_on_flip == m.EnforcementMode.ENFORCE)

    return {
        "deploy_script_syntax_ok": sh_ok,
        "litellm_v7_config_ok": yaml_ok,
        "enforce_flip_2026_11_14_ok": flip_ok,
        "all_ready": sh_ok and yaml_ok and flip_ok,
    }


if __name__ == "__main__":
    res = check_readiness()
    print(res)
    sys.exit(0 if res["all_ready"] else 1)
