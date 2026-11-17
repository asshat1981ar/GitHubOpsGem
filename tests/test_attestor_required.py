"""ENFORCE must not allow a write on a local-only verdict (no ForgeCore attestor configured).

The local HMAC signature is a dev fallback and "never counts as evidence" (README, CLAUDE.md). Before this
change a session without AUTODEV_URL / AUTODEV_API_BEARER_TOKEN silently got PASS on a feature-branch push in
ENFORCE. WARN mode keeps the fallback so the warn week can still collect data.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import mcp_reference_monitor as m  # noqa: E402

ENFORCE = m.GemConfig(deployment_id="accounts/t/deployments/t", mode=m.EnforcementMode.ENFORCE)
WARN = m.GemConfig(deployment_id="accounts/t/deployments/t", mode=m.EnforcementMode.WARN)


@pytest.fixture(autouse=True)
def _no_forgecore_env(monkeypatch):
    for name in ("AUTODEV_URL", "GEM_FORGECORE_URL", "AUTODEV_API_BEARER_TOKEN"):
        monkeypatch.delenv(name, raising=False)


def mon(cfg):
    return m.StatefulGitHubOpsMonitor(config=cfg, signer=m.ReceiptSigner(b"test-key"))


def test_enforce_blocks_a_feature_branch_push_without_an_attestor():
    gd = mon(ENFORCE).evaluate_write("push_files", "feat/x")
    assert gd.decision == "BLOCK" and not gd.allowed
    assert "attestor" in gd.violations[-1].lower()
    assert gd.facts["attestation"] == "not_configured"


@pytest.mark.parametrize("tool", ["push_files", "create_or_update_file", "git_push", "create_pull_request"])
def test_enforce_blocks_every_write_tool_without_an_attestor(tool):
    assert not mon(ENFORCE).evaluate_write(tool, "feat/x").allowed


def test_warn_mode_keeps_the_local_fallback():
    gd = mon(WARN).evaluate_write("push_files", "feat/x")
    assert gd.allowed and gd.decision == "PASS"
    assert gd.signature  # local HMAC, still not evidence


def test_enforce_does_not_block_a_non_write_tool_without_an_attestor():
    assert mon(ENFORCE).evaluate_write("add_issue_comment", "feat/x").allowed
