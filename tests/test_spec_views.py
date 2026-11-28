"""Single-source spec views (state/spec.yaml) and the gem-review workflow scan (ported from gem-v5.8 in GC-001)."""
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PY = sys.executable
GEMCTL = os.path.join(ROOT, "gemctl.py")
RENDER = os.path.join(ROOT, "state", "render_spec.py")


def test_single_source_spec_views_are_byte_identical_and_clean():
    r = subprocess.run([PY, RENDER, "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "5/5 spec views byte-identical" in r.stdout
    for rel in ("CLAUDE.md", "SKILL.md", "references/gem_knowledge_pack.md", "state/LINEAR_LEDGER.md", "state/GEM_INTENT.md"):
        content = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        assert not any(ord(ch) < 32 and ord(ch) not in (9, 10, 13) for ch in content), f"control char in {rel}"
        assert "GlobTool" not in content and "GrepTool" not in content
        assert "WARN` until `GEM_ENFORCE_AFTER`" in content or rel != "CLAUDE.md"


def test_no_generated_view_hardcodes_an_enforce_date():
    import re
    for rel in ("CLAUDE.md", "SKILL.md", "references/gem_knowledge_pack.md", "state/LINEAR_LEDGER.md", "state/GEM_INTENT.md"):
        content = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        assert not re.search(r"20\d\d-\d\d-\d\d", content), f"date in {rel}: the flip date belongs in claude-gem.env"


def test_gem_review_workflow_passes_scanner_with_zero_critical():
    wf_path = os.path.join(ROOT, ".github", "workflows", "gem-review.yml")
    lines = ["+" + line for line in open(wf_path, encoding="utf-8").read().splitlines()]
    patch = f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join(lines) + "\n"
    r = subprocess.run([PY, GEMCTL, "scan-diff", "--path", ".github/workflows/gem-review.yml", "--fail-on-critical"],
                       input=patch, capture_output=True, text=True)
    out = json.loads(r.stdout)
    assert r.returncode == 0 and out["critical"] == 0
