# Build and test (GitHubOpsGem)

CLAUDE.md is the repo-agnostic operational profile; the commands for this repo live here (R4).

- Tools (same pins as CI): `python -m pip install pytest==9.1.1 PyYAML==6.0.3 litellm==1.108.2 actionlint-py==1.7.12.25 zizmor==1.32.0 shellcheck-py==0.11.0.1`
- Tests (the required "pytest" check): `python -m pytest -q --ignore=tests/test_deploy.py`
- Deploy end-to-end tests need root (they create the `gem` user): `sudo -E env "PATH=$PATH" "$(command -v python)" -m pytest -q tests/test_deploy.py`
- Python 3.12, as in `.github/workflows/tests.yml`. If a local run fails where CI passes (for example a missing jinja2), trust CI and note it (S11).
- Lint is not enforced yet (R10): `ruff check --select E4,E7,E9,F .` reports a backlog to fix before the check is turned on.
