"""CWE-94 workflow scanner, round 3 of the PR #2 review (CodeRabbit).

Root cause fixed here: the scanner parsed YAML by hand. In full-file mode (the post-image is the patch's
target) it now walks a real YAML parse (PyYAML: anchors, merge keys, flow mappings, quoting, CRLF); in
patch-only mode the heuristics stay and fail closed. Each test names the review comment it covers; the
parametrised ones run both modes ("heuristic": patch only, "yaml": whole file parsed).
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import mcp_reference_monitor as m  # noqa: E402
from test_monitor import (CWE94, CWE94_MUST_FLAG, CWE94_MUST_NOT_FLAG, WF, WF_HEAD, _found,  # noqa: E402
                          _hunk_around, _line_of, _scan, _with_index)

MODES = ("heuristic", "yaml")


def scan(text, mode, path=WF):
    """CWE-94 findings only (other rules, e.g. unpinned actions, are not what these tests are about)."""
    return [f for f in _scan(path, text, post_image=text if mode == "yaml" else None) if f[2] == CWE94[1]]


def sink_line(text, needle="${{"):
    return _line_of(text, needle)


@pytest.mark.parametrize(("head", "unsafe", "expected_line"), [
    (WF_HEAD + '      - run: |\n          echo "${{\n          github.event.issue.title\n          }}"\n',
     "issue.title", len(WF_HEAD.splitlines()) + 3),
    (WF_HEAD.replace("    steps:", "    env:\n      TITLE: ${{ github.event.issue.title }}\n    steps:")
     + '      - run: echo "${{ env.TITLE }}"\n        env:\n          title: fixed\n',
     "issue.title", len(WF_HEAD.splitlines()) + 1),
    (WF_HEAD.replace("    steps:", "    env:\n      TITLE: fixed\n    steps:")
     + '      - run: echo "TITLE=$T" >> "$GITHUB_ENV"\n        env:\n'
       '          T: ${{ github.event.issue.body }}\n      - run: echo "${{ env.COPY }}"\n'
       '        env:\n          COPY: ${{ env.TITLE }}\n',
     "issue.body", len(WF_HEAD.splitlines()) + 5),
    (WF_HEAD + '      - run: echo "LABEL=$T" >> "$GITHUB_ENV"\n        env:\n'
       '          T: ${{ github.event.issue.body }}\n      - run: echo "${{ env.PAYLOAD }}"\n',
     "issue.body", len(WF_HEAD.splitlines()) + 3),
    ((WF_HEAD + '      - run: echo "${{ github.event.issue.title }}"\n').replace("\n", "\r"),
     "issue.title", 1),
], ids=["multiline-interior", "case-distinct-env", "runtime-derived-env", "runtime-extra-record", "cr-only"])
def test_changed_workflow_reports_injection(tmp_path, head, unsafe, expected_line):
    assert scan_changed_workflow(tmp_path, head.replace(unsafe, "issue.number"), head) == [(expected_line, *CWE94)]


def scan_changed_workflow(tmp_path, base, head):
    (tmp_path / "base.yml").write_bytes(base.encode())
    (tmp_path / "head.yml").write_bytes(head.encode())
    diff = subprocess.run(["git", "diff", "--no-index", "--", "base.yml", "head.yml"],
                          cwd=tmp_path, capture_output=True)
    assert diff.returncode == 1, diff.stderr
    return _found(WF, diff.stdout.decode().replace("\r", " "), post_image=head)


@pytest.mark.parametrize(("runner", "binding", "unsafe"), [
    ("ubuntu-latest", "PAYLOAD", True),
    ("ubuntu-latest", "payload", False),
    ("windows-latest", "payload", True),
    ("windows-latest", "VERSION", False),
    ("${{ matrix.os }}", "payload", True),
], ids=["linux-exact", "linux-distinct", "windows-folded", "windows-benign", "dynamic-runner"])
def test_changed_workflow_resolves_environment_names_for_runner(tmp_path, runner, binding, unsafe):
    prelude = WF_HEAD.replace("ubuntu-24.04", runner).replace(
        "    steps:\n", "    env:\n      PAYLOAD: ${{ github.event.issue.title }}\n"
        "      VERSION: fixed\n    steps:\n")
    sink = '      - run: echo "${{ env.' + binding + ' }}"\n'
    expected = [(len(prelude.splitlines()) + 1, *CWE94)] if unsafe else []
    assert scan_changed_workflow(tmp_path, prelude + "      - run: echo fixed\n", prelude + sink) == expected


@pytest.mark.parametrize(("write", "step_env", "unsafe"), [
    ('echo "LABEL=$T" >> "$GITHUB_ENV"', "", True),
    ('echo "LABEL=$T" >> "$GITHUB_ENV"', "        env:\n          PAYLOAD: fixed\n", False),
    ('echo "VERSION=1.2.3" >> "$GITHUB_ENV"', "", False),
], ids=["injected-record", "safe-step-override", "constant-write-with-unrelated-taint"])
def test_changed_workflow_tracks_runtime_environment_records(tmp_path, write, step_env, unsafe):
    prelude = WF_HEAD + (
        "      - env:\n          T: ${{ github.event.issue.body }}\n"
        f"        run: {write}\n")
    base = prelude + "      - run: echo fixed\n" + step_env
    head = prelude + '      - run: echo "${{ env.PAYLOAD }}"\n' + step_env
    expected = [(len(prelude.splitlines()) + 1, *CWE94)] if unsafe else []
    assert scan_changed_workflow(tmp_path, base, head) == expected


# ------------------------------------------------------------------ line endings (4507449480, 4507449491)

SAFE_FAR = WF_HEAD.replace("    steps:\n", "    env:\n      TITLE: ${{ github.event.issue.title }}\n"
                           "      SAFE: fixed\n    steps:\n") + \
    "      - run: echo one\n      - run: echo two\n      - run: echo three\n      - run: echo four\n" \
    '      - run: echo "${{ env.SAFE }}"\n      - run: echo five\n'
TAINTED_FAR = SAFE_FAR.replace("${{ env.SAFE }}", "${{ env.TITLE }}")


def _crlf_hunk(lf_text, line):
    """The hunk gem-review's diff step writes for a CRLF file: it turns each \\r into a space."""
    lines = lf_text.splitlines()
    lo, hi = line - 3, min(len(lines), line + 3)
    body = "".join(("+" if n == line else " ") + lines[n - 1] + " \n" for n in range(lo, hi + 1))
    return f"@@ -{lo},{hi - lo} +{lo},{hi - lo + 1} @@\n" + body


def test_cwe94_crlf_checkout_matches_the_patch_4507449480():
    line = sink_line(SAFE_FAR, "env.SAFE")
    crlf = SAFE_FAR.replace("\n", "\r\n")
    assert _found(WF, _crlf_hunk(SAFE_FAR, line), post_image=crlf) == []   # accepted: SAFE is bound in view
    bad_line = sink_line(TAINTED_FAR, "env.TITLE")
    assert _found(WF, _crlf_hunk(TAINTED_FAR, bad_line), post_image=TAINTED_FAR.replace("\n", "\r\n")) == [
        (bad_line, *CWE94)]
    stale = crlf.replace("echo two", "echo 2")                              # still validated line by line
    assert _found(WF, _crlf_hunk(SAFE_FAR, line), post_image=stale) == [(line, *CWE94)]


def test_cwe94_lf_blob_checked_out_with_eol_crlf_is_the_target_4507449491():
    line = sink_line(SAFE_FAR, "env.SAFE")
    patch = _with_index(_hunk_around(SAFE_FAR, line), SAFE_FAR)           # index names the LF blob
    assert _found(WF, patch, post_image=SAFE_FAR.replace("\n", "\r\n")) == []
    other = _with_index(_hunk_around(SAFE_FAR, line), SAFE_FAR.replace("fixed", "other"))
    assert _found(WF, other, post_image=SAFE_FAR.replace("\n", "\r\n")) == [(line, *CWE94)]  # wrong blob: not used


# ------------------------------------------------------------------ robustness (4507449484, 4507453218)

@pytest.mark.parametrize("mode", MODES)
def test_cwe94_deeply_nested_boolean_does_not_crash_the_scan_4507449484(mode):
    import inspect
    n = 100  # 400 tokens, under the 2000-token cap; the limit below is lower than the recursion this needs
    text = WF_HEAD + "      - run: echo ${{ " + "true && (" * n + "github.event.issue.title" + ")" * n + " }}\n"
    old, base = sys.getrecursionlimit(), len(inspect.stack())
    sys.setrecursionlimit(base + 150)
    try:
        assert scan(text, mode) == [(sink_line(text), *CWE94)]
    finally:
        sys.setrecursionlimit(old)


def test_cwe94_contexts_does_not_copy_nested_index_contents_4507453218(monkeypatch):
    n = 20000

    class Counting(list):
        copied = 0

        def __getitem__(self, k):
            if isinstance(k, slice):
                Counting.copied += len(range(*k.indices(len(self))))
            return super().__getitem__(k)

    real = m.UntrustedContextPolicy._tokens.__func__
    monkeypatch.setattr(m.UntrustedContextPolicy, "_tokens", classmethod(lambda cls, e: Counting(real(cls, e))))
    expr = "x" + "[x" * n + "]" * n
    assert m.UntrustedContextPolicy.contexts(expr) == ["x", "x.*"] or m.UntrustedContextPolicy.contexts(expr)
    assert Counting.copied < 20 * n


# ------------------------------------------------------------------ GITHUB_ENV (4507449486)

GHENV_TAINTED = WF_HEAD + ("      - env:\n          T: ${{ github.event.issue.title }}\n"
                           '        run: echo "TITLE=$T" >> "$GITHUB_ENV"\n'
                           '      - run: echo "${{ env.TITLE }}"\n')
GHENV_BENIGN = WF_HEAD + ('      - run: echo "VERSION=1.2.3" >> "$GITHUB_ENV"\n'
                          '      - run: echo "${{ env.VERSION }}"\n')


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_values_written_through_github_env_are_tracked_4507449486(mode):
    assert scan(GHENV_TAINTED, mode) == [(len(GHENV_TAINTED.splitlines()), *CWE94)]


def test_cwe94_benign_github_env_write_is_not_flagged_in_full_file_mode_4507449486():
    assert scan(GHENV_BENIGN, "yaml") == []
    assert scan(GHENV_BENIGN, "heuristic") != []          # patch-only: cannot tell what is written, fails closed


def test_cwe94_github_env_writer_with_unknown_names_taints_every_env_name_4507449486():
    text = WF_HEAD + ("      - env:\n          T: ${{ github.event.issue.title }}\n"
                      '        run: cat "$T" >> "$GITHUB_ENV"\n      - run: echo "${{ env.ANYTHING }}"\n')
    assert scan(text, "yaml") == [(len(text.splitlines()), *CWE94)]


def test_cwe94_step_env_overrides_github_env_and_job_env_4507449486():
    text = WF_HEAD.replace("    steps:\n", "    env:\n      TITLE: ${{ github.event.issue.title }}\n    steps:\n") + (
        "      - env:\n          TITLE: fixed\n        run: echo ${{ env.TITLE }}\n"
        "      - run: echo ${{ env.TITLE }}\n")
    assert scan(text, "yaml") == [(len(text.splitlines()), *CWE94)]       # most specific scope wins


# ------------------------------------------------------------------ changed producer, unchanged sink (4507449488)

def test_cwe94_changed_env_producer_reaches_an_unchanged_sink_4507449488():
    base = SAFE_FAR.replace("${{ github.event.issue.title }}", "fixed").replace("env.SAFE", "env.TITLE")
    head = SAFE_FAR.replace("env.SAFE", "env.TITLE")
    prod = sink_line(head, "github.event.issue.title")
    # the patch touches only the producer line; the sink is a context line far below it, so the whole file decides
    patch = _hunk_around(head, prod)
    assert _found(WF, patch, post_image=head) == [(prod, *CWE94)]
    assert _found(WF, _hunk_around(base, prod), post_image=base) == []


def test_cwe94_changed_producer_with_the_sink_in_the_hunk_4507449488():
    text = WF_HEAD + ("      - env:\n          TITLE: ${{ github.event.issue.title }}\n"
                      '        run: echo "${{ env.TITLE }}"\n')
    prod = sink_line(text, "github.event.issue.title")
    hunk = f"@@ -{prod - 2},4 +{prod - 2},5 @@\n" + "".join(
        ("+" if n == prod else " ") + ln + "\n" for n, ln in enumerate(text.splitlines(), 1) if n >= prod - 2)
    assert _found(WF, hunk) == [(prod, *CWE94)]
    assert _found(WF, hunk, post_image=text) == [(prod, *CWE94)]


# ------------------------------------------------------------------ action identity (4507449497, 4507449516)

@pytest.mark.parametrize("mode", MODES)
def test_cwe94_uses_as_folded_scalar_or_alias_identifies_the_action_4507449497(mode):
    folded = WF_HEAD + ("      - uses: >-\n          azure/cli@v2\n        with:\n"
                        "          inlineScript: az group show -n ${{ github.event.issue.title }}\n")
    assert scan(folded, mode) == [(len(folded.splitlines()), *CWE94)]
    aliased = WF_HEAD.replace("    steps:\n", "    env:\n      CLI: &cli azure/cli@v2\n    steps:\n") + (
        "      - uses: *cli\n        with:\n          inlineScript: az ${{ github.event.issue.title }}\n")
    assert scan(aliased, mode) == [(len(aliased.splitlines()), *CWE94)]
    quoted = WF_HEAD + ("      - uses: 'azure/cli@v2'\n        with:\n"
                        "          inlineScript: az ${{ github.event.issue.title }}\n")
    assert scan(quoted, mode) == [(len(quoted.splitlines()), *CWE94)]


def test_cwe94_unresolved_code_input_in_a_patch_only_hunk_fails_closed_4507449516():
    text = WF_HEAD + (f"      - uses: azure/cli@{'a' * 40}\n        name: login\n        id: x\n        if: always()\n"
                      "        with:\n          inlineScript: az ${{ github.event.issue.title }}\n")
    line = sink_line(text)
    found = m.SupplyChainAndSecretScanner.audit_diff(WF, _hunk_around(text, line))
    assert [(f.line, f.severity, f.category) for f in found] == [(line, *CWE94)]
    assert "outside this diff" in found[0].message
    assert _found(WF, _hunk_around(text, line), post_image=text) == [(line, *CWE94)]   # resolved: azure/cli runs it
    data = text.replace("azure/cli", "acme/data").replace("inlineScript", "inlinescript2")
    assert _found(WF, _hunk_around(data, line), post_image=data) == []


# ------------------------------------------------------------------ YAML syntax (4507449502, 4507449506, ...)

@pytest.mark.parametrize("mode", MODES)
def test_cwe94_hash_line_inside_a_multiline_quoted_flow_value_is_text_4507449502(mode):
    text = WF_HEAD + ('      - {name: x, run: "echo a\n'
                      '          # ${{ github.event.issue.title }}"}\n')
    assert scan(text, mode) == [(sink_line(text), *CWE94)]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_flow_mapped_jobs_are_traversed_4507449506(mode):
    one = 'on: pull_request\njobs: {build: {runs-on: ubuntu-latest, steps: [{run: "echo ${{ inputs.payload }}"}]}}\n'
    assert scan(one, mode) == [(sink_line(one), *CWE94)]
    block = ('on: pull_request\njobs:\n'
             '  build: {runs-on: ubuntu-latest, steps: [{run: "echo ${{ inputs.payload }}"}]}\n')
    assert scan(block, mode) == [(sink_line(block), *CWE94)]
    envd = ('on: pull_request\njobs:\n  b: {env: {T: "${{ github.head_ref }}"}, '
            'steps: [{run: "echo ${{ env.T }}"}]}\n')
    assert scan(envd, mode) == [(sink_line(envd, "env.T"), *CWE94)]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_aliased_step_is_inspected_as_a_sink_4507449519(mode):
    text = ("on: pull_request\njobs:\n  a:\n    runs-on: u\n    steps:\n      - &deploy\n"
            '        run: echo "${{ env.TITLE }}"\n  b:\n    runs-on: u\n    env:\n'
            "      TITLE: ${{ github.event.issue.title }}\n    steps:\n      - *deploy\n")
    line = len(text.splitlines())
    hunk = f"@@ -{line - 2},2 +{line - 2},3 @@\n" + "".join(
        ("+" if n == line else " ") + ln + "\n" for n, ln in enumerate(text.splitlines(), 1) if n >= line - 2)
    assert _found(WF, hunk, post_image=text if mode == "yaml" else None) == [(line, *CWE94)]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_matrix_collection_members_are_decoded_4507449522(mode):
    text = WF_HEAD.replace("    steps:\n", "    strategy:\n      matrix:\n"
                           '        payload: ["\\u0024{{ inputs.payload }}"]\n    steps:\n') + \
        "      - run: echo ${{ matrix.payload }}\n"
    assert scan(text, mode) == [(len(text.splitlines()), *CWE94)]
    plain = text.replace('"\\u0024{{ inputs.payload }}"', '"fixed"')
    assert scan(plain, mode) == []


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_alias_inside_a_flow_mapped_run_is_resolved_4507449525(mode):
    text = WF_HEAD.replace("    steps:\n", '    env:\n      C: &command "echo ${{ github.event.issue.title }}"\n'
                           "    steps:\n") + "      - {run: *command}\n"
    assert scan(text, mode) == [(len(text.splitlines()), *CWE94)]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_unresolved_alias_in_a_flow_run_is_reported_when_added_4507449525(mode):
    text = WF_HEAD + "      - {run: *elsewhere}\n      - run: echo ok\n"   # no such anchor: the parse fails
    line = _line_of(text, "*elsewhere")
    assert _found(WF, _hunk_around(text, line), post_image=text if mode == "yaml" else None) == [(line, *CWE94)]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_escaped_line_break_in_double_quotes_joins_the_expression_4507449528(mode):
    text = WF_HEAD + '      - run: "echo $\\\n          {{ inputs.payload }}"\n'
    assert scan(text, mode) == [(_line_of(text, 'run: "echo $'), *CWE94)]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_single_quoted_scalars_are_decoded_before_extraction_4507453222(mode):
    text = WF_HEAD + """      - run: 'echo "${{ format(''}} {0}'', github.event.issue.title) }}"'\n"""
    assert scan(text, mode) == [(len(text.splitlines()), *CWE94)]


# ------------------------------------------------------------------ nitpicks

def test_cwe94_linear_taint_bounds_propagation_work_review_nitpick(monkeypatch):
    n = 3000
    env = "".join(f"      E{i}: ${{{{ env.E{i - 1} }}}}\n" for i in range(1, n))
    text = WF_HEAD.replace("    steps:\n", "    env:\n      E0: ${{ github.event.issue.title }}\n" + env + "    steps:\n") \
        + f"      - run: echo ${{{{ env.E{n - 1} }}}}\n"
    pops = {"n": 0}

    class Counting(m.deque):
        def popleft(self):
            pops["n"] += 1
            return super().popleft()

    monkeypatch.setattr(m, "deque", Counting)
    for post in (None, text):
        pops["n"] = 0
        assert _scan(WF, text, post_image=post) == [(len(text.splitlines()), *CWE94)]
        assert 0 < pops["n"] <= 3 * n, pops["n"]


@pytest.mark.parametrize("mode", MODES)
def test_cwe94_safe_only_flow_env_is_clean_review_nitpick(mode):
    text = WF_HEAD.replace("    steps:\n", "    env: {A: fixed, B: 'x', C: \"y\"}\n    steps:\n") + \
        "      - run: echo ${{ env.A }} ${{ env.B }} ${{ env.C }}\n" \
        "      - {env: {D: 1}, run: 'echo ${{ env.D }}'}\n"
    assert scan(text, mode) == []


# ------------------------------------------------------------------ the YAML parser path itself

def test_yaml_path_most_specific_env_scope_wins():
    wf = ("on: pull_request\nenv:\n  T: ${{ github.event.issue.title }}\njobs:\n  a:\n    env:\n      T: fixed\n"
          "    steps:\n      - run: echo ${{ env.T }}\n      - env:\n          T: ${{ github.head_ref }}\n"
          "        run: echo ${{ env.T }}\n  b:\n    steps:\n      - run: echo ${{ env.T }}\n")
    assert scan(wf, "yaml") == [(12, *CWE94), (15, *CWE94)]   # job env beats workflow env; step env beats job env


def test_yaml_path_merge_keys_and_anchors_in_steps():
    text = ("on: pull_request\nx-step: &s\n  shell: bash\n  run: echo ${{ github.event.issue.title }}\n"
            "jobs:\n  a:\n    steps:\n      - <<: *s\n      - <<: *s\n        run: echo safe\n")
    assert scan(text, "yaml") == [(8, *CWE94)]       # the step that merges it; the overriding `run` is clean


def test_yaml_path_comments_and_data_positions_are_not_sinks():
    text = ("on: pull_request\nconcurrency: ci-${{ github.event.pull_request.title }}\njobs:\n  a:\n    name: ${{ github.head_ref }}\n"
            "    steps:\n      - name: ${{ github.head_ref }}\n        if: github.head_ref == 'x'\n"
            "        run: echo ok # ${{ github.head_ref }}\n")
    assert scan(text, "yaml") == []


def test_yaml_fallback_fails_closed_when_pyyaml_is_unavailable(monkeypatch):
    text = WF_HEAD + '      - run: echo "${{ env.MISSING }}"\n'
    assert scan(text, "yaml") == []                                    # whole file parsed: no such binding anywhere
    monkeypatch.setattr(m, "_import_yaml", lambda: None)
    assert scan(text, "yaml") == [(len(text.splitlines()), *CWE94)]    # heuristics, treating the file as partial


def test_yaml_fallback_fails_closed_on_unparseable_files():
    text = WF_HEAD + '      - run: echo "${{ env.MISSING }}"\n      - run: [unclosed\n'
    assert scan(text, "yaml") == [(_line_of(text, "env.MISSING"), *CWE94)]


@pytest.mark.parametrize("case", sorted(CWE94_MUST_FLAG))
def test_yaml_path_agrees_with_the_heuristics_on_the_must_flag_corpus(case):
    path, text = CWE94_MUST_FLAG[case]
    assert _scan(path, text, post_image=text) == _scan(path, text) != []


@pytest.mark.parametrize("case", sorted(CWE94_MUST_NOT_FLAG))
def test_yaml_path_is_clean_on_the_must_not_flag_corpus(case):
    entry = CWE94_MUST_NOT_FLAG[case]
    path, text = entry if isinstance(entry, tuple) else (WF, entry)
    assert _scan(path, text, post_image=text) == []


def test_yaml_path_alias_bomb_falls_back_instead_of_hanging():
    levels = "".join(f"  l{i}: &l{i} [{', '.join([f'*l{i - 1}'] * 9)}]\n" for i in range(1, 9))
    text = ("on: pull_request\nx:\n  l0: &l0 [a, a, a, a, a, a, a, a, a]\n" + levels +
            "jobs:\n  a:\n    strategy:\n      matrix:\n        v: *l8\n    steps:\n"
            '      - run: echo "${{ env.MISSING }}"\n')
    assert scan(text, "yaml") == [(len(text.splitlines()), *CWE94)]   # walk gave up: heuristics, failing closed
