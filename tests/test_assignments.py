"""state/ASSIGNMENTS.yaml: every open unit in tasks/QUEUE.md has exactly one entry, each entry is exactly what the
ordered rules derive from its facts, gate-path work is reviewed by a different agent type, and human gates keep
agents away from gated units."""
import copy
import os
import re

import pytest
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ASSIGNMENTS = os.path.join(ROOT, "state", "ASSIGNMENTS.yaml")
INVENTORY = os.path.join(ROOT, "state", "INVENTORY.md")
QUEUE = os.path.join(ROOT, "tasks", "QUEUE.md")
DERIVED = ("owner_type", "agent", "skill", "reviewer")


def load():
    with open(ASSIGNMENTS, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def open_queue_lines():
    with open(QUEUE, encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.startswith("- [ ] ")]


def inventory_agents():
    text = open(INVENTORY, encoding="utf-8").read()
    section = text.split("## Agent types", 1)[1].split("\n## ", 1)[0]
    return set(re.findall(r"^- `([^`]+)`\s*$", section, flags=re.M))


def touches_gate(facts, gate_paths):
    return any(p.startswith(g) for p in facts.get("paths", []) for g in gate_paths)


def matches(when, facts, gate_paths):
    checks = {
        "needs_host": bool(facts.get("needs_host")),
        "external_write": bool(facts.get("external_write")),
        "human_gated": bool(facts.get("human_gates")),
        "v2": bool(facts.get("v2")),
        "touches_gate_path": touches_gate(facts, gate_paths),
        "docs_only": bool(facts.get("docs_only")),
    }
    return all(checks[k] == v for k, v in when.items())


def derive(doc, facts):
    for rule in doc["rules"]:
        if matches(rule["when"], facts, doc["gate_paths"]):
            return rule["id"], rule["then"]
    raise AssertionError("no rule matched")


def problems(doc, queue_lines, agents):
    """Every way the table can be wrong, as strings. The tests assert this is empty."""
    out = []
    units = doc["units"]
    for line in queue_lines:
        hits = [u["unit"] for u in units if u["queue_line"] in line]
        if len(hits) != 1:
            out.append(f"queue line {line!r} matched {len(hits)} entries")
    for u in units:
        hits = [ln for ln in queue_lines if u["queue_line"] in ln]
        if len(hits) != 1:
            out.append(f"entry {u['unit']} matched {len(hits)} open queue lines (stale or ambiguous)")
    if len({u["unit"] for u in units}) != len(units):
        out.append("duplicate unit ids")
    known = {u["unit"] for u in units} | set(doc["human_gates"])
    for u in units:
        rule_id, then = derive(doc, u["facts"])
        if u["rule"] != rule_id:
            out.append(f"{u['unit']}: rule {u['rule']} but the rules derive {rule_id}")
        for key in DERIVED:
            if u[key] != then[key]:
                out.append(f"{u['unit']}: {key}={u[key]!r} but the rules derive {then[key]!r}")
        for name in (u["agent"], u["reviewer"]):
            if name and name not in agents:
                out.append(f"{u['unit']}: agent type {name!r} is not in state/INVENTORY.md")
        if u["agent"] and u["reviewer"] and touches_gate(u["facts"], doc["gate_paths"]) and u["agent"] == u["reviewer"]:
            out.append(f"{u['unit']}: gate-path work reviewed by the same agent type")
        for dep in u["depends_on"]:
            if dep not in known:
                out.append(f"{u['unit']}: depends_on {dep!r} is neither a unit nor a human gate")
        gates = set(u["facts"].get("human_gates", []))
        if not gates <= set(doc["human_gates"]):
            out.append(f"{u['unit']}: unknown human gate in facts")
        if gates and u["owner_type"] != "human":
            out.append(f"{u['unit']}: depends on a human gate but is assigned to an agent")
        if gates and not gates <= set(u["depends_on"]):
            out.append(f"{u['unit']}: facts.human_gates not listed in depends_on")
    # The enforce date and ForgeCore must stay human decisions; no unit may be assigned to an agent while it needs them.
    for u in units:
        if {"H1", "H2"} & set(u["depends_on"]) and u["owner_type"] != "human":
            out.append(f"{u['unit']}: depends on H1/H2 but owner_type is {u['owner_type']}")
    return out


def test_assignments_are_consistent_with_the_queue_and_the_rules():
    assert problems(load(), open_queue_lines(), inventory_agents()) == []


def test_queue_has_open_units():
    assert len(open_queue_lines()) >= 10


def test_a_unit_missing_from_the_table_is_reported():
    doc = load()
    doc["units"] = [u for u in doc["units"] if u["unit"] != "WU-12"]
    assert any("WU-12 Repair" in p for p in problems(doc, open_queue_lines(), inventory_agents()))


def test_same_agent_reviewing_gate_path_work_is_reported():
    doc = load()
    u = next(x for x in doc["units"] if x["unit"] == "WU-14")
    u["reviewer"] = u["agent"]
    found = problems(doc, open_queue_lines(), inventory_agents())
    assert any("same agent type" in p for p in found)


def test_unknown_agent_type_is_reported():
    doc = copy.deepcopy(load())
    next(x for x in doc["units"] if x["unit"] == "WU-13")["agent"] = "not-an-agent"
    assert any("not in state/INVENTORY.md" in p for p in problems(doc, open_queue_lines(), inventory_agents()))


def test_handing_a_gated_unit_to_an_agent_is_reported():
    doc = load()
    u = next(x for x in doc["units"] if x["unit"] == "WU-11")
    u.update(owner_type="agent", agent="general-purpose")
    assert any("WU-11" in p for p in problems(doc, open_queue_lines(), inventory_agents()))


def test_every_python_module_is_listed_in_the_inventory():
    text = open(INVENTORY, encoding="utf-8").read()
    missing = []
    for base in ("", "hooks", "lifecycle", "gateway", "ci"):
        folder = os.path.join(ROOT, base)
        for name in sorted(os.listdir(folder)):
            if name.endswith(".py"):
                rel = f"{base}/{name}" if base else name
                if f"`{rel}`" not in text:
                    missing.append(rel)
    assert missing == []
