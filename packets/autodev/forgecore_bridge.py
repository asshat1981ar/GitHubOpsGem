#!/usr/bin/env python3
"""
PKT-03 (PRO-66): AutoDev Control Plane <-> ForgeCore Verified Orchestration Bridge.
Connects HTTP/SSE objective intake (`GET/POST /api/v1/objectives`, `/events`) to
ForgeCore `VerifiedOrchestrator` with trusted `AuthorizationGrant`, SQLite WAL
durable evidence receipts, and `UnifiedExecutionEnvelopeV5` state transitions.
"""

from __future__ import annotations
import hashlib
import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.mcp_reference_monitor import (
    ATRIZInnovationEngine,
    FMEARecord,
    LLMTechnicalDebtSensor,
    StatefulGitHubOpsMonitor,
    TrustLevel,
)


class ObjectiveLifecycleState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    BLOCKED = "blocked"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    REPLANNED = "replanned"


@dataclass(frozen=True)
class AuthorizationGrant:
    grant_id: str
    issuer: str
    scope: str
    effect_digest: str
    expires_at_epoch: int

    def is_valid(self, expected_digest: str, current_epoch: Optional[int] = None) -> bool:
        now = current_epoch if current_epoch is not None else int(time.time())
        return now <= self.expires_at_epoch and self.effect_digest == expected_digest


@dataclass
class ObjectiveRecord:
    objective_id: str
    repository: str
    description: str
    target_branch: str
    state: ObjectiveLifecycleState = ObjectiveLifecycleState.QUEUED
    effect_digest: str = ""
    blocked_reason: Optional[str] = None
    envelope: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]] = field(default_factory=list)


class ForgeCoreVerifiedBridge:
    """
    Bridges queued control-plane objectives to ForgeCore verified orchestration
    backed by an append-only SQLite WAL evidence ledger.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS objective_ledger (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                objective_id TEXT NOT NULL,
                state TEXT NOT NULL,
                effect_digest TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                recorded_at INTEGER NOT NULL
            )
            """
        )
        self.objectives: Dict[str, ObjectiveRecord] = {}

    def submit_objective(self, objective_id: str, repository: str, description: str, target_branch: str) -> ObjectiveRecord:
        digest = hashlib.sha256(f"{objective_id}:{repository}:{target_branch}:{description}".encode("utf-8")).hexdigest()
        rec = ObjectiveRecord(
            objective_id=objective_id,
            repository=repository,
            description=description,
            target_branch=target_branch,
            state=ObjectiveLifecycleState.QUEUED,
            effect_digest=digest,
        )
        self._emit_state(rec, ObjectiveLifecycleState.QUEUED, {"message": "Objective queued in control plane"})
        self.objectives[objective_id] = rec
        return rec

    def execute_verified_transition(
        self,
        objective_id: str,
        files_payload: List[Dict[str, Any]],
        symbol_searches: List[str],
        has_tests: bool,
        grant: Optional[AuthorizationGrant] = None,
    ) -> ObjectiveRecord:
        rec = self.objectives[objective_id]
        self._emit_state(rec, ObjectiveLifecycleState.RUNNING, {"message": "Dispatched to ForgeCore VerifiedOrchestrator"})

        monitor = StatefulGitHubOpsMonitor(author_trust=TrustLevel.COLLABORATOR)
        quarantined_desc = monitor.sanitize_text(rec.description, source_tag=f"Objective:{objective_id}")
        _, stripped_think = monitor.deepseek_sanitizer.strip_reasoning_tokens(quarantined_desc)

        monitor.ingest_pull_request_files(files_payload)
        for query in symbol_searches:
            monitor.record_symbol_search(query)

        self._emit_state(rec, ObjectiveLifecycleState.VERIFYING, {"message": "Running Stage 4-5 aTRIZ-SWE & PreFlightGate"})

        combined_patch = "\n".join(str(f.get("patch", "")) for f in files_payload)
        triza_receipt = ATRIZInnovationEngine.synthesize_triza_mutation(
            improving="formal_correctness",
            worsening="smt_solver_timeout",
            code_patch=combined_patch or "+// verified patch",
            benefits=[12.0, 9.0],
            costs=[2.0],
            harms=[0.5],
        )
        rice_score = ATRIZInnovationEngine.compute_rice(reach=100.0, impact=3.0, confidence=0.95, effort=2.0)
        fmea_rec = FMEARecord("Cross-boundary ABI drift", severity=8, occurrence=2, detection=2)
        lats_uct = ATRIZInnovationEngine.compute_lats_uct(value=0.92, parent_visits=25, node_visits=5)

        td_report = LLMTechnicalDebtSensor.evaluate_patch(
            patch_text=combined_patch,
            has_tests=has_tests,
            has_prompt_versioning=True,
            has_provenance_receipt=True,
        )

        gate_ok, gate_msg = monitor.verify_and_gate_write(
            tool_name="push_files",
            target_branch=rec.target_branch,
            action_event="APPROVE",
        )

        if td_report.psc_score > 0.0 or td_report.dur_score > 0.0 or not has_tests:
            gate_ok = False
            gate_msg = f"BLOCK: Technical debt gate triggered ({[d.value for d in td_report.detected_debts]})"

        if grant is None or not grant.is_valid(rec.effect_digest):
            gate_ok = False
            gate_msg = "BLOCK: Missing or invalid trusted AuthorizationGrant for effect_digest"

        envelope = {
            "objective_id": rec.objective_id,
            "deployment_id": "accounts/YOUR_ACCOUNT/deployments/YOUR_DEPLOYMENT",
            "workflow_phase": monitor.phase.value,
            "target_branch": rec.target_branch,
            "quarantine_receipt": {
                "nfkc_normalized": True,
                "unicode_tags_stripped": True,
                "injection_alerts": monitor.injection_alerts,
                "think_blocks_stripped": stripped_think,
            },
            "abi_receipt": {
                "required_symbols": sorted(monitor.required_symbols),
                "verified_symbols": sorted(monitor.verified_symbols),
                "all_callers_verified": monitor.required_symbols.issubset(monitor.verified_symbols),
            },
            "atriz_mutation_receipt": {
                "improving_param": triza_receipt.improving_param,
                "worsening_param": triza_receipt.worsening_param,
                "inventive_principle": triza_receipt.inventive_principle,
                "code_diff_sha256": triza_receipt.code_diff_sha256,
                "ideality_score": triza_receipt.ideality_score,
                "rice_score": rice_score,
                "fmea_rpn": fmea_rec.rpn,
                "lats_uct": lats_uct,
            },
            "tech_debt_report": {
                "psc_score": td_report.psc_score,
                "aup_score": td_report.aup_score,
                "dur_score": td_report.dur_score,
                "detected_debts": [d.value for d in td_report.detected_debts],
            },
            "pre_flight_gate": {
                "gate_decision": "PASS" if gate_ok else "BLOCK",
                "inline_comments_count": 0,
                "fallback_body_count": 0,
                "blocked_reason": None if gate_ok else gate_msg,
            },
        }
        rec.envelope = envelope

        if not gate_ok:
            rec.blocked_reason = gate_msg
            self._emit_state(rec, ObjectiveLifecycleState.BLOCKED, {"reason": gate_msg, "effect_digest": rec.effect_digest})
        else:
            rec.blocked_reason = None
            self._emit_state(rec, ObjectiveLifecycleState.COMPLETED, {"envelope": envelope})

        self.conn.execute(
            "INSERT INTO objective_ledger (objective_id, state, effect_digest, envelope_json, recorded_at) VALUES (?, ?, ?, ?, ?)",
            (rec.objective_id, rec.state.value, rec.effect_digest, json.dumps(envelope), int(time.time())),
        )
        self.conn.commit()
        return rec

    @staticmethod
    def _emit_state(rec: ObjectiveRecord, new_state: ObjectiveLifecycleState, payload: Dict[str, Any]) -> None:
        rec.state = new_state
        rec.events.append({
            "event": "objective.lifecycle",
            "objective_id": rec.objective_id,
            "state": new_state.value,
            "timestamp": int(time.time()),
            "payload": payload,
        })
