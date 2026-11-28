package com.chimera.ai.director

/**
 * PKT-04 (PRO-77): Advisory AI Game Progression Director & Dynamic Pacing Orchestrator.
 * Adheres strictly to Living-World Invariants:
 * - Invariant G1: Zero AI authority in game-core; simulation state is 100% authoritative.
 * - Invariant G2/G3: Non-omniscient NPC beliefs grounded in causal event ledger.
 * - Invariant G7: 100% functional offline via DeterministicHeuristicDirector fallback.
 * - Invariant G8: Bit-for-bit deterministic reducer transitions.
 */

enum class PacingPhase {
    RESPITE,
    RISING_TENSION,
    CLIMAX,
    AFTERMATH
}

data class WorldPacingSnapshot(
    val tick: Long,
    val settlementNodeId: String,
    val partyStaminaRatio: Double,
    val recentCombatCount: Int,
    val unresolvedRumors: Int,
    val scarcityIndex: Double
)

data class ProgressionDirective(
    val directiveId: String,
    val targetNodeId: String,
    val recommendedPhase: PacingPhase,
    val opportunityTag: String,
    valrationale: String,
    val advisoryOnly: Boolean = true,
    val fallbackUsed: Boolean = false
)

interface OnDeviceInferencePort {
    fun isAvailable(): Boolean
    fun proposeDirective(snapshot: WorldPacingSnapshot): ProgressionDirective?
}

object DeterministicHeuristicDirector {
    fun evaluate(snapshot: WorldPacingSnapshot): ProgressionDirective {
        val phase = when {
            snapshot.partyStaminaRatio < 0.35 -> PacingPhase.RESPITE
            snapshot.recentCombatCount >= 3 && snapshot.scarcityIndex > 0.6 -> PacingPhase.CLIMAX
            snapshot.unresolvedRumors > 0 -> PacingPhase.RISING_TENSION
            else -> PacingPhase.AFTERMATH
        }
        val tag = when (phase) {
            PacingPhase.RESPITE -> "camp_sanctuary_recovery"
            PacingPhase.RISING_TENSION -> "causal_rumor_investigation"
            PacingPhase.CLIMAX -> "caldera_crisis_ambush"
            PacingPhase.AFTERMATH -> "merchant_caravan_barter"
        }
        return ProgressionDirective(
            directiveId = "dir_det_${snapshot.tick}_${snapshot.settlementNodeId}",
            targetNodeId = snapshot.settlementNodeId,
            recommendedPhase = phase,
            opportunityTag = tag,
            valrationale = "Deterministic heuristic evaluation at tick=${snapshot.tick}",
            advisoryOnly = true,
            fallbackUsed = true
        )
    }
}

class GameProgressionDirectorAgent(
    private val inferencePort: OnDeviceInferencePort
) {
    fun issueAdvisoryDirective(snapshot: WorldPacingSnapshot): ProgressionDirective {
        if (inferencePort.isAvailable()) {
            val candidate = runCatching { inferencePort.proposeDirective(snapshot) }.getOrNull()
            if (candidate != null && validateCandidate(candidate, snapshot)) {
                return candidate.copy(advisoryOnly = true, fallbackUsed = false)
            }
        }
        return DeterministicHeuristicDirector.evaluate(snapshot)
    }

    private fun validateCandidate(directive: ProgressionDirective, snapshot: WorldPacingSnapshot): Boolean {
        if (!directive.advisoryOnly) return false
        if (snapshot.partyStaminaRatio < 0.25 && directive.recommendedPhase == PacingPhase.CLIMAX) {
            return false // Prevent unfair party wipe when stamina is critically depleted
        }
        return directive.targetNodeId.isNotBlank() && directive.opportunityTag.isNotBlank()
    }
}
