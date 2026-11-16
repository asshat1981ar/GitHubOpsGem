package com.autodev.commandcenter.ui

/**
 * PKT-05 (PRO-71 & PRO-69): Android Objective Lifecycle Command Center UI Model & State Reducer.
 * Supports GET/POST `/api/v1/objectives`, renders all 7 lifecycle states (`queued`, `running`,
 * `blocked`, `verifying`, `completed`, `failed`, `replanned`), and surfaces blocked
 * `<PreFlightGate>` approvals bound to `effect_digest` so they cannot be bypassed from the client.
 */

enum class UiLifecycleStatus {
    QUEUED,
    RUNNING,
    BLOCKED,
    VERIFYING,
    COMPLETED,
    FAILED,
    REPLANNED
}

data class VerificationEvidenceSummary(
    val idealityScore: Double,
    val riceScore: Double,
    val fmeaRpn: Int,
    val pscScore: Double,
    val aupScore: Double,
    val durScore: Double,
    val allAbiCallersVerified: Boolean,
    val codeDiffSha256: String
)

data class BlockedApprovalPrompt(
    val objectiveId: String,
    val effectDigest: String,
    val reason: String,
    val requiresServerSideGrant: Boolean = true
)

data class ObjectiveCardUiModel(
    val objectiveId: String,
    val repository: String,
    val branch: String,
    val description: String,
    val status: UiLifecycleStatus,
    val evidence: VerificationEvidenceSummary?,
    val blockedApproval: BlockedApprovalPrompt?
)

data class CommandCenterUiState(
    val serverEndpoint: String = "http://10.0.2.2:8080",
    val sseConnected: Boolean = false,
    val objectives: List<ObjectiveCardUiModel> = emptyList(),
    val selectedObjectiveId: String? = null,
    val submissionInFlight: Boolean = false,
    val errorBanner: String? = null
) {
    val selectedObjective: ObjectiveCardUiModel?
        get() = objectives.firstOrNull { it.objectiveId == selectedObjectiveId }
}
