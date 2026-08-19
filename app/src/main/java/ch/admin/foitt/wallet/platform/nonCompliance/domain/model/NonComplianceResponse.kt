package ch.admin.foitt.wallet.platform.nonCompliance.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class NonComplianceResponse(
    @SerialName("nonCompliantActors")
    val nonCompliantActors: List<NonCompliantActor>
)

@Serializable
data class NonCompliantActor(
    @SerialName("did")
    val did: String,
    @SerialName("flaggedAsNonCompliantAt")
    val flaggedAsNonCompliantAt: String,
    @SerialName("reason")
    val reason: Map<String, String> // mapOf("de" to "reason de", "en" to "reason en", ...)
)
