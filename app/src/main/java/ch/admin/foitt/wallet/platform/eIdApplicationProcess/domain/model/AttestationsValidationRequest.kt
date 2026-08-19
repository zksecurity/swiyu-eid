package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AttestationsValidationRequest(
    @SerialName("clientAttestation")
    val clientAttestation: String,
    @SerialName("keyAttestation")
    val keyAttestation: String,
)
