package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ClientAttestationResponse(
    @SerialName("clientAttestation")
    val clientAttestation: String,
)
