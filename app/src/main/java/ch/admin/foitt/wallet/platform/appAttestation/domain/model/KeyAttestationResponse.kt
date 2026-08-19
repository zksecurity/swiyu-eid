package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeyAttestationResponse(
    @SerialName("keyAttestation")
    val keyAttestation: KeyAttestationJwt,
)
