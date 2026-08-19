package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import kotlinx.serialization.Serializable

@JvmInline
@Serializable
value class KeyAttestationJwt(val value: String)
