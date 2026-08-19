package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt

data class ClientAttestation(
    val keyStoreAlias: String,
    val attestation: Jwt,
) {
    companion object {
        const val KEY_ALIAS = "clientAttestation"
        val SIGNING_ALGORITHM = SigningAlgorithm.ES256
        const val TYPE_PROOF_OF_POSSESSION = "oauth-client-attestation-pop+jwt"
        const val REQUEST_HEADER = "OAuth-Client-Attestation"
    }
}
