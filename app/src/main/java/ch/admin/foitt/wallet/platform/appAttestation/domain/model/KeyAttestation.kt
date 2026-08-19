package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt

data class KeyAttestation(
    val keyPair: JWSKeyPair,
    val attestation: Jwt,
) {
    companion object {
        const val KEY_ALIAS = "keyAttestation"
        val signingAlgorithm = SigningAlgorithm.ES256
    }
}
