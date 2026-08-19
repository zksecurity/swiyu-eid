package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt

enum class AttestationAlgorithm(val value: String) {
    ES256("ES256");

    companion object {
        fun fromJwt(jwt: Jwt): AttestationAlgorithm? = AttestationAlgorithm.entries.firstOrNull {
            jwt.algorithm == it.value
        }
    }
}
