package ch.admin.foitt.openid4vc.domain.model.credentialoffer

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import java.security.KeyPair

interface SigningKeyPair {
    val keyPair: KeyPair
    val keyId: String
}

data class JWSKeyPair(
    val algorithm: SigningAlgorithm,
    override val keyPair: KeyPair,
    override val keyId: String,
    val bindingType: KeyBindingType,
) : SigningKeyPair
