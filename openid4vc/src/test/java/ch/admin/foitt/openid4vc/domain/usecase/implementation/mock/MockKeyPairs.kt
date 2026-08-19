package ch.admin.foitt.openid4vc.domain.usecase.implementation.mock

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

object MockKeyPairs {
    val VALID_KEY_PAIR_SOFTWARE = createValidKeyPair(KeyBindingType.SOFTWARE)
    val VALID_KEY_PAIR_HARDWARE = createValidKeyPair(KeyBindingType.HARDWARE)
    val UNSUPPORTED_KEY_PAIR = createUnsupportedKeyPair(KeyBindingType.HARDWARE)
    val INVALID_KEY_PAIR = createInvalidPrivateKeyKeyPair()
}

private fun createValidKeyPair(bindingType: KeyBindingType): JWSKeyPair {
    val generator = KeyPairGenerator.getInstance("EC")
    generator.initialize(ECGenParameterSpec("secp521r1"), SecureRandom())
    return createJwsKeyPair(generator, bindingType)
}

private fun createUnsupportedKeyPair(bindingType: KeyBindingType): JWSKeyPair {
    val generator = KeyPairGenerator.getInstance("RSA")
    return createJwsKeyPair(generator, bindingType)
}

private fun createInvalidPrivateKeyKeyPair(): JWSKeyPair {
    val keyPair = createValidKeyPair(KeyBindingType.HARDWARE)
    val otherKeyPair = createUnsupportedKeyPair(KeyBindingType.HARDWARE)
    return JWSKeyPair(
        algorithm = SigningAlgorithm.ES512,
        keyPair = KeyPair(keyPair.keyPair.public, otherKeyPair.keyPair.private),
        keyId = MockCredentialOffer.KEY_ID,
        bindingType = KeyBindingType.SOFTWARE,
    )
}

fun createJwsKeyPair(generator: KeyPairGenerator, bindingType: KeyBindingType): JWSKeyPair {
    val keyPair = generator.generateKeyPair()
    return JWSKeyPair(
        algorithm = SigningAlgorithm.ES512,
        keyPair = keyPair,
        keyId = MockCredentialOffer.KEY_ID,
        bindingType = bindingType
    )
}
