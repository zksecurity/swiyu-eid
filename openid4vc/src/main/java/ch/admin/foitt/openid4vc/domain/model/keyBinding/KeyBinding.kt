package ch.admin.foitt.openid4vc.domain.model.keyBinding

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm

data class KeyBinding(
    val identifier: String,
    val algorithm: SigningAlgorithm,
    val bindingType: KeyBindingType,
    val publicKey: ByteArray? = null,
    val privateKey: ByteArray? = null,
) {
    @Suppress("CyclomaticComplexMethod")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyBinding

        if (identifier != other.identifier) return false
        if (algorithm != other.algorithm) return false
        if (bindingType != other.bindingType) return false
        if (publicKey != null) {
            if (other.publicKey == null) return false
            if (!publicKey.contentEquals(other.publicKey)) return false
        } else if (other.publicKey != null) return false
        if (privateKey != null) {
            if (other.privateKey == null) return false
            if (!privateKey.contentEquals(other.privateKey)) return false
        } else if (other.privateKey != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = identifier.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + bindingType.hashCode()
        result = 31 * result + (publicKey?.contentHashCode() ?: 0)
        result = 31 * result + (privateKey?.contentHashCode() ?: 0)
        return result
    }
}
