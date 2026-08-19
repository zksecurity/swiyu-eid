package ch.admin.foitt.openid4vc.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Attack Potential Resistance values as per ISO 18045
 *
 * [See OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attack-potential-resistance)
 */
@Serializable
enum class KeyStorageSecurityLevel(val value: String) {
    @SerialName("iso_18045_high")
    HIGH("iso_18045_high"),

    @SerialName("iso_18045_moderate")
    MODERATE("iso_18045_moderate"),

    @SerialName("iso_18045_enhanced-basic")
    ENHANCED_BASIC("iso_18045_enhanced-basic"),

    @SerialName("iso_18045_basic")
    BASIC("iso_18045_basic");

    val priority: Int get() = when (this) {
        HIGH -> 0
        MODERATE -> 1
        ENHANCED_BASIC -> 2
        BASIC -> 3
    }

    companion object {
        fun get(value: String): KeyStorageSecurityLevel? =
            KeyStorageSecurityLevel.entries.firstOrNull { it.value == value }
    }
}
