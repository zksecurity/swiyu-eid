package ch.admin.foitt.wallet.platform.oca.domain.model.overlays

import ch.admin.foitt.wallet.platform.oca.domain.model.OverlaySpecType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

sealed interface StandardOverlay : Overlay

@Serializable
data class StandardOverlay1x0(
    @SerialName("capture_base")
    override val captureBaseDigest: String,

    @SerialName("attr_standards")
    val attributeStandards: Map<String, String>,
) : StandardOverlay {
    override val type: OverlaySpecType = OverlaySpecType.STANDARD_1_0
}

sealed interface Standard {
    data object DataUrl : Standard
    data object Iso8601 : Standard
    data object UnixTime : Standard
    data class Unknown(val rawValue: String) : Standard

    companion object {
        fun fromString(input: String?): Standard? {
            return when {
                input == null -> null
                input.startsWith("urn:ietf:rfc:2397") -> DataUrl
                input.startsWith("urn:iso:std:iso:8601") -> Iso8601
                input.startsWith("urn:iso:std:iso-iec:9945") || input.startsWith("urn:iso:std:iso-iec-ieee:9945") -> UnixTime

                else -> Unknown(input)
            }
        }
    }
}
