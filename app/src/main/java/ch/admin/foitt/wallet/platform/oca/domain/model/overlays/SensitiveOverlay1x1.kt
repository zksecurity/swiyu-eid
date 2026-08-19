package ch.admin.foitt.wallet.platform.oca.domain.model.overlays

import ch.admin.foitt.wallet.platform.oca.domain.model.OverlaySpecType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

sealed interface SensitiveOverlay : Overlay

@Serializable
data class SensitiveOverlay1x0(
    @SerialName("capture_base")
    override val captureBaseDigest: String,
    @SerialName("attributes")
    val attributes: List<String>,
) : SensitiveOverlay {
    @SerialName("type")
    override val type: OverlaySpecType = OverlaySpecType.SENSITIVE_1_0
}
