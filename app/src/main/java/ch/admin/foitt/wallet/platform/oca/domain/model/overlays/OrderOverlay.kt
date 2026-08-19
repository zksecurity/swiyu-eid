package ch.admin.foitt.wallet.platform.oca.domain.model.overlays

import ch.admin.foitt.wallet.platform.oca.domain.model.OverlaySpecType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

sealed interface OrderOverlay : Overlay

@Serializable
data class OrderOverlay1x0(
    @SerialName("capture_base")
    override val captureBaseDigest: String,

    @SerialName("attribute_orders")
    val attributeOrders: Map<String, Int>,
) : OrderOverlay {
    override val type: OverlaySpecType = OverlaySpecType.ORDER_1_0
}
