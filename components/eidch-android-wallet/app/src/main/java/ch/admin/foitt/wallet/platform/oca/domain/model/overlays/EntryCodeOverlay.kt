package ch.admin.foitt.wallet.platform.oca.domain.model.overlays

import ch.admin.foitt.wallet.platform.oca.domain.model.OverlaySpecType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer

sealed interface EntryCodeOverlay : Overlay

@Serializable
data class EntryCodeOverlay1x0(
    @SerialName("capture_base")
    override val captureBaseDigest: String,

    @SerialName("attribute_entry_codes")
    @Serializable(with = AttributeEntryCodeSerializer::class)
    val attributeEntryCodes: Map<String, List<String>>
) : EntryCodeOverlay {
    override val type: OverlaySpecType = OverlaySpecType.ENTRY_CODE_1_0
}

private object AttributeEntryCodeSerializer : JsonTransformingSerializer<Map<String, List<String>>>(
    tSerializer = MapSerializer(
        String.serializer(),
        ListSerializer(String.serializer())
    )
) {
    override fun transformDeserialize(element: JsonElement): JsonElement {
        if (element !is JsonObject) return element
        val filtered = element.filterValues { it is JsonArray } // we do not support code tables, so ignore them
        return JsonObject(filtered)
    }
}
