package ch.admin.foitt.wallet.platform.oca.domain.model.overlays

import ch.admin.foitt.wallet.platform.oca.domain.model.OverlaySpecType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer

sealed interface EntryOverlay : LocalizedOverlay

@Serializable
data class EntryOverlay1x0(
    @SerialName("capture_base")
    override val captureBaseDigest: String,

    @SerialName("language")
    override val language: String,

    @SerialName("attribute_entries")
    @Serializable(with = AttributeEntrySerializer::class)
    val attributeEntries: Map<String, Map<String, String>>
) : EntryOverlay {
    override val type: OverlaySpecType = OverlaySpecType.ENTRY_1_0
}

private object AttributeEntrySerializer : JsonTransformingSerializer<Map<String, Map<String, String>>>(
    tSerializer = MapSerializer(
        String.serializer(),
        MapSerializer(String.serializer(), String.serializer())
    )
) {
    override fun transformDeserialize(element: JsonElement): JsonElement {
        if (element !is JsonObject) return element
        val filtered = element.filterValues { it is JsonObject } // we do not support code tables, so ignore them
        return JsonObject(filtered)
    }
}
