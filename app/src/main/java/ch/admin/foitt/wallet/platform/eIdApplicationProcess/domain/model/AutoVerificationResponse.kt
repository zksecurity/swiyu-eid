package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AutoVerificationResponse(
    @SerialName("jwt")
    val jwt: String,
    @SerialName("use_nfc")
    val useNfc: Boolean,
    @SerialName("scan_document")
    val scanDocument: Boolean,
    @SerialName("record_document_video")
    val recordDocumentVideo: Boolean,
)
