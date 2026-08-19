package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model

import io.ktor.http.ContentType

data class UploadFileRequest(
    val caseId: String,
    val accessToken: String,
    val fileName: String,
    val document: ByteArray,
    val mime: ContentType,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as UploadFileRequest

        if (caseId != other.caseId) return false
        if (accessToken != other.accessToken) return false
        if (fileName != other.fileName) return false
        if (!document.contentEquals(other.document)) return false
        if (mime != other.mime) return false

        return true
    }

    override fun hashCode(): Int {
        var result = caseId.hashCode()
        result = 31 * result + accessToken.hashCode()
        result = 31 * result + fileName.hashCode()
        result = 31 * result + document.contentHashCode()
        result = 31 * result + mime.hashCode()
        return result
    }
}
