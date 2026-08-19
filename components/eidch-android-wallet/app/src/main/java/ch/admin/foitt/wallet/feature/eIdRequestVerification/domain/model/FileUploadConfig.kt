package ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.model

import io.ktor.http.ContentType

data class FileUploadConfig(
    val fileName: String,
    val contentType: ContentType,
    val serverFileName: String,
    val isMandatory: Boolean
)
