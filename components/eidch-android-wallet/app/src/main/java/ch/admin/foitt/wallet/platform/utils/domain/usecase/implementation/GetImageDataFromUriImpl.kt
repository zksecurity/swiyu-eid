package ch.admin.foitt.wallet.platform.utils.domain.usecase.implementation

import androidx.core.net.toUri
import ch.admin.foitt.wallet.platform.utils.base64NonUrlStringToByteArray
import ch.admin.foitt.wallet.platform.utils.domain.usecase.GetImageDataFromUri
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.getOrElse
import timber.log.Timber
import javax.inject.Inject

internal class GetImageDataFromUriImpl @Inject constructor() : GetImageDataFromUri {
    override suspend fun invoke(uriString: String?): ByteArray? = runSuspendCatching {
        if (uriString == null) return@runSuspendCatching null
        val imageUri = uriString.toUri()
        val imageData = when (imageUri.scheme) {
            "data" -> base64NonUrlStringToByteArray(imageUri.toString().substringAfter("base64,"))
            "https" -> null
            else -> {
                Timber.e("Unsupported image scheme: ${imageUri.scheme}")
                null
            }
        }

        imageData
    }.getOrElse {
        Timber.w(t = it, message = "Failed getting image data byte array from Url")
        null
    }
}
