package ch.admin.foitt.wallet.platform.composables.presentation.adapter.implementation

import android.graphics.drawable.Drawable
import ch.admin.foitt.wallet.platform.composables.presentation.adapter.GetDrawableFromImageData
import ch.admin.foitt.wallet.platform.composables.presentation.adapter.GetDrawableFromUri
import ch.admin.foitt.wallet.platform.utils.domain.usecase.GetImageDataFromUri
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.getOrElse
import timber.log.Timber
import javax.inject.Inject

internal class GetDrawableFromUriImpl @Inject constructor(
    private val getImageDataFromUri: GetImageDataFromUri,
    private val getDrawableFromImageData: GetDrawableFromImageData,
) : GetDrawableFromUri {
    override suspend fun invoke(uriString: String?): Drawable? = runSuspendCatching {
        getImageDataFromUri(uriString)?.let { imageData ->
            getDrawableFromImageData(imageData)
        }
    }.getOrElse {
        Timber.w(t = it, message = "Failed getting Drawable from Url")
        null
    }
}
