package ch.admin.foitt.wallet.platform.composables.presentation.adapter.implementation

import android.content.Context
import android.graphics.drawable.Drawable
import ch.admin.foitt.wallet.platform.composables.presentation.adapter.GetDrawableFromImageData
import coil.ImageLoader
import coil.request.ImageRequest
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.getOrElse
import dagger.hilt.android.qualifiers.ApplicationContext
import timber.log.Timber
import javax.inject.Inject

internal class GetDrawableFromImageDataImpl @Inject constructor(
    private val imageLoader: ImageLoader,
    @param:ApplicationContext private val appContext: Context,
) : GetDrawableFromImageData {
    override suspend fun invoke(imageData: ByteArray): Drawable? = runSuspendCatching {
        val imageRequest = ImageRequest.Builder(appContext)
            .data(imageData)
            .build()
        val result = imageLoader.execute(imageRequest)

        return result.drawable
    }.getOrElse {
        Timber.w(t = it, message = "Failed getting Drawable from Url")
        null
    }
}
