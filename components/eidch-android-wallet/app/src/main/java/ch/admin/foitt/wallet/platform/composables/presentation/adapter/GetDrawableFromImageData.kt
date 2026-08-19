package ch.admin.foitt.wallet.platform.composables.presentation.adapter

import android.graphics.drawable.Drawable

fun interface GetDrawableFromImageData {
    suspend operator fun invoke(imageData: ByteArray): Drawable?
}
