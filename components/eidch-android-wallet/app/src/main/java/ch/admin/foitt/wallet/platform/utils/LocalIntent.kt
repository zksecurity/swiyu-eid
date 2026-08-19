package ch.admin.foitt.wallet.platform.utils

import android.content.Intent
import androidx.compose.runtime.staticCompositionLocalOf

val LocalIntent = staticCompositionLocalOf<Intent> {
    error(message = "No Intent provided")
}
