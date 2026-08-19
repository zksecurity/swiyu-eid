package ch.admin.foitt.wallet.platform.utils

import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.staticCompositionLocalOf

val LocalActivity = staticCompositionLocalOf<AppCompatActivity> {
    error(message = "No AppCompatActivity provided")
}
