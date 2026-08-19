package ch.admin.foitt.wallet.platform.utils

import android.app.Activity
import android.content.pm.ActivityInfo

fun Activity.lockOrientation() {
    requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LOCKED
}

fun Activity.unlockOrientation() {
    requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED
}
