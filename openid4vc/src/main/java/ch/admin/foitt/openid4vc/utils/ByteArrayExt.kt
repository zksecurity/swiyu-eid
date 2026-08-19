package ch.admin.foitt.openid4vc.utils

import java.util.Base64

internal fun ByteArray.toBase64StringUrlEncodedWithoutPadding(): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(this)

internal fun ByteArray.toNonUrlEncodedBase64String() = Base64.getEncoder().encodeToString(this)
