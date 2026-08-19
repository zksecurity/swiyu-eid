package ch.admin.foitt.wallet.platform.utils

import java.util.Base64

fun base64StringToByteArray(string: String): ByteArray =
    Base64.getUrlDecoder().decode(string)

fun base64NonUrlStringToByteArray(string: String): ByteArray =
    Base64.getDecoder().decode(string)
