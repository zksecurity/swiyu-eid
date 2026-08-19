package ch.admin.foitt.wallet.platform.utils

import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

fun URI.getQueryParameter(key: String): Result<String?, Throwable> = runSuspendCatching {
    val encodedKey = URLEncoder.encode(key, "utf-8")
    val length = rawQuery.length
    var start = 0
    do {
        val nextAmpersand = rawQuery.indexOf('&', start)
        val end = if (nextAmpersand != -1) nextAmpersand else length

        var separator = rawQuery.indexOf('=', start)
        if (separator > end || separator == -1) {
            separator = end
        }

        if (separator - start == encodedKey.length && rawQuery.regionMatches(start, encodedKey, 0, encodedKey.length)) {
            if (separator == end) {
                return@runSuspendCatching null
            } else {
                val encodedValue = rawQuery.substring(separator + 1, end)
                return@runSuspendCatching URLDecoder.decode(encodedValue, "utf-8")
            }
        }

        // Move start to end of name.
        if (nextAmpersand != -1) {
            start = nextAmpersand + 1
        } else {
            break
        }
    } while (true)
    return@runSuspendCatching null
}
