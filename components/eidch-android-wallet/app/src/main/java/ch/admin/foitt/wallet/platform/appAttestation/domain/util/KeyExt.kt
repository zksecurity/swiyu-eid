package ch.admin.foitt.wallet.platform.appAttestation.domain.util

import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.utils.Constants
import ch.admin.foitt.wallet.platform.utils.toNonUrlEncodedBase64String
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import java.security.KeyStore

typealias Base64CertificateChain = List<String>

fun JWSKeyPair.getBase64CertificateChain(
    keyStoreName: String = Constants.ANDROID_KEY_STORE,
): Result<Base64CertificateChain, Throwable> = runSuspendCatching {
    val keyStore = KeyStore.getInstance(keyStoreName)
    keyStore.load(null)
    val certificateChain = keyStore.getCertificateChain(keyId)

    certificateChain.map { it.encoded.toNonUrlEncodedBase64String() }
}
