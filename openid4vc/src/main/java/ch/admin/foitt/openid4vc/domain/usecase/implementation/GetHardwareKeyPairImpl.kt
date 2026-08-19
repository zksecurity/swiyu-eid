package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.di.DefaultDispatcher
import ch.admin.foitt.openid4vc.domain.model.GetKeyPairError
import ch.admin.foitt.openid4vc.domain.model.KeyPairError
import ch.admin.foitt.openid4vc.domain.usecase.GetHardwareKeyPair
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.toErrorIfNull
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.KeyStore
import javax.inject.Inject

internal class GetHardwareKeyPairImpl @Inject constructor(
    @param:DefaultDispatcher private val defaultDispatcher: CoroutineDispatcher,
) : GetHardwareKeyPair {
    override suspend fun invoke(
        keyId: String,
        provider: String,
    ): Result<KeyPair, GetKeyPairError> = withContext(defaultDispatcher) {
        runSuspendCatching {
            val keyStore = KeyStore.getInstance(provider)
            keyStore.load(null)
            keyStore.getEntry(keyId, null)?.let {
                val privateKeyEntry = it as KeyStore.PrivateKeyEntry
                KeyPair(privateKeyEntry.certificate.publicKey, privateKeyEntry.privateKey)
            }
        }.mapError { throwable ->
            KeyPairError.Unexpected(throwable)
        }.toErrorIfNull {
            KeyPairError.NotFound
        }
    }
}
