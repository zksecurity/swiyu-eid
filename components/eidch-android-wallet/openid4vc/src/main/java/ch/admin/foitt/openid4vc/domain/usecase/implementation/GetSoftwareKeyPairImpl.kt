package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.GetSoftwareKeyPairError
import ch.admin.foitt.openid4vc.domain.model.KeyPairError
import ch.admin.foitt.openid4vc.domain.usecase.GetSoftwareKeyPair
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.inject.Inject

internal class GetSoftwareKeyPairImpl @Inject constructor() : GetSoftwareKeyPair {
    override suspend fun invoke(
        publicKeyBytes: ByteArray,
        privateKeyBytes: ByteArray,
    ): Result<KeyPair, GetSoftwareKeyPairError> = runSuspendCatching {
        val keyFactory = KeyFactory.getInstance("EC")
        val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)

        val publicKey = keyFactory.generatePublic(publicKeySpec)
        val privateKey = keyFactory.generatePrivate(privateKeySpec)

        KeyPair(publicKey, privateKey)
    }.mapError { throwable ->
        KeyPairError.Unexpected(throwable)
    }
}
