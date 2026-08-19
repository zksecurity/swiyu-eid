package ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.GetKeyPairError
import ch.admin.foitt.openid4vc.domain.model.toCurve
import ch.admin.foitt.openid4vc.domain.model.toJWSAlgorithm
import ch.admin.foitt.openid4vc.domain.usecase.GetHardwareKeyPair
import ch.admin.foitt.openid4vc.utils.Constants
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationPoP
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.GenerateProofOfPossessionError
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.toGenerateProofOfPossessionError
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.GenerateProofOfPossession
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.JsonElement
import org.erdtman.jcs.JsonCanonicalizer
import java.security.KeyPair
import java.security.MessageDigest
import java.time.Instant
import java.util.Date
import java.util.UUID
import javax.inject.Inject

internal class GenerateProofOfPossessionImpl @Inject constructor(
    private val getKeyPair: GetHardwareKeyPair,
) : GenerateProofOfPossession {
    @OptIn(ExperimentalStdlibApi::class)
    override suspend fun invoke(
        clientAttestation: ClientAttestation,
        challenge: String,
        audience: String,
        requestBody: JsonElement,
    ): Result<ClientAttestationPoP, GenerateProofOfPossessionError> = coroutineBinding {
        val canonicalJsonBytes = runSuspendCatching {
            JsonCanonicalizer(requestBody.toString()).encodedUTF8
        }.mapError { throwable ->
            throwable.toGenerateProofOfPossessionError("Failed to canonicalize request body")
        }.bind()

        val bodyBase64Hash = MessageDigest.getInstance(SHA256)
            .digest(canonicalJsonBytes)
            .toHexString()

        val proofOfPossessionHeader = JWSHeader.Builder(ClientAttestation.SIGNING_ALGORITHM.toJWSAlgorithm())
            .type(JOSEObjectType(ClientAttestation.TYPE_PROOF_OF_POSSESSION))
            .build()

        val proofOfPossessionBody = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .expirationTime(expirationTime)
            .issuer(clientAttestation.attestation.subject)
            .claim("req", bodyBase64Hash)
            .claim("nonce", challenge)
            .jwtID(UUID.randomUUID().toString())
            .build()

        val signedJwt = SignedJWT(proofOfPossessionHeader, proofOfPossessionBody)

        val keyPair: KeyPair = getKeyPair(clientAttestation.keyStoreAlias, Constants.ANDROID_KEY_STORE)
            .mapError(GetKeyPairError::toGenerateProofOfPossessionError).bind()

        runSuspendCatching {
            val signer = ECDSASigner(keyPair.private, ClientAttestation.SIGNING_ALGORITHM.toCurve())
            signedJwt.sign(signer)
        }.mapError { throwable ->
            throwable.toGenerateProofOfPossessionError("Failed to sign proof of possession jwt")
        }.bind()

        val clientAttestationProofOfPossessionJwt = runSuspendCatching {
            signedJwt.serialize()
        }.mapError { throwable ->
            throwable.toGenerateProofOfPossessionError("Failed to serialize proof of possession jwt")
        }.bind()

        ClientAttestationPoP(clientAttestationProofOfPossessionJwt)
    }

    private val expirationTime get() = Date(Instant.now().plusSeconds(EXPIRATION_DURATION).toEpochMilli())

    companion object {
        private const val EXPIRATION_DURATION = 300L
        private const val SHA256 = "sha256"
    }
}
