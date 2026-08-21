package ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase

import com.github.michaelbull.result.Result

/** Platform-owned trust, network, and holder-key operations exposed to the proof runtime. */
interface ZkPresentationRuntimeCallbacks {
    /** Returns a key only after the wallet has applied its configured trust policy. */
    suspend fun resolveTrustedP256Key(
        issuer: String,
        keyId: String,
        purpose: ZkTrustedKeyPurpose,
    ): Result<ZkP256PublicKey, ZkPresentationRuntimeCallbackError>

    suspend fun fetchStatusListJwt(
        uri: String,
    ): Result<String, ZkPresentationRuntimeCallbackError>

    /** Signs a SHA-256 digest and returns a compact 64-byte P-256 signature (r || s). */
    suspend fun signHolderDigest(
        holderKeyId: String,
        digest: ByteArray,
    ): Result<ByteArray, ZkPresentationRuntimeCallbackError>
}

enum class ZkTrustedKeyPurpose {
    CREDENTIAL_ISSUER,
    STATUS_LIST_ISSUER,
}

data class ZkP256PublicKey(
    /** Unpadded base64url encoding of the 32-byte affine X coordinate. */
    val x: String,
    /** Unpadded base64url encoding of the 32-byte affine Y coordinate. */
    val y: String,
)

sealed interface ZkPresentationRuntimeCallbackError {
    data class Unexpected(val throwable: Throwable?) : ZkPresentationRuntimeCallbackError
}
