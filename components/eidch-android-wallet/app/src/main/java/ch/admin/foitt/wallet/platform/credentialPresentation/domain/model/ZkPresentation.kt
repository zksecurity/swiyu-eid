package ch.admin.foitt.wallet.platform.credentialPresentation.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkPresentationPolicy(
    val profile: String,
    @SerialName("circuit_id")
    val circuitId: String,
    @SerialName("cutoff_date")
    val cutoffDate: String,
    @SerialName("status_list_snapshot")
    val statusListSnapshot: String,
    @SerialName("current_time")
    val currentTime: Long,
)

/**
 * Complete app-to-proof-runtime handoff for one selected credential.
 *
 * The future Android proof package owns issuer/status resolution, holder-key
 * signing, witness generation, and proof generation. The app already owns and
 * authenticates every request value passed through this boundary.
 */
data class ZkPresentationRuntimeRequest(
    val credentialId: Long,
    val compactSdJwt: String,
    val holderKeyId: String,
    val challenge: ZkPresentationChallenge,
)

data class ZkPresentationChallenge(
    val nonce: String,
    val clientId: String,
    val responseUri: String,
    val state: String,
    val queryId: String,
    val policy: ZkPresentationPolicy,
)

fun PresentationRequestWithRaw.toZkPresentationRuntimeRequest(
    compatibleCredential: CompatibleCredential,
    compactSdJwt: String,
    holderKeyId: String,
): ZkPresentationRuntimeRequest? {
    val policy = zkPresentationPolicies[compatibleCredential.dcqlQueryId] ?: return null
    val request = authorizationRequest

    return ZkPresentationRuntimeRequest(
        credentialId = compatibleCredential.credentialId,
        compactSdJwt = compactSdJwt,
        holderKeyId = holderKeyId,
        challenge = ZkPresentationChallenge(
            nonce = request.nonce,
            clientId = request.clientId,
            responseUri = requireNotNull(request.responseUri),
            state = requireNotNull(request.state),
            queryId = compatibleCredential.dcqlQueryId,
            policy = policy,
        ),
    )
}
