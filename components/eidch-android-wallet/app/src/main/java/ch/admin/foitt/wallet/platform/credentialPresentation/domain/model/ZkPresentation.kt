package ch.admin.foitt.wallet.platform.credentialPresentation.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

const val ZkPresentationRuntimeRequestSchema = "swiyu.mobile-runtime-request.v1"

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
@Serializable
data class ZkPresentationRuntimeRequest(
    val schema: String,
    @SerialName("credential_id")
    val credentialId: Long,
    @SerialName("compact_sd_jwt")
    val compactSdJwt: String,
    @SerialName("holder_key_id")
    val holderKeyId: String,
    val challenge: ZkPresentationChallenge,
)

@Serializable
data class ZkPresentationChallenge(
    val nonce: String,
    @SerialName("client_id")
    val clientId: String,
    @SerialName("response_uri")
    val responseUri: String,
    val state: String,
    @SerialName("query_id")
    val queryId: String,
    val policy: ZkPresentationRuntimePolicy,
)

@Serializable
data class ZkPresentationRuntimePolicy(
    val profile: String,
    @SerialName("circuit_ids")
    val circuitIds: List<String>,
    val parameters: JsonObject,
)

fun PresentationRequestWithRaw.toZkPresentationRuntimeRequest(
    compatibleCredential: CompatibleCredential,
    compactSdJwt: String,
    holderKeyId: String,
): ZkPresentationRuntimeRequest? {
    val policy = zkPresentationPolicies[compatibleCredential.dcqlQueryId] ?: return null
    val request = authorizationRequest

    return ZkPresentationRuntimeRequest(
        schema = ZkPresentationRuntimeRequestSchema,
        credentialId = compatibleCredential.credentialId,
        compactSdJwt = compactSdJwt,
        holderKeyId = holderKeyId,
        challenge = ZkPresentationChallenge(
            nonce = request.nonce,
            clientId = request.clientId,
            responseUri = requireNotNull(request.responseUri),
            state = requireNotNull(request.state),
            queryId = compatibleCredential.dcqlQueryId,
            policy = ZkPresentationRuntimePolicy(
                profile = policy.profile,
                circuitIds = listOf(policy.circuitId),
                parameters = buildJsonObject {
                    put("cutoff_date", policy.cutoffDate)
                    put("status_list_snapshot", policy.statusListSnapshot)
                    put("current_time", policy.currentTime)
                },
            ),
        ),
    )
}
