package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.jwe.CreateJWEError
import ch.admin.foitt.openid4vc.domain.model.payloadEncryption.EncryptionAlgorithm
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationRequest
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationResponse
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationResponseConfig
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationResponseParam
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationResponseType
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.GetAuthorizationResponseConfigError
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.PresentationRequestError
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.PresentationResponseMode
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.toGetPresentationRequestConfigError
import ch.admin.foitt.openid4vc.domain.usecase.BuildAuthorizationResponseConfig
import ch.admin.foitt.openid4vc.domain.usecase.jwe.CreateJWE
import ch.admin.foitt.openid4vc.utils.JsonParsingError
import ch.admin.foitt.openid4vc.utils.SafeJson
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.binding
import com.github.michaelbull.result.mapError
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import javax.inject.Inject

internal class BuildAuthorizationResponseConfigImpl @Inject constructor(
    private val safeJson: SafeJson,
    private val createJWE: CreateJWE,
) : BuildAuthorizationResponseConfig {
    override suspend fun invoke(
        verifiablePresentation: String,
        authorizationRequest: AuthorizationRequest,
        usePayloadEncryption: Boolean,
        dcqlQueryId: String?,
    ): Result<AuthorizationResponseConfig, GetAuthorizationResponseConfigError> = binding {
        val dcqlId = dcqlQueryId ?: return@binding Err(
            PresentationRequestError.Unexpected(IllegalStateException("No dcql query provided"))
        ).bind<AuthorizationResponseConfig>()

        val authorizationResponse = AuthorizationResponse.Dcql(
            vpToken = mapOf(dcqlId to listOf(verifiablePresentation)),
            state = authorizationRequest.state,
        )

        when {
            usePayloadEncryption && authorizationRequest.responseMode == PresentationResponseMode.DIRECT_POST_JWT.value -> {
                getJWEAuthorizationResponseConfig(authorizationRequest, authorizationResponse)
            }

            authorizationRequest.responseMode == PresentationResponseMode.DIRECT_POST.value ||
                authorizationRequest.responseMode == PresentationResponseMode.DC_API_JWT.value -> {
                getDCQLAuthorizationResponseConfig(authorizationResponse)
            }

            else -> Err(PresentationRequestError.Unexpected(IllegalStateException("invalid response mode")))
        }.bind()
    }

    private fun getDCQLAuthorizationResponseConfig(
        authorizationResponse: AuthorizationResponse.Dcql
    ): Result<AuthorizationResponseConfig, GetAuthorizationResponseConfigError> = binding {
        val value = safeJson.safeEncodeObjectToString(authorizationResponse.vpToken)
            .mapError(JsonParsingError::toGetPresentationRequestConfigError)
            .bind()
        AuthorizationResponseConfig(
            type = AuthorizationResponseType.DCQL,
            params = buildMap {
                put(AuthorizationResponseParam.VP_TOKEN, value)
                authorizationResponse.state?.let { put(AuthorizationResponseParam.STATE, it) }
            }
        )
    }

    private fun getJWEAuthorizationResponseConfig(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse.Dcql
    ): Result<AuthorizationResponseConfig, GetAuthorizationResponseConfigError> = binding {
        val clientMetadata = authorizationRequest.clientMetaData
        val jwk = clientMetadata?.jwks?.keys?.firstOrNull { candidate ->
            candidate.kty in SUPPORTED_KEY_TYPES &&
                candidate.alg in SUPPORTED_ALGORITHMS && candidate.crv in SUPPORTED_CURVES
        }

        if (jwk == null) {
            return@binding Err(
                PresentationRequestError.Unexpected(IllegalStateException("no valid jwk provided"))
            ).bind<AuthorizationResponseConfig>()
        }

        val encValue = clientMetadata.encryptedResponseEncValuesSupported?.firstOrNull { encryptedValue ->
            encryptedValue in SUPPORTED_ENC_VALUES
        } ?: if (clientMetadata.encryptedResponseEncValuesSupported == null) {
            DEFAULT_ENCRYPTION_ALGORITHM
        } else {
            return@binding Err(
                PresentationRequestError.Unexpected(IllegalStateException("no valid enc value provided"))
            ).bind<AuthorizationResponseConfig>()
        }

        val value = safeJson.safeEncodeObjectToString(authorizationResponse.vpToken)
            .mapError(JsonParsingError::toGetPresentationRequestConfigError)
            .bind()
        val payloadJson = buildJsonObject {
            put(AuthorizationResponseParam.VP_TOKEN.jsonName, value)
            authorizationResponse.state?.let { put(AuthorizationResponseParam.STATE.jsonName, it) }
        }
        val payloadString = safeJson.safeEncodeObjectToString(payloadJson)
            .mapError(JsonParsingError::toGetPresentationRequestConfigError)
            .bind()
        val jwe = createJWE(
            algorithm = jwk.alg ?: "",
            encryptionMethod = encValue,
            payload = payloadString,
            encryptionKey = jwk,
        ).mapError(CreateJWEError::toGetPresentationRequestConfigError)
            .bind()

        AuthorizationResponseConfig(
            type = AuthorizationResponseType.DCQL,
            params = mapOf(AuthorizationResponseParam.RESPONSE to jwe)
        )
    }

    private companion object {
        private val SUPPORTED_KEY_TYPES = listOf("EC")
        private val SUPPORTED_ALGORITHMS = listOf("ECDH-ES")
        private val SUPPORTED_CURVES = listOf("P-256")
        private val DEFAULT_ENCRYPTION_ALGORITHM = EncryptionAlgorithm.A256GCM.name
        private val SUPPORTED_ENC_VALUES = listOf(DEFAULT_ENCRYPTION_ALGORITHM, EncryptionAlgorithm.A128GCM.name)
    }
}
