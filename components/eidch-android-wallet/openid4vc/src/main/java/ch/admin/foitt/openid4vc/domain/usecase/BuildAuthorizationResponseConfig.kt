package ch.admin.foitt.openid4vc.domain.usecase

import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationRequest
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationResponseConfig
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.GetAuthorizationResponseConfigError
import com.github.michaelbull.result.Result

/**
 * Packages an already-created presentation into the normal OID4VP response.
 *
 * The presentation is intentionally opaque here. Ordinary SD-JWT and ZK proof
 * producers can therefore share the same DCQL direct_post/direct_post.jwt path.
 */
interface BuildAuthorizationResponseConfig {
    suspend operator fun invoke(
        verifiablePresentation: String,
        authorizationRequest: AuthorizationRequest,
        usePayloadEncryption: Boolean,
        dcqlQueryId: String?,
    ): Result<AuthorizationResponseConfig, GetAuthorizationResponseConfigError>
}
