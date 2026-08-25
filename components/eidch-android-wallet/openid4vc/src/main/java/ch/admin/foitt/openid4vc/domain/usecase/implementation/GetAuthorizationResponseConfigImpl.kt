package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.anycredential.AnyCredential
import ch.admin.foitt.openid4vc.domain.model.claimsPathPointer.ClaimsPathPointer
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationRequest
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationResponseConfig
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.CreateAnyVerifiablePresentationError
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.GetAuthorizationResponseConfigError
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.toGetAuthorizationResponseConfigError
import ch.admin.foitt.openid4vc.domain.usecase.BuildAuthorizationResponseConfig
import ch.admin.foitt.openid4vc.domain.usecase.CreateAnyVerifiablePresentation
import ch.admin.foitt.openid4vc.domain.usecase.GetAuthorizationResponseConfig
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

internal class GetAuthorizationResponseConfigImpl @Inject constructor(
    private val createAnyVerifiablePresentation: CreateAnyVerifiablePresentation,
    private val buildAuthorizationResponseConfig: BuildAuthorizationResponseConfig,
) : GetAuthorizationResponseConfig {
    override suspend fun invoke(
        anyCredential: AnyCredential,
        presentationPaths: List<ClaimsPathPointer>,
        authorizationRequest: AuthorizationRequest,
        usePayloadEncryption: Boolean,
        dcqlQueryId: String?,
    ): Result<AuthorizationResponseConfig, GetAuthorizationResponseConfigError> = coroutineBinding {
        val verifiablePresentation = createAnyVerifiablePresentation(
            anyCredential = anyCredential,
            presentationPaths = presentationPaths,
            authorizationRequest = authorizationRequest,
        ).mapError(CreateAnyVerifiablePresentationError::toGetAuthorizationResponseConfigError)
            .bind()

        buildAuthorizationResponseConfig(
            verifiablePresentation = verifiablePresentation,
            authorizationRequest = authorizationRequest,
            usePayloadEncryption = usePayloadEncryption,
            dcqlQueryId = dcqlQueryId,
        ).bind()
    }
}
