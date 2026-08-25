package ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.credentialPresentation.domain.model.ZkPresentationRuntimeRequest
import ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase.CreateZkPresentation
import ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase.CreateZkPresentationError
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import javax.inject.Inject

/** Replaced by the native zkID adapter when the proof runtime is packaged. */
class UnpackagedZkPresentationRuntime @Inject constructor() : CreateZkPresentation {
    override suspend fun invoke(
        request: ZkPresentationRuntimeRequest,
    ): Result<String, CreateZkPresentationError> = Err(CreateZkPresentationError.RuntimeNotPackaged)
}
