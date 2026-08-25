package ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase

import ch.admin.foitt.wallet.platform.credentialPresentation.domain.model.ZkPresentationRuntimeRequest
import com.github.michaelbull.result.Result

fun interface CreateZkPresentation {
    suspend operator fun invoke(
        request: ZkPresentationRuntimeRequest,
    ): Result<String, CreateZkPresentationError>
}

sealed interface CreateZkPresentationError {
    data object RuntimeNotPackaged : CreateZkPresentationError
    data class Unexpected(val throwable: Throwable?) : CreateZkPresentationError
}
