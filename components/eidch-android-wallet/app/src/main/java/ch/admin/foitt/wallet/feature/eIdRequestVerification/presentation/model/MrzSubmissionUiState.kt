package ch.admin.foitt.wallet.feature.eIdRequestVerification.presentation.model

internal sealed interface MrzSubmissionUiState {
    data object Loading : MrzSubmissionUiState
    data object Valid : MrzSubmissionUiState
    data class Unexpected(
        val onClose: () -> Unit,
        val onRetry: () -> Unit,
    ) : MrzSubmissionUiState
    data class NetworkError(
        val onClose: () -> Unit,
        val onRetry: () -> Unit,
    ) : MrzSubmissionUiState
}
