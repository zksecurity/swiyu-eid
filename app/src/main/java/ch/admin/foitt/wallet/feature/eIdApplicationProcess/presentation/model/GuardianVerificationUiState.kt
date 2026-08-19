package ch.admin.foitt.wallet.feature.eIdApplicationProcess.presentation.model

internal sealed interface GuardianVerificationUiState {
    data class Info(
        val isLoading: Boolean,
        val onStart: () -> Unit,
    ) : GuardianVerificationUiState
    data class NoValidCredential(
        val onCancel: () -> Unit,
        val onRequestEId: () -> Unit,
        val onHelp: () -> Unit,
    ) : GuardianVerificationUiState
    data class Loading(
        val onCancel: () -> Unit,
    ) : GuardianVerificationUiState
    data class NetworkError(
        val onRetry: () -> Unit,
        val onClose: () -> Unit,
    ) : GuardianVerificationUiState
    data class UnexpectedError(
        val onClose: () -> Unit,
    ) : GuardianVerificationUiState
}
