package ch.admin.foitt.wallet.platform.invitation.domain.model

/**
 * Parameter for the error screen state
 */
enum class InvitationErrorScreenState {
    INVALID_CREDENTIAL,
    UNKNOWN_ISSUER,
    INVALID_PRESENTATION,
    EMPTY_WALLET,
    NO_COMPATIBLE_CREDENTIAL,
    UNSUPPORTED_KEY_STORAGE,
    UNSUPPORTED_KEY_STORAGE_CAPABILITIES,
    NETWORK_ERROR,
    UNEXPECTED,
}
