package ch.admin.foitt.openid4vc.domain.model

interface KeyPairError {
    data object NotFound : GetKeyPairError
    data object DeleteFailed : DeleteKeyPairError
    data class Unexpected(val throwable: Throwable) : GetKeyPairError, DeleteKeyPairError, GetSoftwareKeyPairError
}

sealed interface GetKeyPairError
sealed interface GetSoftwareKeyPairError
sealed interface DeleteKeyPairError
