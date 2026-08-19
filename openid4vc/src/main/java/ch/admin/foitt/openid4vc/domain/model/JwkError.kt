package ch.admin.foitt.openid4vc.domain.model

interface JwkError {
    data object UnsupportedCryptographicSuite : CreateJwkError
    data class Unexpected(val cause: Throwable?) : CreateJwkError
}

sealed interface CreateJwkError
