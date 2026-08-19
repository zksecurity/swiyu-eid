package ch.admin.foitt.wallet.platform.jsonSchema.domain.model

import timber.log.Timber

sealed interface JsonSchemaError {
    data object ValidationFailed : JsonSchemaError
}

fun Throwable.toJsonSchemaError(): JsonSchemaError {
    Timber.e(this, "invalid json schema")
    return JsonSchemaError.ValidationFailed
}
