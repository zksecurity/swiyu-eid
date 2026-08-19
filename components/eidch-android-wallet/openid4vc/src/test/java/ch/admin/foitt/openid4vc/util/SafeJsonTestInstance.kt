package ch.admin.foitt.openid4vc.util

import ch.admin.foitt.openid4vc.utils.SafeJson
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.ClassDiscriminatorMode
import kotlinx.serialization.json.Json

internal object SafeJsonTestInstance {

    @OptIn(ExperimentalSerializationApi::class)
    var json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    val safeJson = SafeJson(json)

    @OptIn(ExperimentalSerializationApi::class)
    var jsonWithClassDiscriminator = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        classDiscriminatorMode = ClassDiscriminatorMode.NONE
    }

    val safeJsonWithDiscriminator = SafeJson(jsonWithClassDiscriminator)
}
