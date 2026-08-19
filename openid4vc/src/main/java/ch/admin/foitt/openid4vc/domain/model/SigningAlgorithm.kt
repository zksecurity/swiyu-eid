package ch.admin.foitt.openid4vc.domain.model

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class SigningAlgorithm(val stdName: String) {
    @SerialName("ES512")
    ES512("ES512"),

    @SerialName("ES256")
    ES256("ES256"),
}

fun SigningAlgorithm.toJWSAlgorithm(): JWSAlgorithm = when (this) {
    SigningAlgorithm.ES256 -> JWSAlgorithm.ES256
    SigningAlgorithm.ES512 -> JWSAlgorithm.ES512
}

fun SigningAlgorithm.toCurve(): Curve = when (this) {
    SigningAlgorithm.ES256 -> Curve.P_256
    SigningAlgorithm.ES512 -> Curve.P_521
}

fun SigningAlgorithm.toSignatureName(): String = when (this) {
    SigningAlgorithm.ES256 -> "SHA256withECDSA"
    SigningAlgorithm.ES512 -> "SHA512withECDSA"
}
