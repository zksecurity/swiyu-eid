package ch.admin.foitt.openid4vc.util

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class Credential {
    abstract val name: String
}

@Serializable
class TwoFieldsCredential(override val name: String, val owner: String) : Credential()

@Serializable
class ThreeFieldsCredential(override val name: String, val group: String, val someOtherData: Int) : Credential()

@Serializable
class OneFieldCredential(override val name: String) : Credential()

@Serializable
class AnotherOneFieldCredential(override val name: String) : Credential()

@Serializable
@SerialName("oneField")
class OneFieldCredentialWithSerialName(override val name: String) : Credential()

@Serializable
@SerialName("anotherOneField")
class AnotherOneFieldCredentialWithSerialName(override val name: String) : Credential()
