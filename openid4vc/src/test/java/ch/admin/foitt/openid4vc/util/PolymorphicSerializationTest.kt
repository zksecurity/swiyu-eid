package ch.admin.foitt.openid4vc.util

import com.github.michaelbull.result.get
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * These tests demonstrate the behavior of polymorphic serialization in Kotlin when using
 * different `ClassDiscriminatorMode` settings.
 *
 * When using `ClassDiscriminatorMode.NONE`, the `type` attribute is omitted from the JSON.
 * As a result, during deserialization, the runtime is unable to determine the correct subclass
 * of `Credential` to instantiate, and deserialization fails.
 *
 * When a discriminator is used (either the default or a custom one via @SerialName), the
 * `type` attribute is included in the JSON, allowing the deserializer to correctly
 * reconstruct the original subclass instance.
 */
class PolymorphicSerializationTest {

    private lateinit var twoFieldsCredential: Credential
    private lateinit var threeFieldsCredential: Credential
    private lateinit var oneFieldCredential: Credential
    private lateinit var anotherOneFieldCredential: Credential

    @BeforeEach
    fun setUp() {
        twoFieldsCredential = TwoFieldsCredential("some name", "me")
        threeFieldsCredential = ThreeFieldsCredential("shared name", "group", 1)
        oneFieldCredential = OneFieldCredential("shared name")
        anotherOneFieldCredential = AnotherOneFieldCredential("shared name")
    }

    @Test
    fun testSerializationWithDiscriminator() {
        val safeJson = SafeJsonTestInstance.safeJsonWithDiscriminator
        val resultTwoFieldsCredential = safeJson.safeEncodeObjectToString(twoFieldsCredential)
        val resultThreeFieldsCredential = safeJson.safeEncodeObjectToString(threeFieldsCredential)
        val resultOneFieldCredential = safeJson.safeEncodeObjectToString(oneFieldCredential)
        val resultAnotherOneFieldCredential = safeJson.safeEncodeObjectToString(anotherOneFieldCredential)

        val afterTwoFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultTwoFieldsCredential.get()!!)
        val afterThreeFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultThreeFieldsCredential.get()!!)
        val afterOneFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultOneFieldCredential.get()!!)
        val afterAnotherOneFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultAnotherOneFieldCredential.get()!!)

        assert(resultTwoFieldsCredential.get()!!.contains("owner"))
        assert(resultThreeFieldsCredential.get()!!.contains("someOtherData"))
        assert(!resultOneFieldCredential.get()!!.contains("someOtherData"))
        assert(!resultAnotherOneFieldCredential.get()!!.contains("someOtherData"))

        assert(afterTwoFieldsCredential.isErr)
        assert(afterThreeFieldsCredential.isErr)
        assert(afterOneFieldsCredential.isErr)
        assert(afterAnotherOneFieldsCredential.isErr)
    }

    @Test
    fun testSerializationWithoutDiscriminator() {
        val safeJson = SafeJsonTestInstance.safeJson
        val resultTwoFieldsCredential = safeJson.safeEncodeObjectToString(twoFieldsCredential)
        val resultThreeFieldsCredential = safeJson.safeEncodeObjectToString(threeFieldsCredential)
        val resultOneFieldCredential = safeJson.safeEncodeObjectToString(oneFieldCredential)
        val resultAnotherOneFieldCredential = safeJson.safeEncodeObjectToString(anotherOneFieldCredential)

        val afterTwoFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultTwoFieldsCredential.get()!!)
        val afterThreeFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultThreeFieldsCredential.get()!!)
        val afterOneFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultOneFieldCredential.get()!!)
        val afterAnotherOneFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultAnotherOneFieldCredential.get()!!)

        assert(resultTwoFieldsCredential.get()!!.contains("owner"))
        assert(resultThreeFieldsCredential.get()!!.contains("someOtherData"))
        assert(
            resultOneFieldCredential.get()!! == "{\"type\":\"ch.admin.foitt.openid4vc.util.OneFieldCredential\",\"name\":\"shared name\"}"
        )
        assert(
            resultAnotherOneFieldCredential.get()!! == "{\"type\":\"ch.admin.foitt.openid4vc.util.AnotherOneFieldCredential\",\"name\":\"shared name\"}"
        )

        assert(afterTwoFieldsCredential.isOk)
        assert(afterThreeFieldsCredential.isOk)
        assert(afterOneFieldsCredential.isOk)
        assert(afterAnotherOneFieldsCredential.isOk)
    }

    @Test
    fun testSerializationWithSerialName() {
        val oneFieldCredentialWithSerialName: Credential = OneFieldCredentialWithSerialName("shared name")
        val anotherOneFieldCredentialWithSerialName: Credential = AnotherOneFieldCredentialWithSerialName("shared name")
        val safeJson = SafeJsonTestInstance.safeJson
        val resultOneFieldCredential = safeJson.safeEncodeObjectToString(oneFieldCredentialWithSerialName)
        val resultAnotherOneFieldCredential = safeJson.safeEncodeObjectToString(anotherOneFieldCredentialWithSerialName)

        val afterOneFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultOneFieldCredential.get()!!)
        val afterAnotherOneFieldsCredential = safeJson.safeDecodeStringTo<Credential>(resultAnotherOneFieldCredential.get()!!)

        assert(resultOneFieldCredential.get()!!.contains("oneField"))
        assert(resultOneFieldCredential.get()!! == "{\"type\":\"oneField\",\"name\":\"shared name\"}")
        assert(resultAnotherOneFieldCredential.get()!!.contains("anotherOneField"))
        assert(resultAnotherOneFieldCredential.get()!! == "{\"type\":\"anotherOneField\",\"name\":\"shared name\"}")

        assert(afterOneFieldsCredential.isOk)
        assert(afterAnotherOneFieldsCredential.isOk)
    }
}
