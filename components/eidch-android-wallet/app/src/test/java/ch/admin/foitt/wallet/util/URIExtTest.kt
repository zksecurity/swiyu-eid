package ch.admin.foitt.wallet.util

import ch.admin.foitt.wallet.platform.utils.getQueryParameter
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.URI

class URIExtTest {

    @Test
    fun `Getting the parameter value of a simple URI returns the value`() = runTest {
        val result = simpleUri.getQueryParameter("param1").assertOk()
        assertEquals(simpleUriParamValue, result)
    }

    @Test
    fun `Getting the parameter value of a complex URI returns the value`() = runTest {
        val result = complexUri.getQueryParameter("param2").assertOk()
        assertEquals(complexUriParamValue, result)
    }

    @Test
    fun `Trying to get a non-existing parameter returns null`() = runTest {
        val result = simpleUri.getQueryParameter("otherParam").assertOkNullable()
        assertEquals(null, result)
    }

    @Test
    fun `Getting the parameter of a deeplink style uri returns a success`() = runTest {
        val result = deeplinkUri.getQueryParameter("client_id").assertOk()
        assertEquals(deeplinkUriParamValue, result)
    }

    @Test
    fun `Getting the parameter of a uri that contains multiple times the same parameter returns the first one`() = runTest {
        val result = multipleParamUri.getQueryParameter("param1").assertOk()
        assertEquals(multipleParamUriParamValue, result)
    }

    private val simpleUri = URI("https%3A%2F%2Fexample.com?param1=param1Value")
    private val simpleUriParamValue = "param1Value"

    private val complexUri = URI("https%3A%2F%2Fexample.com?param1=param1Value&param2=value%26value")
    private val complexUriParamValue = "value&value"

    private val multipleParamUri = URI("https%3A%2F%2Fexample.com?param1=param1Value&param1=param1Value2")
    private val multipleParamUriParamValue = "param1Value"

    private val deeplinkUri = URI(
        "swiyu-verify://?client_id=did%3Atdw%3Aexample.com&request_uri=https%3A%2F%2Ftfp.example.com%2Frequest.jwt%2FGkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"
    )
    private val deeplinkUriParamValue = "did:tdw:example.com"
}
