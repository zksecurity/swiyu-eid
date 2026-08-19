package ch.admin.foitt.wallet.platform.utils.domain.usecase.implementation

import android.net.Uri
import ch.admin.foitt.wallet.platform.utils.base64NonUrlStringToByteArray
import ch.admin.foitt.wallet.platform.utils.domain.usecase.GetImageDataFromUri
import ch.admin.foitt.wallet.util.assertTrue
import io.mockk.MockKAnnotations
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertNull

class GetImageDataFromUriImplTest {

    @MockK
    private lateinit var mockUri: Uri

    private lateinit var useCase: GetImageDataFromUri

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)

        mockkStatic(Uri::class)
        every { Uri.parse(any()) } returns mockUri

        useCase = GetImageDataFromUriImpl()
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `valid data uri returns image data`() = runTest {
        val scheme = "data"
        val path = "image/png;base64,"
        val imageData = "AAECAw=="
        every { mockUri.scheme } returns scheme
        every { mockUri.path } returns "$path$imageData"
        every { mockUri.toString() } returns "$scheme:$path$imageData"
        mockkStatic("ch.admin.foitt.wallet.platform.utils.StringUtilsKt")
        every { base64NonUrlStringToByteArray(any()) } returns byteArrayOf(0, 1, 2, 3)

        val result = useCase("$scheme:$path$imageData")
        assertTrue(byteArrayOf(0, 1, 2, 3).contentEquals(result)) {
            "$scheme:$path$imageData"
        }
    }

    @TestFactory
    fun `invalid uris return null`(): List<DynamicTest> {
        return invalidUriInputs().map { input ->
            DynamicTest.dynamicTest("$input should return null") {
                runTest {
                    every { mockUri.scheme } returns input.first
                    every { mockUri.path } returns input.second

                    val uriString = "${input.first}:${input.second}"

                    assertNull(useCase(uriString))
                }
            }
        }
    }

    @Test
    fun `null input returns null`() = runTest {
        assertNull(useCase(null))
    }

    private fun invalidUriInputs(): List<Pair<String, String>> = listOf(
        validHttpsUri,
        invalidUri,
    )

    private val validHttpsUri = Pair("https", "//www.example.org/image")
    private val invalidUri = Pair("invalid uri", "")
}
