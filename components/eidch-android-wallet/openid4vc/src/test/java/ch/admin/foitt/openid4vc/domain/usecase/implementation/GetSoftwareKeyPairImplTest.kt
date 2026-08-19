package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.KeyPairError
import ch.admin.foitt.openid4vc.domain.usecase.GetSoftwareKeyPair
import ch.admin.foitt.openid4vc.util.assertErrorType
import ch.admin.foitt.openid4vc.util.assertOk
import io.mockk.MockKAnnotations
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class GetSoftwareKeyPairImplTest {

    private lateinit var useCase: GetSoftwareKeyPair

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)

        useCase = GetSoftwareKeyPairImpl()
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `Valid input returns success`() = runTest {
        val generator = KeyPairGenerator.getInstance("EC")
        val spec = ECGenParameterSpec("secp256r1")
        generator.initialize(spec)
        val originalKeyPair = generator.generateKeyPair()

        val publicKeyBytes = originalKeyPair.public.encoded
        val privateKeyBytes = originalKeyPair.private.encoded

        val result = useCase(publicKeyBytes, privateKeyBytes).assertOk()

        assertEquals(originalKeyPair.public, result.public)
        assertEquals(originalKeyPair.private, result.private)
    }

    @Test
    fun `Exceptions are caught and error is returned`() = runTest {
        useCase(byteArrayOf(), byteArrayOf()).assertErrorType(KeyPairError.Unexpected::class)
    }
}
