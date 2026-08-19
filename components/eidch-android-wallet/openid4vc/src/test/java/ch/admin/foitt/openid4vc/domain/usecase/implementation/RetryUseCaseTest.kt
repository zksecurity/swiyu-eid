package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.JwkError
import ch.admin.foitt.openid4vc.domain.usecase.CreateJwk
import ch.admin.foitt.openid4vc.domain.usecase.implementation.mock.MockKeyPairs.VALID_KEY_PAIR_HARDWARE
import ch.admin.foitt.openid4vc.util.assertErrorType
import ch.admin.foitt.openid4vc.util.assertOk
import ch.admin.foitt.openid4vc.utils.retryUseCase
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.impl.annotations.MockK
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RetryUseCaseTest {

    @MockK
    private lateinit var createJwk: CreateJwk

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)

        coEvery { createJwk(any(), any()) } returns Ok("")
    }

    @Test
    fun `retry returns success if first iteration is successful`() = runTest {
        retryUseCase {
            createJwk(
                algorithm = VALID_KEY_PAIR_HARDWARE.algorithm,
                keyPair = VALID_KEY_PAIR_HARDWARE.keyPair
            )
        }.assertOk()

        coVerify(exactly = 1) {
            createJwk(any(), any())
        }
    }

    @Test
    fun `retry returns success if third iteration is successful`() = runTest {
        val errorResult = Err(JwkError.Unexpected(Exception("")))
        coEvery {
            createJwk(any(), any())
        } returnsMany listOf(
            errorResult, errorResult, Ok("")
        )

        retryUseCase {
            createJwk(
                algorithm = VALID_KEY_PAIR_HARDWARE.algorithm,
                keyPair = VALID_KEY_PAIR_HARDWARE.keyPair
            )
        }.assertOk()

        coVerify(exactly = 3) {
            createJwk(any(), any())
        }
    }

    @Test
    fun `retry returns error if all iterations fail`() = runTest {
        coEvery { createJwk(any(), any()) } returns Err(JwkError.Unexpected(Exception("")))

        retryUseCase {
            createJwk(
                algorithm = VALID_KEY_PAIR_HARDWARE.algorithm,
                keyPair = VALID_KEY_PAIR_HARDWARE.keyPair
            )
        }.assertErrorType(JwkError.Unexpected::class)

        coVerify(exactly = 3) {
            createJwk(any(), any())
        }
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }
}
