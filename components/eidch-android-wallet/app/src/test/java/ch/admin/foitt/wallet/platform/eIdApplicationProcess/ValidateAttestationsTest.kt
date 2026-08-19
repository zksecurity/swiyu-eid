package ch.admin.foitt.wallet.platform.eIdApplicationProcess

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.KeyAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.EIdRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation.ValidateAttestationsImpl
import ch.admin.foitt.wallet.util.assertErrorType
import ch.admin.foitt.wallet.util.assertOk
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.impl.annotations.MockK
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ValidateAttestationsTest {

    @MockK
    private lateinit var mockSIdRepository: SIdRepository

    @MockK
    private lateinit var mockClientAttestation: ClientAttestation

    @MockK
    private lateinit var mockKeyAttestation: KeyAttestation

    private lateinit var useCase: ValidateAttestationsImpl

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)

        useCase = ValidateAttestationsImpl(
            sIdRepository = mockSIdRepository,
        )

        coEvery {
            mockSIdRepository.validateAttestations(any(), any())
        } returns Ok(Unit)
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `A successful validation returns Ok`() = runTest {
        val result = useCase(
            clientAttestation = mockClientAttestation,
            keyAttestation = mockKeyAttestation,
        )

        result.assertOk()
    }

    @Test
    fun `An error is properly mapped`() = runTest {
        coEvery {
            mockSIdRepository.validateAttestations(any(), any())
        } returns Err(EIdRequestError.InvalidClientAttestation)

        val result = useCase(
            clientAttestation = mockClientAttestation,
            keyAttestation = mockKeyAttestation,
        )

        result.assertErrorType(EIdRequestError.InvalidClientAttestation::class)
    }
}
