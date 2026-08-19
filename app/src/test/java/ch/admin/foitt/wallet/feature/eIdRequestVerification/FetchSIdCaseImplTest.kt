package ch.admin.foitt.wallet.feature.eIdRequestVerification

import ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase.FetchSIdCase
import ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase.implementation.FetchSIdCaseImpl
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.AttestationError
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationPoP
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.GenerateProofOfPossession
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.RequestClientAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.ApplyRequest
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.CaseResponse
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.EIdRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.IdentityType
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.SIdChallengeResponse
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.environmentSetup.domain.repository.EnvironmentSetupRepository
import ch.admin.foitt.wallet.util.SafeJsonTestInstance
import ch.admin.foitt.wallet.util.assertErrorType
import ch.admin.foitt.wallet.util.assertOk
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.coVerifyOrder
import io.mockk.impl.annotations.MockK
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class FetchSIdCaseImplTest {

    @MockK
    private lateinit var mockSIdRepository: SIdRepository

    @MockK
    private lateinit var mockRequestClientAttestation: RequestClientAttestation

    @MockK
    private lateinit var mockGenerateProofOfPossession: GenerateProofOfPossession

    @MockK
    private lateinit var mockEnvironmentSetupRepository: EnvironmentSetupRepository

    private val mockSIdUrl = "https://example.com"
    private val mockSIdChallenge = SIdChallengeResponse("someChallenge")

    private val testSafeJson = SafeJsonTestInstance.safeJson

    lateinit var fetchSIdCase: FetchSIdCase
    private val testApplyRequest = ApplyRequest(
        mrz = listOf("ID<<<I7A<<<<<<7<<<<<<<<<<<<<<<", "1001015X3012316<<<<<<<<<<<<<<2", "MINDERJAEHRIGE<<ANNETTE<<<<<<<"),
        legalRepresentant = false,
        email = null
    )

    private val testCaseResponse = CaseResponse(
        caseId = "1234-5678-abcd-1234567890ABCDE",
        surname = "Muster",
        givenNames = "Max Felix",
        dateOfBirth = "1989-08-24T00:00:00Z",
        identityType = IdentityType.SWISS_PASS,
        identityNumber = "A123456789",
        validUntil = "2028-12-23T00:00:00Z",
        legalRepresentant = false,
        email = "user@examle.com"
    )

    @MockK
    private lateinit var mockClientAttestation: ClientAttestation

    @MockK
    private lateinit var mockClientAttestationPoP: ClientAttestationPoP

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)
        fetchSIdCase = FetchSIdCaseImpl(
            sIdRepository = mockSIdRepository,
            requestClientAttestation = mockRequestClientAttestation,
            generateProofOfPossession = mockGenerateProofOfPossession,
            environmentSetupRepository = mockEnvironmentSetupRepository,
            safeJson = testSafeJson,
        )

        coEvery { mockSIdRepository.requestSIdCase(any(), any(), any()) } returns Ok(testCaseResponse)
        coEvery { mockRequestClientAttestation(any(), any()) } returns Ok(mockClientAttestation)
        coEvery { mockSIdRepository.fetchChallenge() } returns Ok(mockSIdChallenge)
        coEvery { mockGenerateProofOfPossession(any(), any(), any(), any()) } returns Ok(mockClientAttestationPoP)
        coEvery { mockEnvironmentSetupRepository.sidBackendUrl } returns mockSIdUrl
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `A success follow specific step`() = runTest {
        val response = fetchSIdCase(testApplyRequest).assertOk()

        assertEquals(testCaseResponse.caseId, response.caseId)
        assertEquals(testCaseResponse.surname, response.surname)
        assertEquals(testCaseResponse.legalRepresentant, response.legalRepresentant)

        coVerifyOrder {
            mockRequestClientAttestation(any(), any())
            mockSIdRepository.fetchChallenge()
            mockGenerateProofOfPossession(
                clientAttestation = mockClientAttestation,
                challenge = mockSIdChallenge.challenge,
                audience = mockSIdUrl,
                requestBody = any(),
            )

            mockSIdRepository.requestSIdCase(
                clientAttestation = mockClientAttestation,
                clientAttestationPoP = mockClientAttestationPoP,
                applyRequest = testApplyRequest,
            )
        }
    }

    @Test
    fun `A client attestation error is propagated`() = runTest {
        val exception = Exception("testException")
        coEvery {
            mockRequestClientAttestation(any(), any())
        } returns Err(AttestationError.Unexpected(exception))

        val error = fetchSIdCase(testApplyRequest).assertErrorType(EIdRequestError.Unexpected::class)
        assertEquals(exception, error.cause)
    }

    @Test
    fun `A challenge fetching failure is propagated`() = runTest {
        coEvery {
            mockSIdRepository.fetchChallenge()
        } returns Err(EIdRequestError.NetworkError)

        fetchSIdCase(testApplyRequest).assertErrorType(EIdRequestError.NetworkError::class)
    }

    @Test
    fun `A client attestation PoP generation failure is propagated`() = runTest {
        val exception = Exception("my exception")
        coEvery {
            mockGenerateProofOfPossession(any(), any(), any(), any())
        } returns Err(AttestationError.Unexpected(exception))

        val error = fetchSIdCase(testApplyRequest).assertErrorType(EIdRequestError.Unexpected::class)
        assertEquals(exception, error.cause)
    }

    @Test
    fun `A sId request failure is propagated`() = runTest {
        coEvery {
            mockSIdRepository.requestSIdCase(
                clientAttestation = any(),
                clientAttestationPoP = any(),
                applyRequest = any(),
            )
        } returns Err(EIdRequestError.NetworkError)

        fetchSIdCase(testApplyRequest).assertErrorType(EIdRequestError.NetworkError::class)
    }
}
