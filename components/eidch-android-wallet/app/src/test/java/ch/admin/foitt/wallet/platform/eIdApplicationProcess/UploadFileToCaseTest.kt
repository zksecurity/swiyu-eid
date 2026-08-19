package ch.admin.foitt.wallet.platform.eIdApplicationProcess

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.EIdRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.UploadFileRequest
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.EIdAvRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation.UploadFileToCaseImpl
import ch.admin.foitt.wallet.util.assertErrorType
import ch.admin.foitt.wallet.util.assertOk
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import io.ktor.http.ContentType
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.impl.annotations.MockK
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class UploadFileToCaseTest {

    @MockK
    private lateinit var mockEIdAvRepository: EIdAvRepository

    private lateinit var useCase: UploadFileToCaseImpl

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)

        useCase = UploadFileToCaseImpl(
            eIdAvRepository = mockEIdAvRepository
        )

        coEvery {
            mockEIdAvRepository.uploadFileToCase(any())
        } returns Ok(Unit)
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `A successful upload returns Ok`() = runTest {
        val result = useCase(
            UploadFileRequest(
                caseId = "",
                accessToken = "",
                fileName = "",
                document = byteArrayOf(),
                mime = ContentType.Image.PNG
            )
        )

        result.assertOk()
    }

    @Test
    fun `An error is properly mapped`() = runTest {
        coEvery {
            mockEIdAvRepository.uploadFileToCase(any())
        } returns Err(EIdRequestError.DeclinedProcessData(""))

        val result = useCase(
            UploadFileRequest(
                caseId = "",
                accessToken = "",
                fileName = "",
                document = byteArrayOf(),
                mime = ContentType.Image.PNG
            )
        )

        result.assertErrorType(EIdRequestError.DeclinedProcessData::class)
    }
}
