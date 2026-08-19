package ch.admin.foitt.wallet.platform.activityList.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityListError
import ch.admin.foitt.wallet.platform.activityList.domain.repository.CredentialActivityRepository
import ch.admin.foitt.wallet.platform.activityList.domain.usecase.DeleteActivity
import ch.admin.foitt.wallet.util.assertErrorType
import ch.admin.foitt.wallet.util.assertOk
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

class DeleteActivityImplTest {

    @MockK
    private lateinit var mockCredentialActivityRepository: CredentialActivityRepository

    private lateinit var useCase: DeleteActivity

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)
        useCase = DeleteActivityImpl(
            credentialActivityRepository = mockCredentialActivityRepository,
        )

        coEvery {
            mockCredentialActivityRepository.deleteById(any())
        } returns Ok(Unit)
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `Deleting an activity calls the repo with the correct parameters`() = runTest {
        val activityId = 1L

        useCase(activityId).assertOk()

        coVerify {
            mockCredentialActivityRepository.deleteById(activityId)
        }
    }

    @Test
    fun `Deleting an activity maps errors from the repository`() = runTest {
        coEvery {
            mockCredentialActivityRepository.deleteById(any())
        } returns Err(ActivityListError.Unexpected(IllegalStateException("error in repo")))

        useCase(activityId = 1L).assertErrorType(ActivityListError.Unexpected::class)
    }
}
