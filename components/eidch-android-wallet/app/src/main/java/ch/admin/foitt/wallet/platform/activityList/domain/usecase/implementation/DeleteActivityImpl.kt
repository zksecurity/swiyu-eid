package ch.admin.foitt.wallet.platform.activityList.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.activityList.domain.model.CredentialActivityRepositoryError
import ch.admin.foitt.wallet.platform.activityList.domain.model.DeleteActivityError
import ch.admin.foitt.wallet.platform.activityList.domain.model.toDeleteActivityError
import ch.admin.foitt.wallet.platform.activityList.domain.repository.CredentialActivityRepository
import ch.admin.foitt.wallet.platform.activityList.domain.usecase.DeleteActivity
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class DeleteActivityImpl @Inject constructor(
    private val credentialActivityRepository: CredentialActivityRepository,
) : DeleteActivity {
    override suspend fun invoke(activityId: Long): Result<Unit, DeleteActivityError> = coroutineBinding {
        credentialActivityRepository.deleteById(activityId)
            .mapError(CredentialActivityRepositoryError::toDeleteActivityError)
            .bind()
    }
}
