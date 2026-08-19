package ch.admin.foitt.wallet.platform.activityList.data.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityClaimRepositoryError
import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityListError
import ch.admin.foitt.wallet.platform.activityList.domain.repository.ActivityClaimRepository
import ch.admin.foitt.wallet.platform.database.data.dao.ActivityClaimEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.DaoProvider
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityClaimEntity
import ch.admin.foitt.wallet.platform.di.IoDispatcher
import ch.admin.foitt.wallet.platform.utils.suspendUntilNonNull
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject

class ActivityClaimRepositoryImpl @Inject constructor(
    daoProvider: DaoProvider,
    @param:IoDispatcher private val ioDispatcher: CoroutineDispatcher,
) : ActivityClaimRepository {
    override suspend fun insert(activityClaimEntity: ActivityClaimEntity): Result<Long, ActivityClaimRepositoryError> = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().insert(activityClaimEntity)
        }
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error when inserting activity claim entity")
        ActivityListError.Unexpected(throwable)
    }

    override suspend fun getById(activityClaimId: Long): Result<ActivityClaimEntity, ActivityClaimRepositoryError> = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().getById(activityClaimId)
        }
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error when getting activity claim entity")
        ActivityListError.Unexpected(throwable)
    }

    private suspend fun dao(): ActivityClaimEntityDao = suspendUntilNonNull { daoFlow.value }
    private val daoFlow = daoProvider.activityClaimEntityDao
}
