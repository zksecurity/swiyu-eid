package ch.admin.foitt.wallet.platform.activityList.data.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityActorDisplayRepositoryError
import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityListError
import ch.admin.foitt.wallet.platform.activityList.domain.repository.ActivityActorDisplayRepository
import ch.admin.foitt.wallet.platform.database.data.dao.ActivityActorDisplayEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.DaoProvider
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityActorDisplayEntity
import ch.admin.foitt.wallet.platform.di.IoDispatcher
import ch.admin.foitt.wallet.platform.utils.suspendUntilNonNull
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject

class ActivityActorDisplayRepositoryImpl @Inject constructor(
    daoProvider: DaoProvider,
    @param:IoDispatcher private val ioDispatcher: CoroutineDispatcher
) : ActivityActorDisplayRepository {
    override suspend fun insert(
        activityActorDisplay: ActivityActorDisplayEntity
    ): Result<Long, ActivityActorDisplayRepositoryError> = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().insert(activityActorDisplay)
        }
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error when inserting activity actor display entity")
        ActivityListError.Unexpected(throwable)
    }

    override suspend fun getById(
        activityActorDisplayId: Long
    ): Result<ActivityActorDisplayEntity, ActivityActorDisplayRepositoryError> = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().getById(activityActorDisplayId)
        }
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error when getting activity actor display entity")
        ActivityListError.Unexpected(throwable)
    }

    private suspend fun dao(): ActivityActorDisplayEntityDao = suspendUntilNonNull { daoFlow.value }
    private val daoFlow = daoProvider.activityActorDisplayEntityDao
}
