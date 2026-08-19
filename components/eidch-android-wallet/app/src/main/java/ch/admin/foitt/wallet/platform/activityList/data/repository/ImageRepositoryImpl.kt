package ch.admin.foitt.wallet.platform.activityList.data.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityListError
import ch.admin.foitt.wallet.platform.activityList.domain.model.ImageRepositoryError
import ch.admin.foitt.wallet.platform.activityList.domain.repository.ImageRepository
import ch.admin.foitt.wallet.platform.database.data.dao.DaoProvider
import ch.admin.foitt.wallet.platform.database.data.dao.ImageEntityDao
import ch.admin.foitt.wallet.platform.database.domain.model.ImageEntity
import ch.admin.foitt.wallet.platform.di.IoDispatcher
import ch.admin.foitt.wallet.platform.utils.suspendUntilNonNull
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject

class ImageRepositoryImpl @Inject constructor(
    daoProvider: DaoProvider,
    @param:IoDispatcher private val ioDispatcher: CoroutineDispatcher
) : ImageRepository {

    override suspend fun insert(imageEntity: ImageEntity): Result<Long, ImageRepositoryError> = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().insert(imageEntity)
        }
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error when inserting image entity")
        ActivityListError.Unexpected(throwable)
    }

    override suspend fun getByHash(hash: String): Result<ImageEntity, ImageRepositoryError> = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().getByHash(hash)
        }
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error when inserting activity actor display entity")
        ActivityListError.Unexpected(throwable)
    }

    private suspend fun dao(): ImageEntityDao = suspendUntilNonNull { daoFlow.value }
    private val daoFlow = daoProvider.imageEntityDao
}
