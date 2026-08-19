package ch.admin.foitt.wallet.platform.activityList.data.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityWithActorDisplaysRepositoryError
import ch.admin.foitt.wallet.platform.activityList.domain.model.toActivityWithDisplaysRepositoryError
import ch.admin.foitt.wallet.platform.activityList.domain.repository.ActivityWithActorDisplaysRepository
import ch.admin.foitt.wallet.platform.database.data.dao.DaoProvider
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityWithActorDisplays
import ch.admin.foitt.wallet.platform.utils.catchAndMap
import com.github.michaelbull.result.Result
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flatMapLatest
import javax.inject.Inject

@OptIn(ExperimentalCoroutinesApi::class)
class ActivityWithActorDisplaysRepositoryImpl @Inject constructor(
    daoProvider: DaoProvider,
) : ActivityWithActorDisplaysRepository {
    override fun getActivitiesByCredentialId(
        credentialId: Long
    ): Flow<Result<List<ActivityWithActorDisplays>, ActivityWithActorDisplaysRepositoryError>> = daoFlow.flatMapLatest { dao ->
        dao?.getActivitiesByCredentialIdFlow(credentialId)
            ?.catchAndMap { throwable ->
                throwable.toActivityWithDisplaysRepositoryError("Error getting ActivityWithDetails by credentialId")
            } ?: emptyFlow()
    }

    private val daoFlow = daoProvider.activityWithDisplaysDao
}
