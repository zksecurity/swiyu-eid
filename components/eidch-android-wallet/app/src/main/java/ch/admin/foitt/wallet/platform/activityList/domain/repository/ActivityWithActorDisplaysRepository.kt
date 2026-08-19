package ch.admin.foitt.wallet.platform.activityList.domain.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityWithActorDisplaysRepositoryError
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityWithActorDisplays
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow

interface ActivityWithActorDisplaysRepository {
    fun getActivitiesByCredentialId(
        credentialId: Long
    ): Flow<Result<List<ActivityWithActorDisplays>, ActivityWithActorDisplaysRepositoryError>>
}
