package ch.admin.foitt.wallet.platform.activityList.domain.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityActorDisplayRepositoryError
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityActorDisplayEntity
import com.github.michaelbull.result.Result

interface ActivityActorDisplayRepository {
    suspend fun insert(activityActorDisplay: ActivityActorDisplayEntity): Result<Long, ActivityActorDisplayRepositoryError>
    suspend fun getById(activityActorDisplayId: Long): Result<ActivityActorDisplayEntity, ActivityActorDisplayRepositoryError>
}
