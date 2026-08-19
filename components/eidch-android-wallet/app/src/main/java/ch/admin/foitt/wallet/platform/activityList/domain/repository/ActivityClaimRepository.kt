package ch.admin.foitt.wallet.platform.activityList.domain.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityClaimRepositoryError
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityClaimEntity
import com.github.michaelbull.result.Result

interface ActivityClaimRepository {
    suspend fun insert(activityClaimEntity: ActivityClaimEntity): Result<Long, ActivityClaimRepositoryError>
    suspend fun getById(activityClaimId: Long): Result<ActivityClaimEntity, ActivityClaimRepositoryError>
}
