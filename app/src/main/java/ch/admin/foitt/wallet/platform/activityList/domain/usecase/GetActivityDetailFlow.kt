package ch.admin.foitt.wallet.platform.activityList.domain.usecase

import ch.admin.foitt.wallet.platform.activityList.domain.model.ActivityDetail
import ch.admin.foitt.wallet.platform.activityList.domain.model.GetActivityDetailFlowError
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow

interface GetActivityDetailFlow {
    operator fun invoke(
        credentialId: Long,
        activityId: Long,
    ): Flow<Result<ActivityDetail?, GetActivityDetailFlowError>>
}
