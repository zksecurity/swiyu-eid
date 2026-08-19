package ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase

import ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.model.SaveEIdRequestStateError
import ch.admin.foitt.wallet.platform.database.domain.model.EIdRequestState
import com.github.michaelbull.result.Result

interface SaveEIdRequestState {
    suspend operator fun invoke(state: EIdRequestState): Result<Long, SaveEIdRequestStateError>
}
