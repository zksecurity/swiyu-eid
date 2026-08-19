package ch.admin.foitt.wallet.platform.ssi.domain.usecase

import ch.admin.foitt.wallet.platform.credential.domain.model.CredentialDisplayData
import ch.admin.foitt.wallet.platform.ssi.domain.model.GetCredentialsWithDetailsFlowError
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow

interface GetCredentialsWithDetailsFlow {
    operator fun invoke(): Flow<Result<List<CredentialDisplayData>, GetCredentialsWithDetailsFlowError>>
}
