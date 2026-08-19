package ch.admin.foitt.wallet.platform.trustRegistry.domain.usecase

import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.FetchVcSchemaTrustStatusError
import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.TrustStatementActor
import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.VcSchemaTrustStatus
import com.github.michaelbull.result.Result

interface FetchVcSchemaTrustStatus {
    suspend operator fun invoke(
        trustStatementActor: TrustStatementActor,
        actorDid: String,
        vcSchemaId: String,
    ): Result<VcSchemaTrustStatus, FetchVcSchemaTrustStatusError>
}
