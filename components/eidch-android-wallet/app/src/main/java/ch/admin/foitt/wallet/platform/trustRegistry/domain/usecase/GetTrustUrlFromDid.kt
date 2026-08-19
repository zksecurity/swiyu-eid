package ch.admin.foitt.wallet.platform.trustRegistry.domain.usecase

import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.GetTrustUrlFromDidError
import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.TrustStatementType
import com.github.michaelbull.result.Result
import java.net.URL

fun interface GetTrustUrlFromDid {
    operator fun invoke(
        trustStatementType: TrustStatementType,
        actorDid: String,
        vcSchemaId: String?,
    ): Result<URL, GetTrustUrlFromDidError>
}
