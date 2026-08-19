package ch.admin.foitt.wallet.platform.trustRegistry.domain.usecase

import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.GetTrustDomainFromDidError
import com.github.michaelbull.result.Result

fun interface GetTrustDomainFromDid {
    operator fun invoke(
        actorDid: String,
    ): Result<String, GetTrustDomainFromDidError>
}
