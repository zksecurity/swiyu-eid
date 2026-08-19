package ch.admin.foitt.wallet.platform.trustRegistry.domain.usecase

import ch.admin.foitt.openid4vc.domain.model.vcSdJwt.VcSdJwt
import ch.admin.foitt.wallet.platform.trustRegistry.domain.model.ValidateTrustStatementError
import com.github.michaelbull.result.Result

interface ValidateTrustStatement {
    suspend operator fun invoke(
        trustStatement: VcSdJwt,
        actorDid: String,
    ): Result<VcSdJwt, ValidateTrustStatementError>
}
