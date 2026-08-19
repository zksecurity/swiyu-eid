package ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.AvSubmitCaseError
import com.github.michaelbull.result.Result

interface SubmitCaseId {
    suspend operator fun invoke(caseId: String, accessToken: String): Result<Unit, AvSubmitCaseError>
}
