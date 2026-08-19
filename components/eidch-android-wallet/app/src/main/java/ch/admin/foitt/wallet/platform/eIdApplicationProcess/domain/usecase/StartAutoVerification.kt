package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.AutoVerificationResponse
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.StartAutoVerificationError
import com.github.michaelbull.result.Result

fun interface StartAutoVerification {
    suspend operator fun invoke(caseId: String): Result<AutoVerificationResponse, StartAutoVerificationError>
}
