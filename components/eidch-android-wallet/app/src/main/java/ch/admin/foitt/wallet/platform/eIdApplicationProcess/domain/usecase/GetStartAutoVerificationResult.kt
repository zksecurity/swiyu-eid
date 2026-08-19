package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.AutoVerificationResponse
import kotlinx.coroutines.flow.StateFlow

fun interface GetStartAutoVerificationResult {
    operator fun invoke(): StateFlow<AutoVerificationResponse?>
}
