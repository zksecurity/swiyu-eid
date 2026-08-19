package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.AutoVerificationResponse

fun interface SetStartAutoVerificationResult {
    operator fun invoke(startAutoVerificationResult: AutoVerificationResponse)
}
