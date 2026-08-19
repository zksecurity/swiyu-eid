package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.StartOnlineSessionError
import com.github.michaelbull.result.Result

fun interface StartOnlineSession {
    suspend operator fun invoke(caseId: String): Result<Unit, StartOnlineSessionError>
}
