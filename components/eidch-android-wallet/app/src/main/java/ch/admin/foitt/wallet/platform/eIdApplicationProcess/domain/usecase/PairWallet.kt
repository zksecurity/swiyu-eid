package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.PairWalletError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.PairWalletResponse
import com.github.michaelbull.result.Result

fun interface PairWallet {
    suspend operator fun invoke(caseId: String): Result<PairWalletResponse, PairWalletError>
}
