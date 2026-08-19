package ch.admin.foitt.wallet.platform.oca.domain.usecase

import ch.admin.foitt.wallet.platform.oca.domain.model.CaptureBase
import ch.admin.foitt.wallet.platform.oca.domain.model.GetRootCaptureBaseError
import com.github.michaelbull.result.Result

interface GetRootCaptureBase {
    suspend operator fun invoke(captureBases: List<CaptureBase>): Result<CaptureBase, GetRootCaptureBaseError>
}
