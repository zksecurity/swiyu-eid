package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.AvRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.UploadFileRequest
import com.github.michaelbull.result.Result

interface UploadFileToCase {
    suspend operator fun invoke(
        file: UploadFileRequest
    ): Result<Unit, AvRepositoryError>
}
