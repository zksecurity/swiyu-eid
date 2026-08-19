package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.AvRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.UploadFileRequest
import com.github.michaelbull.result.Result

interface EIdAvRepository {
    suspend fun uploadFileToCase(
        file: UploadFileRequest
    ): Result<Unit, AvRepositoryError>

    suspend fun submitCase(
        caseId: String,
        accessToken: String
    ): Result<Unit, AvRepositoryError>
}
