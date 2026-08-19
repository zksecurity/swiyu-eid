package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.UploadFileRequest
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.EIdAvRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.UploadFileToCase
import javax.inject.Inject

class UploadFileToCaseImpl @Inject constructor(
    private val eIdAvRepository: EIdAvRepository
) : UploadFileToCase {
    override suspend fun invoke(
        file: UploadFileRequest
    ) = eIdAvRepository.uploadFileToCase(
        file = file
    )
}
