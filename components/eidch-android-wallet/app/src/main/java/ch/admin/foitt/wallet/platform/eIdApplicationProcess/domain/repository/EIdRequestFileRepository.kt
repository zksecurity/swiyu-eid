package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository

import ch.admin.foitt.wallet.platform.database.domain.model.EIdRequestFile
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.EIdRequestFileRepositoryError
import com.github.michaelbull.result.Result

interface EIdRequestFileRepository {
    suspend fun saveEIdRequestFile(file: EIdRequestFile): Result<Long, EIdRequestFileRepositoryError>

    suspend fun saveEIdRequestFiles(files: List<EIdRequestFile>): Result<List<Long>, EIdRequestFileRepositoryError>

    suspend fun getEIdRequestFilesByCaseId(caseId: String): Result<List<EIdRequestFile>, EIdRequestFileRepositoryError>

    suspend fun getEIdRequestFileByCaseIdAndFileName(
        caseId: String,
        fileName: String
    ): Result<EIdRequestFile, EIdRequestFileRepositoryError>
}
