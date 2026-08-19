package ch.admin.foitt.wallet.platform.eIdApplicationProcess.data.repository

import ch.admin.foitt.wallet.platform.database.data.dao.DaoProvider
import ch.admin.foitt.wallet.platform.database.data.dao.EIdRequestFileDao
import ch.admin.foitt.wallet.platform.database.domain.model.EIdRequestFile
import ch.admin.foitt.wallet.platform.di.IoDispatcher
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.EIdRequestFileRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.toEIdRequestFileError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.EIdRequestFileRepository
import ch.admin.foitt.wallet.platform.utils.suspendUntilNonNull
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import javax.inject.Inject

class EIdRequestFileRepositoryImpl @Inject constructor(
    @param:IoDispatcher private val ioDispatcher: CoroutineDispatcher,
    daoProvider: DaoProvider,
) : EIdRequestFileRepository {
    override suspend fun saveEIdRequestFile(
        file: EIdRequestFile,
    ): Result<Long, EIdRequestFileRepositoryError> = withContext(ioDispatcher) {
        runSuspendCatching {
            eIdRequestFileDao().insert(file)
        }.mapError {
            it.toEIdRequestFileError("Failed to save EId request file")
        }
    }

    override suspend fun saveEIdRequestFiles(
        files: List<EIdRequestFile>,
    ): Result<List<Long>, EIdRequestFileRepositoryError> = withContext(ioDispatcher) {
        runSuspendCatching {
            eIdRequestFileDao().insertAll(files)
        }.mapError {
            it.toEIdRequestFileError("Failed to save EId request files")
        }
    }

    override suspend fun getEIdRequestFilesByCaseId(
        caseId: String
    ): Result<List<EIdRequestFile>, EIdRequestFileRepositoryError> = withContext(ioDispatcher) {
        runSuspendCatching {
            eIdRequestFileDao().getAllFilesByCaseId(caseId)
        }.mapError {
            it.toEIdRequestFileError("Failed to get EId request files")
        }
    }

    override suspend fun getEIdRequestFileByCaseIdAndFileName(
        caseId: String,
        fileName: String
    ): Result<EIdRequestFile, EIdRequestFileRepositoryError> = withContext(ioDispatcher) {
        runSuspendCatching {
            eIdRequestFileDao().getFile(caseId, fileName)
        }.mapError {
            it.toEIdRequestFileError("Failed to get EId request file")
        }
    }

    private val eIdRequestFileDaoFlow = daoProvider.eIdRequestFileDaoFlow
    private suspend fun eIdRequestFileDao(): EIdRequestFileDao = suspendUntilNonNull { eIdRequestFileDaoFlow.value }
}
