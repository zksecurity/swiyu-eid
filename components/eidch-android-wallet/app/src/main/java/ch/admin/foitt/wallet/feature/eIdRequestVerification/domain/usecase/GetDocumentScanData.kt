package ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase

import ch.admin.foitt.avwrapper.DocumentScanPackageResult
import ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.model.GetDocumentScanDataError
import com.github.michaelbull.result.Result

fun interface GetDocumentScanData {
    suspend operator fun invoke(caseId: String): Result<DocumentScanPackageResult, GetDocumentScanDataError>
}
