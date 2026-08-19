package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository

import ch.admin.foitt.avwrapper.DocumentScanPackageResult
import kotlinx.coroutines.flow.StateFlow

interface EIdDocumentScanRepository {
    val packageResult: StateFlow<DocumentScanPackageResult?>
    fun setPackageResult(packageResult: DocumentScanPackageResult)
}
