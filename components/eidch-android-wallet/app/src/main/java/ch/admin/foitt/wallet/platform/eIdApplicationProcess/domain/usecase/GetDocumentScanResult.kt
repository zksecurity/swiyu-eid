package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.avwrapper.DocumentScanPackageResult
import kotlinx.coroutines.flow.StateFlow

fun interface GetDocumentScanResult {
    operator fun invoke(): StateFlow<DocumentScanPackageResult?>
}
