package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.avwrapper.DocumentScanPackageResult

fun interface SetDocumentScanResult {
    operator fun invoke(documentScanResult: DocumentScanPackageResult)
}
