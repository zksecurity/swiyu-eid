package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.avwrapper.DocumentScanPackageResult
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.di.EidApplicationProcessEntryPoint
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.SetDocumentScanResult
import ch.admin.foitt.wallet.platform.navigation.DestinationScopedComponentManager
import ch.admin.foitt.wallet.platform.navigation.domain.model.ComponentScope
import javax.inject.Inject

class SetDocumentScanResultImpl @Inject constructor(
    private val destinationScopedComponentManager: DestinationScopedComponentManager,
) : SetDocumentScanResult {
    override operator fun invoke(documentScanResult: DocumentScanPackageResult) {
        val repository = destinationScopedComponentManager.getEntryPoint(
            entryPointClass = EidApplicationProcessEntryPoint::class.java,
            componentScope = ComponentScope.EidDocumentScan,
        ).eidDocumentScanRepository()

        return repository.setPackageResult(documentScanResult)
    }
}
