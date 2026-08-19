package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.avwrapper.DocumentScanPackageResult
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.di.EidApplicationProcessEntryPoint
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.GetDocumentScanResult
import ch.admin.foitt.wallet.platform.navigation.DestinationScopedComponentManager
import ch.admin.foitt.wallet.platform.navigation.domain.model.ComponentScope
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

class GetDocumentScanResultImpl @Inject constructor(
    private val destinationScopedComponentManager: DestinationScopedComponentManager,
) : GetDocumentScanResult {
    override operator fun invoke(): StateFlow<DocumentScanPackageResult?> {
        val repository = destinationScopedComponentManager.getEntryPoint(
            entryPointClass = EidApplicationProcessEntryPoint::class.java,
            componentScope = ComponentScope.EidDocumentScan,
        ).eidDocumentScanRepository()

        return repository.packageResult
    }
}
