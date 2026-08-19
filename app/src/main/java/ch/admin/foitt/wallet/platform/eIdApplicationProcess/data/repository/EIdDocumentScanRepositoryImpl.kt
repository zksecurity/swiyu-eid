package ch.admin.foitt.wallet.platform.eIdApplicationProcess.data.repository

import ch.admin.foitt.avwrapper.DocumentScanPackageResult
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.EIdDocumentScanRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

class EIdDocumentScanRepositoryImpl @Inject constructor() : EIdDocumentScanRepository {
    private val _packageResult = MutableStateFlow<DocumentScanPackageResult?>(null)
    override val packageResult = _packageResult.asStateFlow()
    override fun setPackageResult(packageResult: DocumentScanPackageResult) {
        _packageResult.value = packageResult
    }
}
