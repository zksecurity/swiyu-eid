package ch.admin.foitt.wallet.platform.oca.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.oca.domain.model.CaptureBase
import ch.admin.foitt.wallet.platform.oca.domain.model.GetRootCaptureBaseError
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaError
import ch.admin.foitt.wallet.platform.oca.domain.model.getReferenceValue
import ch.admin.foitt.wallet.platform.oca.domain.usecase.GetRootCaptureBase
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import javax.inject.Inject

class GetRootCaptureBaseImpl @Inject constructor() : GetRootCaptureBase {
    override suspend fun invoke(captureBases: List<CaptureBase>): Result<CaptureBase, GetRootCaptureBaseError> = coroutineBinding {
        val rootCaptureBases = findRootCaptureBases(captureBases)
        if (rootCaptureBases.size != 1) {
            return@coroutineBinding Err(OcaError.InvalidRootCaptureBase).bind<CaptureBase>()
        }

        rootCaptureBases.first()
    }

    private fun findRootCaptureBases(captureBases: List<CaptureBase>): List<CaptureBase> {
        // A Capture Base is called the root Capture Base, if it isn't referenced by any other Capture Base.
        val rootCaptureBases = captureBases.filter { captureBase ->
            val captureBasesAttributes = captureBases.flatMap { it.attributes.values }
            captureBasesAttributes
                .mapNotNull { it.getReferenceValue() }
                .none { captureBaseReference ->
                    captureBaseReference == captureBase.digest
                }
        }
        return rootCaptureBases
    }
}
