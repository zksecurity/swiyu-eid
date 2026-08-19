package ch.admin.foitt.wallet.platform.oca.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.oca.domain.model.CaptureBase
import ch.admin.foitt.wallet.platform.oca.domain.model.GetRootCaptureBaseError
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaCaptureBaseValidationError
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaError
import ch.admin.foitt.wallet.platform.oca.domain.model.getReferenceValue
import ch.admin.foitt.wallet.platform.oca.domain.model.toOcaCaptureBaseValidationError
import ch.admin.foitt.wallet.platform.oca.domain.usecase.GetRootCaptureBase
import ch.admin.foitt.wallet.platform.oca.domain.usecase.OcaCaptureBaseValidator
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class OcaCaptureBaseValidatorImpl @Inject constructor(
    private val getRootCaptureBase: GetRootCaptureBase,
) : OcaCaptureBaseValidator {

    override suspend fun invoke(
        captureBases: List<CaptureBase>
    ): Result<List<CaptureBase>, OcaCaptureBaseValidationError> = coroutineBinding {
        val rootCaptureBase = getRootCaptureBase(captureBases)
            .mapError(GetRootCaptureBaseError::toOcaCaptureBaseValidationError)
            .bind()

        if (doCaptureBasesContainInvalidReferences(captureBases)) {
            return@coroutineBinding Err(OcaError.InvalidCaptureBaseReferenceAttribute).bind<List<CaptureBase>>()
        }

        if (doCaptureBasesContainReferenceCycles(captureBases, rootCaptureBase, listOf(rootCaptureBase.digest))) {
            return@coroutineBinding Err(OcaError.CaptureBaseCycleError).bind<List<CaptureBase>>()
        }

        captureBases
    }

    private fun doCaptureBasesContainInvalidReferences(captureBases: List<CaptureBase>): Boolean {
        val allAttributes = captureBases.flatMap { it.attributes.values }
        val referenceAttributes = allAttributes.mapNotNull { it.getReferenceValue() }
        val captureBaseDigests = captureBases.map { it.digest }

        return referenceAttributes.any { !captureBaseDigests.contains(it) }
    }

    @Suppress("ReturnCount")
    private fun doCaptureBasesContainReferenceCycles(
        captureBases: List<CaptureBase>,
        captureBase: CaptureBase,
        referencedCaptureBaseDigests: List<String>
    ): Boolean {
        val nextCaptureBaseDigests = captureBase.attributes.values.mapNotNull { it.getReferenceValue() }
        val nextCaptureBases = captureBases.filter { it.digest in nextCaptureBaseDigests }
        nextCaptureBases.forEach { nextCaptureBase ->
            if (!referencedCaptureBaseDigests.contains(nextCaptureBase.digest)) {
                val containsCycle = doCaptureBasesContainReferenceCycles(
                    captureBases = captureBases,
                    captureBase = nextCaptureBase,
                    referencedCaptureBaseDigests = referencedCaptureBaseDigests + listOf(nextCaptureBase.digest)
                )
                if (containsCycle) return true
            } else {
                return true
            }
        }

        return false
    }
}
