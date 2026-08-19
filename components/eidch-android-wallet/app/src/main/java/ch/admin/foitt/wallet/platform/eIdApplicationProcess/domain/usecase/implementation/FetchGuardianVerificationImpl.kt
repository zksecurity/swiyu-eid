package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.RequestClientAttestationError
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.RequestClientAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.GuardianVerificationError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.GuardianVerificationResponse
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.SIdRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.toGuardianVerificationError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.FetchGuardianVerification
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class FetchGuardianVerificationImpl @Inject constructor(
    private val sIdRepository: SIdRepository,
    private val requestClientAttestation: RequestClientAttestation,
) : FetchGuardianVerification {
    override suspend operator fun invoke(
        caseId: String,
    ): Result<GuardianVerificationResponse, GuardianVerificationError> = coroutineBinding {
        val clientAttestation = requestClientAttestation()
            .mapError(RequestClientAttestationError::toGuardianVerificationError).bind()

        sIdRepository.fetchSIdGuardianVerification(
            caseId = caseId,
            clientAttestation = clientAttestation,
        ).mapError(SIdRepositoryError::toGuardianVerificationError).bind()
    }
}
