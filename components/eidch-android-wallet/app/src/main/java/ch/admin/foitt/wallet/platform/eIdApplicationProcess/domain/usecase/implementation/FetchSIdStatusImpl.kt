package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.RequestClientAttestationError
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.RequestClientAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.SIdRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.StateRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.StateResponse
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.toStateRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.FetchSIdStatus
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class FetchSIdStatusImpl @Inject constructor(
    private val sIdRepository: SIdRepository,
    private val requestClientAttestation: RequestClientAttestation,
) : FetchSIdStatus {
    override suspend fun invoke(caseId: String): Result<StateResponse, StateRequestError> = coroutineBinding {
        val clientAttestation = requestClientAttestation()
            .mapError(RequestClientAttestationError::toStateRequestError).bind()

        sIdRepository.fetchSIdState(
            caseId = caseId,
            clientAttestation = clientAttestation,
        ).mapError(SIdRepositoryError::toStateRequestError).bind()
    }
}
