package ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase.implementation

import ch.admin.foitt.wallet.feature.eIdRequestVerification.domain.usecase.FetchSIdCase
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationPoP
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.GenerateProofOfPossessionError
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.RequestClientAttestationError
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.GenerateProofOfPossession
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.RequestClientAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.ApplyRequest
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.ApplyRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.CaseResponse
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.SIdRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.toApplyRequestError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.environmentSetup.domain.repository.EnvironmentSetupRepository
import ch.admin.foitt.wallet.platform.utils.JsonParsingError
import ch.admin.foitt.wallet.platform.utils.SafeJson
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class FetchSIdCaseImpl @Inject constructor(
    private val sIdRepository: SIdRepository,
    private val requestClientAttestation: RequestClientAttestation,
    private val generateProofOfPossession: GenerateProofOfPossession,
    private val environmentSetupRepository: EnvironmentSetupRepository,
    private val safeJson: SafeJson,
) : FetchSIdCase {
    override suspend fun invoke(applyRequest: ApplyRequest): Result<CaseResponse, ApplyRequestError> = coroutineBinding {
        val clientAttestation: ClientAttestation = requestClientAttestation()
            .mapError(RequestClientAttestationError::toApplyRequestError).bind()
        val challengeResponse = sIdRepository.fetchChallenge()
            .mapError(SIdRepositoryError::toApplyRequestError).bind()
        val requestBody = safeJson.safeEncodeObjectToJsonElement(applyRequest)
            .mapError(JsonParsingError::toApplyRequestError).bind()

        val clientAttestationProofOfPossession: ClientAttestationPoP = generateProofOfPossession(
            clientAttestation = clientAttestation,
            challenge = challengeResponse.challenge,
            audience = environmentSetupRepository.sidBackendUrl,
            requestBody = requestBody,
        ).mapError(GenerateProofOfPossessionError::toApplyRequestError).bind()

        sIdRepository.requestSIdCase(
            clientAttestation = clientAttestation,
            clientAttestationPoP = clientAttestationProofOfPossession,
            applyRequest = applyRequest,
        ).mapError(SIdRepositoryError::toApplyRequestError).bind()
    }
}
