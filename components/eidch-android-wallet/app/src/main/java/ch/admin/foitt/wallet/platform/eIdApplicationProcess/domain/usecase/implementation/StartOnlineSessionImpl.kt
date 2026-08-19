package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationPoP
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.GenerateProofOfPossessionError
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.RequestClientAttestationError
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.GenerateProofOfPossession
import ch.admin.foitt.wallet.platform.appAttestation.domain.usecase.RequestClientAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.SIdRepositoryError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.toStartOnlineSessionError
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.StartOnlineSession
import ch.admin.foitt.wallet.platform.environmentSetup.domain.repository.EnvironmentSetupRepository
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import kotlinx.serialization.json.JsonObject
import javax.inject.Inject

class StartOnlineSessionImpl @Inject constructor(
    private val sIdRepository: SIdRepository,
    private val requestClientAttestation: RequestClientAttestation,
    private val generateProofOfPossession: GenerateProofOfPossession,
    private val environmentSetupRepository: EnvironmentSetupRepository,
) : StartOnlineSession {
    override suspend operator fun invoke(caseId: String) = coroutineBinding {
        val clientAttestation = requestClientAttestation()
            .mapError(RequestClientAttestationError::toStartOnlineSessionError).bind()

        val challengeResponse = sIdRepository.fetchChallenge()
            .mapError(SIdRepositoryError::toStartOnlineSessionError).bind()

        val clientAttestationProofOfPossession: ClientAttestationPoP = generateProofOfPossession(
            clientAttestation = clientAttestation,
            challenge = challengeResponse.challenge,
            audience = environmentSetupRepository.sidBackendUrl,
            requestBody = JsonObject(emptyMap()),

        ).mapError(GenerateProofOfPossessionError::toStartOnlineSessionError).bind()

        sIdRepository.startOnlineSession(
            caseId = caseId,
            clientAttestation = clientAttestation,
            clientAttestationPoP = clientAttestationProofOfPossession,
        ).mapError(SIdRepositoryError::toStartOnlineSessionError).bind()
    }
}
