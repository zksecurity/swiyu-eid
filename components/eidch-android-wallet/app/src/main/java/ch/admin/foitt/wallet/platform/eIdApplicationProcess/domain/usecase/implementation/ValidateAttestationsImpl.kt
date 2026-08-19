package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.KeyAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.repository.SIdRepository
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase.ValidateAttestations
import javax.inject.Inject

class ValidateAttestationsImpl @Inject constructor(
    private val sIdRepository: SIdRepository,
) : ValidateAttestations {
    override suspend fun invoke(
        clientAttestation: ClientAttestation,
        keyAttestation: KeyAttestation
    ) = sIdRepository.validateAttestations(
        clientAttestation = clientAttestation,
        keyAttestation = keyAttestation
    )
}
