package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.usecase

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.KeyAttestation
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.ValidateAttestationsError
import com.github.michaelbull.result.Result

fun interface ValidateAttestations {
    suspend operator fun invoke(
        clientAttestation: ClientAttestation,
        keyAttestation: KeyAttestation,
    ): Result<Unit, ValidateAttestationsError>
}
