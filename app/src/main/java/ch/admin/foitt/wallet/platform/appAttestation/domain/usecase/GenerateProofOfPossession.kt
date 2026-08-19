package ch.admin.foitt.wallet.platform.appAttestation.domain.usecase

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationPoP
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.GenerateProofOfPossessionError
import com.github.michaelbull.result.Result
import kotlinx.serialization.json.JsonElement

fun interface GenerateProofOfPossession {
    suspend operator fun invoke(
        clientAttestation: ClientAttestation,
        challenge: String,
        audience: String,
        requestBody: JsonElement,
    ): Result<ClientAttestationPoP, GenerateProofOfPossessionError>
}
