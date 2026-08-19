package ch.admin.foitt.wallet.platform.appAttestation.domain.usecase

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.RequestClientAttestationError
import com.github.michaelbull.result.Result

interface RequestClientAttestation {
    suspend operator fun invoke(
        keyAlias: String = ClientAttestation.KEY_ALIAS,
        signingAlgorithm: SigningAlgorithm = ClientAttestation.SIGNING_ALGORITHM,
    ): Result<ClientAttestation, RequestClientAttestationError>
}
