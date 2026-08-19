package ch.admin.foitt.wallet.platform.appAttestation.domain.repository

import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationRepositoryError
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow

interface CurrentClientAttestationRepository {
    suspend fun save(
        clientAttestation: ClientAttestation,
    ): Result<Long, ClientAttestationRepositoryError>

    fun getFlow(
        keyPairAlias: String = ClientAttestation.KEY_ALIAS,
    ): Flow<ClientAttestation?>

    suspend fun get(
        keyPairAlias: String = ClientAttestation.KEY_ALIAS,
    ): Result<ClientAttestation?, ClientAttestationRepositoryError>

    suspend fun delete(
        keypairAlias: String = ClientAttestation.KEY_ALIAS
    ): Result<Unit, ClientAttestationRepositoryError>
}
