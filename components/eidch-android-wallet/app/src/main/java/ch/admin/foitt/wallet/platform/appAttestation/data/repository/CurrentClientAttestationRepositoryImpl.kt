package ch.admin.foitt.wallet.platform.appAttestation.data.repository

import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestation
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.ClientAttestationRepositoryError
import ch.admin.foitt.wallet.platform.appAttestation.domain.model.toClientAttestationRepositoryError
import ch.admin.foitt.wallet.platform.appAttestation.domain.repository.CurrentClientAttestationRepository
import ch.admin.foitt.wallet.platform.database.data.dao.ClientAttestationDao
import ch.admin.foitt.wallet.platform.database.data.dao.DaoProvider
import ch.admin.foitt.wallet.platform.di.IoDispatcher
import ch.admin.foitt.wallet.platform.utils.suspendUntilNonNull
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import ch.admin.foitt.wallet.platform.database.domain.model.ClientAttestation as DBClientAttestation

class CurrentClientAttestationRepositoryImpl @Inject constructor(
    @param:IoDispatcher private val ioDispatcher: CoroutineDispatcher,
    daoProvider: DaoProvider,
) : CurrentClientAttestationRepository {

    override suspend fun save(
        clientAttestation: ClientAttestation,
    ) = runSuspendCatching {
        withContext(ioDispatcher) {
            val dbClientAttestation = DBClientAttestation(
                id = clientAttestation.keyStoreAlias,
                attestation = clientAttestation.attestation.rawJwt
            )
            dao().insert(dbClientAttestation)
        }
    }.mapError { throwable ->
        throwable.toClientAttestationRepositoryError("Save client attestation failed")
    }

    override suspend fun get(
        keyPairAlias: String,
    ): Result<ClientAttestation?, ClientAttestationRepositoryError> = runSuspendCatching {
        dao().getById(keyPairAlias).let { dbClientAttestation ->
            dbClientAttestation?.let { dbClientAttestation ->
                ClientAttestation(
                    keyStoreAlias = dbClientAttestation.id,
                    attestation = Jwt(dbClientAttestation.attestation),
                )
            }
        }
    }.mapError { throwable ->
        throwable.toClientAttestationRepositoryError("Get client attestation failed")
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    override fun getFlow(
        keyPairAlias: String
    ): Flow<ClientAttestation?> = daoFlow.flatMapLatest { dao ->
        dao?.getFlowById(keyPairAlias)
            ?.map { dbClientAttestation ->
                dbClientAttestation?.let {
                    ClientAttestation(
                        keyStoreAlias = dbClientAttestation.id,
                        attestation = Jwt(dbClientAttestation.attestation),
                    )
                }
            }?.catch { throwable ->
                Timber.e(t = throwable, message = "Get client attestation failed")
                emit(null)
            } ?: emptyFlow()
    }

    override suspend fun delete(keypairAlias: String) = runSuspendCatching {
        withContext(ioDispatcher) {
            dao().deleteById(keypairAlias)
        }
    }.mapError { throwable ->
        throwable.toClientAttestationRepositoryError("Delete client attestation failed")
    }

    private suspend fun dao(): ClientAttestationDao = suspendUntilNonNull { daoFlow.value }
    private val daoFlow = daoProvider.clientAttestationDaoFlow
}
