package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import ch.admin.foitt.wallet.platform.database.domain.model.VerifiableCredentialWithDisplaysAndClusters
import kotlinx.coroutines.flow.Flow

@Dao
interface VerifiableCredentialWithDisplaysAndClustersDao {
    @Transaction
    @Query("SELECT * FROM VerifiableCredentialEntity WHERE credentialId = :id")
    fun getVerifiableCredentialWithDisplaysAndClustersFlowById(id: Long): Flow<VerifiableCredentialWithDisplaysAndClusters>

    @Transaction
    @Query("SELECT * FROM VerifiableCredentialEntity WHERE credentialId = :id")
    fun getNullableVerifiableCredentialWithDisplaysAndClustersFlowById(id: Long): Flow<VerifiableCredentialWithDisplaysAndClusters?>

    @Transaction
    @Query("SELECT * FROM VerifiableCredentialEntity ORDER BY createdAt DESC")
    fun getVerifiableCredentialsWithDisplaysAndClustersFlow(): Flow<List<VerifiableCredentialWithDisplaysAndClusters>>
}
