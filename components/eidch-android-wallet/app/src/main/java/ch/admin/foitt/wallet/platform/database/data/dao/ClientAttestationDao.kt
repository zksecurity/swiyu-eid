package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import ch.admin.foitt.wallet.platform.database.domain.model.ClientAttestation
import kotlinx.coroutines.flow.Flow

@Dao
interface ClientAttestationDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(attestation: ClientAttestation): Long

    @Query("SELECT * FROM ClientAttestation WHERE id = :keyAlias")
    fun getFlowById(keyAlias: String): Flow<ClientAttestation?>

    @Query("SELECT * FROM ClientAttestation WHERE id = :keyAlias")
    suspend fun getById(keyAlias: String): ClientAttestation?

    @Query("DELETE FROM ClientAttestation WHERE id = :keyAlias")
    suspend fun deleteById(keyAlias: String)
}
