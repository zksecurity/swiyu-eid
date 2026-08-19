package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import ch.admin.foitt.wallet.platform.database.domain.model.CredentialClaimClusterDisplayEntity

@Dao
interface CredentialClaimClusterDisplayEntityDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(clusterDisplay: CredentialClaimClusterDisplayEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertAll(clusterDisplays: List<CredentialClaimClusterDisplayEntity>)

    @Query("SELECT * FROM credentialclaimclusterdisplayentity WHERE id = :id")
    fun getById(id: Long): CredentialClaimClusterDisplayEntity?
}
