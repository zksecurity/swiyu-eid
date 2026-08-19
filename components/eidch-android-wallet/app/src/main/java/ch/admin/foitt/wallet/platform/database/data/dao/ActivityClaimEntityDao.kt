package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityClaimEntity

@Dao
interface ActivityClaimEntityDao {
    @Insert
    fun insert(activityClaimEntity: ActivityClaimEntity): Long

    @Query("SELECT * FROM activityclaimentity WHERE id = :claimId")
    fun getById(claimId: Long): ActivityClaimEntity
}
