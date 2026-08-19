package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityWithActorDisplays
import kotlinx.coroutines.flow.Flow

@Dao
interface ActivityWithDisplaysDao {
    @Transaction
    @Query("SELECT * FROM credentialactivityentity WHERE credentialId = :credentialId ORDER BY createdAt DESC")
    fun getActivitiesByCredentialIdFlow(credentialId: Long): Flow<List<ActivityWithActorDisplays>>
}
