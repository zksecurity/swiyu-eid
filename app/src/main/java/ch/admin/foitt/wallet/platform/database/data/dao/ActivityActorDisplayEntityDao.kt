package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import ch.admin.foitt.wallet.platform.database.domain.model.ActivityActorDisplayEntity

@Dao
interface ActivityActorDisplayEntityDao {
    @Insert
    fun insert(activityActorDisplayEntity: ActivityActorDisplayEntity): Long

    @Query("SELECT * FROM activityactordisplayentity WHERE id = :actorDisplayId")
    fun getById(actorDisplayId: Long): ActivityActorDisplayEntity
}
