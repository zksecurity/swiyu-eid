package ch.admin.foitt.wallet.platform.database.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy.Companion.IGNORE
import androidx.room.Query
import ch.admin.foitt.wallet.platform.database.domain.model.ImageEntity

@Dao
interface ImageEntityDao {
    @Insert(onConflict = IGNORE)
    fun insert(imageEntity: ImageEntity): Long

    @Query("SELECT * FROM imageentity WHERE hash = :hash")
    fun getByHash(hash: String): ImageEntity

    @Query(
        "DELETE FROM imageentity WHERE hash NOT IN (" +
            "SELECT imageHash from activityactordisplayentity INTERSECT SELECT hash FROM imageentity" +
            ")"
    )
    fun deleteImagesWithoutChildren()
}
