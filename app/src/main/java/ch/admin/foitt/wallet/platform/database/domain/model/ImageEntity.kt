package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
Concept: works as an image cache to reduce duplications of images in the db
Images are not deleted (by Id f. e.) from this table, but rather references are removed
Triggers are not well supported by room, so manual cleanup of unreferenced images is needed
-> Use dao function "deleteImagesWithoutChildren" for that
 */
@Entity(
    indices = [
        Index(value = ["hash"], unique = true)
    ]
)
data class ImageEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val hash: String,
    val image: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ImageEntity

        if (id != other.id) return false
        if (hash != other.hash) return false
        if (!image.contentEquals(other.image)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + hash.hashCode()
        result = 31 * result + image.contentHashCode()
        return result
    }
}
