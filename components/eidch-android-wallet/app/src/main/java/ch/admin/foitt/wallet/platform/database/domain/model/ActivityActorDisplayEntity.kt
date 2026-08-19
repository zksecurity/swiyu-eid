package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = CredentialActivityEntity::class,
            parentColumns = arrayOf("id"),
            childColumns = arrayOf("activityId"),
            onDelete = ForeignKey.CASCADE,
            onUpdate = ForeignKey.CASCADE
        ),
        ForeignKey(
            entity = ImageEntity::class,
            parentColumns = arrayOf("hash"),
            childColumns = arrayOf("imageHash"),
            onUpdate = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("activityId"),
        Index("imageHash"),
    ]
)
data class ActivityActorDisplayEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val activityId: Long, // ForeignKey
    val imageHash: String? = null, // ForeignKey
    val name: String,
    override val locale: String,
) : LocalizedDisplay
