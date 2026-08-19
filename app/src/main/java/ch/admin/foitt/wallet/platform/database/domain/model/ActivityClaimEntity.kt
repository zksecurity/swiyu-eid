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
            onUpdate = ForeignKey.CASCADE,
        ),
        ForeignKey(
            entity = CredentialClaim::class,
            parentColumns = arrayOf("id"),
            childColumns = arrayOf("claimId"),
            onUpdate = ForeignKey.CASCADE,
        )
    ],
    indices = [
        Index("activityId"),
        Index("claimId"),
    ]
)
data class ActivityClaimEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val activityId: Long, // ForeignKey
    val claimId: Long, // ForeignKey
)
