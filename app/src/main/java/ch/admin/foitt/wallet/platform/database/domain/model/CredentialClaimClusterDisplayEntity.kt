package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = CredentialClaimClusterEntity::class,
            parentColumns = arrayOf("id"),
            childColumns = arrayOf("clusterId"),
            onDelete = ForeignKey.CASCADE,
            onUpdate = ForeignKey.CASCADE,
        )
    ],
    indices = [
        Index("clusterId"),
    ]
)
data class CredentialClaimClusterDisplayEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val clusterId: Long, // Foreign key
    val name: String, // label of the cluster (get from label overlay)
    override val locale: String,
) : LocalizedDisplay

fun ClusterDisplay.toCredentialClaimClusterDisplayEntity(clusterId: Long) = CredentialClaimClusterDisplayEntity(
    clusterId = clusterId,
    name = this.name,
    locale = this.locale,
)
