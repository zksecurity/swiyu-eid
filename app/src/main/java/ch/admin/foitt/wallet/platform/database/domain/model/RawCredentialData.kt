package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = Credential::class,
            parentColumns = arrayOf("id"),
            childColumns = arrayOf("credentialId"),
            onDelete = ForeignKey.CASCADE,
            onUpdate = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("credentialId", unique = true)
    ]
)
data class RawCredentialData(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val credentialId: Long, // Foreign key
    val rawOcaBundle: ByteArray? = null,
    val rawOIDMetadata: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RawCredentialData

        if (id != other.id) return false
        if (credentialId != other.credentialId) return false
        if (!rawOcaBundle.contentEquals(other.rawOcaBundle)) return false
        if (!rawOIDMetadata.contentEquals(other.rawOIDMetadata)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + credentialId.hashCode()
        result = 31 * result + (rawOcaBundle?.contentHashCode() ?: 0)
        result = 31 * result + (rawOIDMetadata?.contentHashCode() ?: 0)
        return result
    }
}
