package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.time.Instant

@Entity
data class ClientAttestation(
    @PrimaryKey
    val id: String,
    val attestation: String,
    val createdAt: Long = Instant.now().epochSecond,
)
