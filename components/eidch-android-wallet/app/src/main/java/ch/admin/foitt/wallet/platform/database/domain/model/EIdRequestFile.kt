package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import java.time.Instant

@Entity(
    foreignKeys = [
        ForeignKey(
            entity = EIdRequestCase::class,
            parentColumns = arrayOf("id"),
            childColumns = arrayOf("eIdRequestCaseId"),
            onDelete = ForeignKey.CASCADE,
            onUpdate = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("eIdRequestCaseId")
    ]
)
data class EIdRequestFile(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val eIdRequestCaseId: String,
    val fileName: String,
    val mime: String,
    val category: EIdRequestFileCategory,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val data: ByteArray,
    val createdAt: Long = Instant.now().epochSecond,
)
