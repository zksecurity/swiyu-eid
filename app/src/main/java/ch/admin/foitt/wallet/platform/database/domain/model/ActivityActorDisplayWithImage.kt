package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Embedded
import androidx.room.Relation

data class ActivityActorDisplayWithImage(
    @Embedded val actorDisplay: ActivityActorDisplayEntity,
    @Relation(
        parentColumn = "imageHash",
        entityColumn = "hash",
    )
    val image: ImageEntity?,
)
