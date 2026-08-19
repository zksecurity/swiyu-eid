package ch.admin.foitt.wallet.platform.database.domain.model

import androidx.room.Embedded
import androidx.room.Relation

data class ClusterWithDisplaysAndClaims(
    @Embedded
    val clusterWithDisplays: CredentialClusterWithDisplays,

    @Relation(
        entity = CredentialClaim::class,
        parentColumn = "id",
        entityColumn = "clusterId"
    )
    val claimsWithDisplays: List<CredentialClaimWithDisplays>,
)

data class CredentialClusterWithDisplays(
    @Embedded
    val cluster: CredentialClaimClusterEntity,
    @Relation(
        entity = CredentialClaimClusterDisplayEntity::class,
        parentColumn = "id",
        entityColumn = "clusterId",
    )
    val displays: List<CredentialClaimClusterDisplayEntity>,
)
