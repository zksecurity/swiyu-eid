package ch.admin.foitt.wallet.platform.credentialCluster.domain.usercase

import androidx.annotation.CheckResult
import ch.admin.foitt.wallet.platform.database.domain.model.ClusterWithDisplaysAndClaims
import ch.admin.foitt.wallet.platform.ssi.domain.model.CredentialClaimCluster

fun interface MapToCredentialClaimCluster {
    @CheckResult
    suspend operator fun invoke(clustersWithDisplaysAndClaims: List<ClusterWithDisplaysAndClaims>): List<CredentialClaimCluster>
}
