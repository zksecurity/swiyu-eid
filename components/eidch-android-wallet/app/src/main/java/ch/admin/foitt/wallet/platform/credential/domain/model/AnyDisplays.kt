package ch.admin.foitt.wallet.platform.credential.domain.model

import ch.admin.foitt.wallet.platform.database.domain.model.Cluster

data class AnyDisplays(
    val issuerDisplays: List<AnyIssuerDisplay>,
    val credentialDisplays: List<AnyCredentialDisplay>,
    val clusters: List<Cluster>
)
