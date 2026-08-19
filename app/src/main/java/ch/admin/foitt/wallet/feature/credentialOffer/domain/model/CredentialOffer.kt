package ch.admin.foitt.wallet.feature.credentialOffer.domain.model

import ch.admin.foitt.wallet.platform.credential.domain.model.CredentialDisplayData
import ch.admin.foitt.wallet.platform.ssi.domain.model.CredentialClaimCluster

data class CredentialOffer(
    val credential: CredentialDisplayData,
    val claims: List<CredentialClaimCluster>,
)
