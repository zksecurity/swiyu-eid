package ch.admin.foitt.wallet.platform.trustRegistry.domain.model

import ch.admin.foitt.wallet.platform.actorEnvironment.domain.model.ActorEnvironment

data class TrustCheckResult(
    val actorEnvironment: ActorEnvironment,
    val actorTrustStatement: TrustStatement?,
    val vcSchemaTrustStatus: VcSchemaTrustStatus,
)
