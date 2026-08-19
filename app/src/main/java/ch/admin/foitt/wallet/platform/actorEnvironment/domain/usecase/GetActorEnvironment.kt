package ch.admin.foitt.wallet.platform.actorEnvironment.domain.usecase

import ch.admin.foitt.wallet.platform.actorEnvironment.domain.model.ActorEnvironment

fun interface GetActorEnvironment {
    suspend operator fun invoke(credentialIssuer: String?): ActorEnvironment
}
