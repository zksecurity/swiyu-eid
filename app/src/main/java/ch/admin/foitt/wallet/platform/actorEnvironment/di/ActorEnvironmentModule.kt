package ch.admin.foitt.wallet.platform.actorEnvironment.di

import ch.admin.foitt.wallet.platform.actorEnvironment.domain.usecase.GetActorEnvironment
import ch.admin.foitt.wallet.platform.actorEnvironment.domain.usecase.implementation.GetActorEnvironmentImpl
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ActivityRetainedComponent

@Module
@InstallIn(ActivityRetainedComponent::class)
internal interface ActorEnvironmentModule {
    @Binds
    fun bindGetActorEnvironment(
        useCase: GetActorEnvironmentImpl
    ): GetActorEnvironment
}
