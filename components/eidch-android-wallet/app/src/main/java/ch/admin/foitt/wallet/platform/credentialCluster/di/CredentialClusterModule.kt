package ch.admin.foitt.wallet.platform.credentialCluster.di

import ch.admin.foitt.wallet.platform.credentialCluster.domain.usercase.MapToCredentialClaimCluster
import ch.admin.foitt.wallet.platform.credentialCluster.domain.usercase.implementation.MapToCredentialClaimClusterImpl
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ActivityRetainedComponent

@Module
@InstallIn(ActivityRetainedComponent::class)
interface CredentialClusterModule {

    @Binds
    fun bindMapToCredentialClaimCluster(
        useCase: MapToCredentialClaimClusterImpl
    ): MapToCredentialClaimCluster
}
