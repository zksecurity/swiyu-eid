package ch.admin.foitt.wallet.feature.settings.presentation.impressum

import android.content.Context
import ch.admin.foitt.wallet.R
import ch.admin.foitt.wallet.platform.navigation.NavigationManager
import ch.admin.foitt.wallet.platform.scaffold.domain.model.TopBarState
import ch.admin.foitt.wallet.platform.scaffold.domain.usecase.SetTopBarState
import ch.admin.foitt.wallet.platform.scaffold.presentation.ScreenViewModel
import ch.admin.foitt.wallet.platform.utils.openLink
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

@HiltViewModel
class ImpressumViewModel @Inject constructor(
    private val navManager: NavigationManager,
    @param:ApplicationContext private val appContext: Context,
    setTopBarState: SetTopBarState,
) : ScreenViewModel(setTopBarState) {
    override val topBarState = TopBarState.Details(navManager::popBackStack, R.string.tk_settings_imprint_title)

    fun onGithub() = appContext.openLink(R.string.tk_settings_imprint_appInformation_github_link_value)

    fun onMoreInformation() = appContext.openLink(R.string.tk_settings_imprint_publisher_link_value)

    fun onLegals() = appContext.openLink(R.string.tk_settings_imprint_legal_termsOfUse_link_value)
}
