package ch.admin.foitt.wallet.feature.onboarding.presentation.composables

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import ch.admin.foitt.wallet.R
import ch.admin.foitt.wallet.platform.composables.presentation.LoadingIndicator
import ch.admin.foitt.wallet.platform.composables.presentation.layout.ScrollableColumnWithPicture
import ch.admin.foitt.wallet.platform.composables.presentation.layout.WalletLayouts
import ch.admin.foitt.wallet.platform.preview.WalletAllScreenPreview
import ch.admin.foitt.wallet.theme.Sizes
import ch.admin.foitt.wallet.theme.WalletTexts
import ch.admin.foitt.wallet.theme.WalletTheme

@Composable
fun OnboardingLoadingScreenContent() = WalletLayouts.ScrollableColumnWithPicture(
    modifier = Modifier
        .background(WalletTheme.colorScheme.background),
    stickyStartContent = { LoadingIndicator() },
    stickyBottomContent = null,
) {
    Spacer(modifier = Modifier.height(Sizes.s06))
    WalletTexts.TitleScreen(
        text = stringResource(id = R.string.tk_onboarding_setup_primary),
    )
    Spacer(modifier = Modifier.height(Sizes.s06))
    WalletTexts.BodyLarge(
        text = stringResource(id = R.string.tk_onboarding_setup_secondary),
        modifier = Modifier
            .fillMaxWidth()
    )
}

@WalletAllScreenPreview
@Composable
private fun OnboardingLoadingScreenContentPreview() {
    WalletTheme {
        OnboardingLoadingScreenContent()
    }
}
