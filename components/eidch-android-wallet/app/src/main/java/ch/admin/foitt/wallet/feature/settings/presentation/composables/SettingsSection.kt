package ch.admin.foitt.wallet.feature.settings.presentation.composables

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import ch.admin.foitt.wallet.platform.preview.WalletComponentPreview
import ch.admin.foitt.wallet.theme.Sizes
import ch.admin.foitt.wallet.theme.WalletListItems
import ch.admin.foitt.wallet.theme.WalletTheme

@Composable
fun SettingsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) = Column(modifier = Modifier.fillMaxWidth()) {
    WalletListItems.SectionHeadlineSettingsItem(title = title)
    Spacer(modifier = Modifier.height(Sizes.s02))
    SettingsCard(
        content = content
    )
}

@WalletComponentPreview
@Composable
private fun SettingsSectionPreview() {
    WalletTheme {
        SettingsSection(
            title = "Section title",
            content = {
                WalletListItems.TextSettingsItem(title = "Item 1")
                WalletListItems.TextSettingsItem(title = "Item 2")
                WalletListItems.TextSettingsItem(title = "Item 3")
            }
        )
    }
}
