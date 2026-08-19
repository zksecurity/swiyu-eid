package ch.admin.foitt.wallet.feature.settings.presentation.composables

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import ch.admin.foitt.wallet.theme.Sizes
import ch.admin.foitt.wallet.theme.WalletTheme

@Composable
fun SettingsCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) = Card(
    modifier = Modifier
        .fillMaxWidth()
        .padding(horizontal = Sizes.s04),
    colors = CardDefaults.cardColors(containerColor = WalletTheme.colorScheme.listItemBackground)
) {
    Column(modifier = modifier) {
        content()
    }
}
