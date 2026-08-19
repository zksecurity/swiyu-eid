package ch.admin.foitt.wallet.platform.activityList.presentation.composables

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.isTraversalGroup
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.traversalIndex
import androidx.compose.ui.text.style.TextAlign
import ch.admin.foitt.wallet.R
import ch.admin.foitt.wallet.platform.composables.Buttons
import ch.admin.foitt.wallet.theme.Sizes
import ch.admin.foitt.wallet.theme.WalletButtonColors
import ch.admin.foitt.wallet.theme.WalletTexts
import ch.admin.foitt.wallet.theme.WalletTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityDeleteConfirmationBottomSheet(
    sheetState: SheetState,
    onCancel: () -> Unit,
    onDelete: () -> Unit,
) {
    ModalBottomSheet(
        modifier = Modifier.semantics {
            isTraversalGroup = true
            traversalIndex = -5f
        },
        sheetState = sheetState,
        containerColor = WalletTheme.colorScheme.background,
        onDismissRequest = onCancel,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = Sizes.s06, vertical = Sizes.s02)
        ) {
            WalletTexts.HeadlineSmall(
                modifier = Modifier
                    .fillMaxWidth()
                    .semantics { heading() },
                text = stringResource(R.string.tk_activity_activityDetail_deleteConfirmation_title),
                color = WalletTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(Sizes.s06))
            WalletTexts.BodyLarge(
                modifier = Modifier.fillMaxWidth(),
                text = stringResource(R.string.tk_activity_activityDetail_deleteConfirmation_body),
                color = WalletTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(Sizes.s06))
            Buttons.FilledPrimary(
                modifier = Modifier.fillMaxWidth(),
                text = stringResource(R.string.tk_activity_activityDetail_deleteConfirmation_cancel_button),
                onClick = onCancel,
            )
            Spacer(modifier = Modifier.height(Sizes.s04))
            Buttons.Text(
                modifier = Modifier.fillMaxWidth(),
                text = stringResource(R.string.tk_activity_activityDetail_deleteConfirmation_delete_button),
                colors = WalletButtonColors.textError(),
                onClick = onDelete,
            )
        }
    }
}
