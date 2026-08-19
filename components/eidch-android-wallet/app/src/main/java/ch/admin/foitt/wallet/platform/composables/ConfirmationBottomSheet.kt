package ch.admin.foitt.wallet.platform.composables

import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.isTraversalGroup
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.traversalIndex
import ch.admin.foitt.wallet.R
import ch.admin.foitt.wallet.platform.composables.presentation.spaceBarKeyClickable
import ch.admin.foitt.wallet.theme.Sizes
import ch.admin.foitt.wallet.theme.WalletTexts
import ch.admin.foitt.wallet.theme.WalletTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfirmationBottomSheet(
    sheetState: SheetState,
    @StringRes title: Int,
    @StringRes body: Int,
    @StringRes acceptButtonText: Int,
    @StringRes declineButtonText: Int,
    onAccept: () -> Unit,
    onDecline: () -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(
        modifier = Modifier.semantics {
            isTraversalGroup = true
            traversalIndex = -5f
        },
        sheetState = sheetState,
        containerColor = WalletTheme.colorScheme.background,
        onDismissRequest = onDismiss,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = Sizes.s06, vertical = Sizes.s02)
        ) {
            WalletTexts.BodyLargeEmphasized(
                text = stringResource(title),
                color = WalletTheme.colorScheme.onSurface,
            )
            Spacer(modifier = Modifier.height(Sizes.s02))
            WalletTexts.BodyLarge(
                text = stringResource(body),
                color = WalletTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(Sizes.s04))
            Button(
                title = stringResource(acceptButtonText),
                icon = R.drawable.wallet_ic_send,
                contentColor = WalletTheme.colorScheme.onSurface,
                onClick = onAccept,
            )
            Spacer(modifier = Modifier.height(Sizes.s04))
            Button(
                title = stringResource(declineButtonText),
                icon = R.drawable.wallet_ic_trashcan_big,
                contentColor = WalletTheme.colorScheme.onLightError,
                onClick = onDecline,
            )
        }
    }
}

@Composable
private fun Button(
    title: String,
    icon: Int,
    contentColor: Color,
    onClick: () -> Unit,
) = ListItem(
    modifier = Modifier
        .clickable(onClick = onClick)
        .spaceBarKeyClickable(onClick),
    headlineContent = {
        WalletTexts.BodyLargeEmphasized(
            text = title,
            color = contentColor,
        )
    },
    leadingContent = {
        Icon(
            painter = painterResource(id = icon),
            contentDescription = null,
            tint = contentColor,
        )
    },
)
