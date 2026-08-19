package ch.admin.foitt.wallet.feature.eIdApplicationProcess.presentation

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import ch.admin.foitt.wallet.R
import ch.admin.foitt.wallet.platform.composables.presentation.spaceBarKeyClickable
import ch.admin.foitt.wallet.platform.preview.WalletComponentPreview
import ch.admin.foitt.wallet.theme.Sizes
import ch.admin.foitt.wallet.theme.WalletTexts
import ch.admin.foitt.wallet.theme.WalletTheme

@Composable
fun EIdDocumentItem(
    onClick: () -> Unit,
    @DrawableRes imageResource: Int,
    @StringRes stringResource: Int,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .clickable(onClick = onClick)
            .spaceBarKeyClickable(onClick)
            .padding(start = Sizes.s04, top = Sizes.s03, end = Sizes.s06, bottom = Sizes.s03),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(
            painter = painterResource(id = imageResource),
            contentDescription = null,
            modifier = Modifier
                .width(Sizes.s20)
                .height(Sizes.s20)
        )
        Spacer(modifier = Modifier.width(Sizes.s04))
        Column(
            modifier = Modifier.weight(1f)
        ) {
            WalletTexts.BodyLarge(
                text = stringResource(id = stringResource),
                color = WalletTheme.colorScheme.onSurface,
            )
        }
        Spacer(modifier = Modifier.width(Sizes.s04))
        Icon(
            modifier = Modifier.size(Sizes.s06),
            painter = painterResource(id = R.drawable.wallet_ic_chevron),
            contentDescription = null,
            tint = WalletTheme.colorScheme.onSurfaceVariant,
        )
    }
    HorizontalDivider(
        modifier = Modifier.padding(start = Sizes.s04)
    )
}

@WalletComponentPreview
@Composable
private fun EIdDocumentItemPreview() {
    WalletTheme {
        EIdDocumentItem(
            stringResource = R.string.tk_eidRequest_documentSelection_passport,
            imageResource = R.drawable.wallet_passport,
            onClick = {},
        )
    }
}
