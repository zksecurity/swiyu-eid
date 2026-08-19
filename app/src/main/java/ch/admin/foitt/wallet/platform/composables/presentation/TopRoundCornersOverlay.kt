package ch.admin.foitt.wallet.platform.composables.presentation

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import ch.admin.foitt.wallet.theme.WalletTheme

@Composable
fun TopRoundCornersOverlay(
    cornerRadius: Dp = 34.dp,
    fillColor: Color = WalletTheme.colorScheme.surface
) {
    Canvas(modifier = Modifier.fillMaxSize()) {
        val radius = cornerRadius.toPx()
        val width = size.width

        val path = Path().apply {
            moveTo(0f, radius)
            quadraticTo(0f, 0f, radius, 0f)

            lineTo(width - radius, 0f)
            quadraticTo(width, 0f, width, radius)

            lineTo(width, 0f)
            lineTo(0f, 0f)
            close()
        }

        drawPath(
            path = path,
            color = fillColor,
            style = Fill
        )
    }
}
