package ch.admin.foitt.wallet.platform.utils

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import timber.log.Timber

@Composable
fun OnLifecycleEventHandler(
    onLifecycleEvent: (Lifecycle.Event) -> Unit,
) {
    val lifecycleOwner = LocalLifecycleOwner.current

    DisposableEffect(lifecycleOwner) {
        Timber.d("EventObserver: Setup OnLifecycleEventHandler")
        val observer = LifecycleEventObserver { _, event ->
            onLifecycleEvent(event)
        }
        lifecycleOwner.lifecycle.addObserver(observer)

        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            Timber.d("EventObserver: Disposed OnLifecycleEventHandler")
        }
    }
}
