package ch.admin.foitt.wallet.platform.scaffold.extension

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.viewModelScope
import ch.admin.foitt.wallet.platform.scaffold.presentation.ScreenViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

private val ScreenViewModel.cameraPermission by lazy { Manifest.permission.CAMERA }

internal fun ScreenViewModel.hasCameraPermission(appContext: Context): Boolean =
    ActivityCompat.checkSelfPermission(appContext, cameraPermission) == PackageManager.PERMISSION_GRANTED

internal fun ScreenViewModel.shouldShowRationale(activity: FragmentActivity): Boolean =
    ActivityCompat.shouldShowRequestPermissionRationale(activity, cameraPermission)

/**
 * Creates a [RefreshableStateFlow] that wraps a [StateFlow] with automatic refreshing capabilities.
 *
 * This function establishes a state flow that can be manually refreshed.
 *
 * @param T The type of data held in the state flow
 * @param initialData The initial value to be emitted by the state flow before any refresh occurs
 * @param timeout The timeout in milliseconds for how long to keep the flow active when no collectors are present
 * @param flowBuilder A suspend function that returns a [Flow] of type [T] to be used for refreshing data
 * @return A [RefreshableStateFlow] containing the state flow and refresh function
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun <T> ScreenViewModel.refreshableStateFlow(
    initialData: T,
    timeout: Long = 5000,
    flowBuilder: suspend () -> Flow<T>,
): RefreshableStateFlow<T> {
    val refreshTrigger = MutableSharedFlow<Unit>(replay = 1)

    val stateFlow: StateFlow<T> = refreshTrigger
        .flatMapLatest {
            flowBuilder()
        }.stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(timeout),
            initialData,
        )

    val refreshFunction: suspend () -> Unit = {
        viewModelScope.launch {
            refreshTrigger.emit(Unit)
        }
    }

    return RefreshableStateFlow(
        stateFlow = stateFlow,
        refreshData = refreshFunction
    )
}

/**
 * A data class that wraps a [StateFlow] with refresh capabilities.
 *
 * This class provides both the current state as a [StateFlow] and a function to manually trigger
 * data refreshes.
 *
 * @param T The type of data held in the state flow
 * @param stateFlow The underlying [StateFlow] that emits the current state
 * @param refreshData A suspend function that triggers a data refresh emitted in [stateFlow]
 *
 * @see RefreshableStateFlow
 */
data class RefreshableStateFlow<T>(
    val stateFlow: StateFlow<T>,
    val refreshData: suspend () -> Unit
)
