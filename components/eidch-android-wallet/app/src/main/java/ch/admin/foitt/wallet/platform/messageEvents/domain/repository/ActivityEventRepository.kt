package ch.admin.foitt.wallet.platform.messageEvents.domain.repository

import ch.admin.foitt.wallet.platform.messageEvents.domain.model.ActivityEvent
import kotlinx.coroutines.flow.StateFlow

interface ActivityEventRepository {
    val event: StateFlow<ActivityEvent>

    fun setEvent(event: ActivityEvent)
    fun resetEvent()
}
