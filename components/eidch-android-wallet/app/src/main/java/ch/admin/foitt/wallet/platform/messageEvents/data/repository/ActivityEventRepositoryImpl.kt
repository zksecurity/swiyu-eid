package ch.admin.foitt.wallet.platform.messageEvents.data.repository

import ch.admin.foitt.wallet.platform.messageEvents.domain.model.ActivityEvent
import ch.admin.foitt.wallet.platform.messageEvents.domain.repository.ActivityEventRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

class ActivityEventRepositoryImpl @Inject constructor() : ActivityEventRepository {
    private val _event = MutableStateFlow(ActivityEvent.NONE)
    override val event = _event.asStateFlow()

    override fun setEvent(event: ActivityEvent) {
        _event.value = event
    }

    override fun resetEvent() {
        _event.value = ActivityEvent.NONE
    }
}
