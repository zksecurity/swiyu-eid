package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model

import kotlinx.serialization.Serializable

@Serializable
data class TestMrzData(
    val displayName: String,
    val mrz: List<String>,
)
