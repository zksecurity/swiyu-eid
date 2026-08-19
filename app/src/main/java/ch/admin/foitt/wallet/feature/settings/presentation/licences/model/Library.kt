package ch.admin.foitt.wallet.feature.settings.presentation.licences.model

data class Library(
    val name: String,
    val version: String?,
    val licenseName: String,
    val licenseContent: String,
)
