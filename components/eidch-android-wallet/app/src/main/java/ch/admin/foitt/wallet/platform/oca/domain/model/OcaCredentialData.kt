package ch.admin.foitt.wallet.platform.oca.domain.model

import kotlinx.serialization.Serializable

/**
 * OcaCredentialData, containing data from overlays that is used for displaying credentials
 */
@Serializable
data class OcaCredentialData(
    val captureBaseDigest: String,
    val locale: String,
    val theme: String?,
    val name: String?,
    val description: String?,
    val logoData: String?,
    val backgroundColor: String?,
)
