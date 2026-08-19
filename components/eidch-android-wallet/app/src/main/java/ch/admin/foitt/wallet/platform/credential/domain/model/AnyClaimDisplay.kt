package ch.admin.foitt.wallet.platform.credential.domain.model

data class AnyClaimDisplay(
    override val locale: String? = null,
    override val name: String,
    val value: String? = null,
) : AnyDisplay
