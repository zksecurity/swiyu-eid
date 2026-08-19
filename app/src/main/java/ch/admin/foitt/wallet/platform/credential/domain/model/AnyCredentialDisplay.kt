package ch.admin.foitt.wallet.platform.credential.domain.model

import ch.admin.foitt.openid4vc.domain.model.credentialoffer.metadata.OidCredentialDisplay
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaCredentialData

data class AnyCredentialDisplay(
    override val locale: String? = null,
    override val name: String? = null,
    val description: String? = null,
    val logo: String? = null,
    val logoAltText: String? = null,
    val backgroundColor: String? = null,
    val textColor: String? = null,
    val theme: String? = null,
) : AnyDisplay

fun OcaCredentialData.toAnyCredentialDisplay() = AnyCredentialDisplay(
    locale = this.locale,
    name = this.name,
    description = this.description,
    logo = this.logoData,
    backgroundColor = this.backgroundColor,
    theme = this.theme,
)

fun OidCredentialDisplay.toAnyCredentialDisplay() = AnyCredentialDisplay(
    locale = this.locale,
    name = this.name,
    description = this.description,
    logo = this.logo?.uri,
    logoAltText = this.logo?.altText,
    backgroundColor = this.backgroundColor,
    textColor = this.textColor,
)
