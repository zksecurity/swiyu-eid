package ch.admin.foitt.openid4vc.domain.model.credentialoffer.metadata

data class RawAndParsedIssuerCredentialInfo(
    val rawIssuerCredentialInfo: String,
    val issuerCredentialInfo: IssuerCredentialInfo,
)
