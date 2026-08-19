package ch.admin.foitt.wallet.platform.appAttestation.domain.model

data class ClientAttestationPoP(
    val value: String,
) {
    companion object {
        const val REQUEST_HEADER = "OAuth-Client-Attestation-PoP"
    }
}
