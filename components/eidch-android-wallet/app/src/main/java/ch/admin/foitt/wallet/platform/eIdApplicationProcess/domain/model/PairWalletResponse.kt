package ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PairWalletResponse(
    @SerialName("walletPairingId")
    val walletPairingId: String,
    @SerialName("credentialOfferLink")
    val credentialOfferLink: String,
)
