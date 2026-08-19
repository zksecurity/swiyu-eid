package ch.admin.foitt.wallet.platform.oca.domain.usecase

import ch.admin.foitt.wallet.platform.oca.domain.model.CaptureBase
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaClaimData
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.Overlay

interface GenerateOcaClaimData {
    operator fun invoke(captureBases: List<CaptureBase>, overlays: List<Overlay>): List<OcaClaimData>
}
