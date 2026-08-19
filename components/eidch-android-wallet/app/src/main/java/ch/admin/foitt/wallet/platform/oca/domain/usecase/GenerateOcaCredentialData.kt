package ch.admin.foitt.wallet.platform.oca.domain.usecase

import ch.admin.foitt.wallet.platform.oca.domain.model.CaptureBase
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaCredentialData
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.Overlay

interface GenerateOcaCredentialData {
    operator fun invoke(rootCaptureBase: CaptureBase, overlays: List<Overlay>): List<OcaCredentialData>
}
