package ch.admin.foitt.wallet.platform.nonCompliance.domain.usecase

import ch.admin.foitt.wallet.platform.nonCompliance.domain.model.NonComplianceData

interface FetchNonComplianceData {
    suspend operator fun invoke(actorDid: String): NonComplianceData
}
