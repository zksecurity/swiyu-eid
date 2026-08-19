package ch.admin.foitt.wallet.platform.locale.domain.usecase

import java.util.Locale

interface GetSupportedAppLocales {
    operator fun invoke(): List<Locale>
}
