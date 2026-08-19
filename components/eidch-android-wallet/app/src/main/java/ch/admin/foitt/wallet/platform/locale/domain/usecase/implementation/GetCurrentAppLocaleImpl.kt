package ch.admin.foitt.wallet.platform.locale.domain.usecase.implementation

import android.content.res.Resources
import androidx.appcompat.app.AppCompatDelegate
import ch.admin.foitt.wallet.platform.database.domain.model.DisplayLanguage
import ch.admin.foitt.wallet.platform.locale.LocaleCompat
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetCurrentAppLocale
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetSupportedAppLocales
import ch.admin.foitt.wallet.platform.utils.toListOfLocales
import java.util.Locale
import javax.inject.Inject

class GetCurrentAppLocaleImpl @Inject constructor(
    private val getSupportedAppLocales: GetSupportedAppLocales
) : GetCurrentAppLocale {

    private val defaultLocale = LocaleCompat.of(DisplayLanguage.DEFAULT, DisplayLanguage.DEFAULT_COUNTRY)

    override fun invoke(): Locale {
        return if (AppCompatDelegate.getApplicationLocales().isEmpty) {
            // no specific app language was set
            // -> use one from the device if possible (but use the order as prioritization)
            useDeviceLocaleOrDefault()
        } else {
            useAppSpecificLocale()
        }
    }

    private fun useDeviceLocaleOrDefault(): Locale {
        val supportedLanguages = getSupportedAppLocales().map { it.language }.toSet()
        val systemLocales = Resources.getSystem().configuration.locales.toListOfLocales()
        val preferredLocale = systemLocales.firstOrNull { it.language in supportedLanguages } ?: defaultLocale
        return preferredLocale
    }

    private fun useAppSpecificLocale(): Locale {
        return AppCompatDelegate.getApplicationLocales()[0] ?: defaultLocale
    }
}
