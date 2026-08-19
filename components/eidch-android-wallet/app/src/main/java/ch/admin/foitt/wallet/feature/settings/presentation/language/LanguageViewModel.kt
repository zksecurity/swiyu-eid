package ch.admin.foitt.wallet.feature.settings.presentation.language

import android.content.res.Resources
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import ch.admin.foitt.wallet.R
import ch.admin.foitt.wallet.platform.database.domain.model.DisplayLanguage
import ch.admin.foitt.wallet.platform.locale.LocaleCompat
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetCurrentAppLocale
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetSupportedAppLocales
import ch.admin.foitt.wallet.platform.navigation.NavigationManager
import ch.admin.foitt.wallet.platform.scaffold.domain.model.TopBarState
import ch.admin.foitt.wallet.platform.scaffold.domain.usecase.SetTopBarState
import ch.admin.foitt.wallet.platform.scaffold.presentation.ScreenViewModel
import ch.admin.foitt.wallet.platform.utils.toListOfLocales
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class LanguageViewModel @Inject constructor(
    private val navManager: NavigationManager,
    private val getSupportedAppLocales: GetSupportedAppLocales,
    private val getCurrentAppLocale: GetCurrentAppLocale,
    setTopBarState: SetTopBarState,
) : ScreenViewModel(setTopBarState) {

    override val topBarState = TopBarState.Details(navManager::popBackStack, R.string.tk_settings_language_title)

    private val defaultLocale = LocaleCompat.of(DisplayLanguage.DEFAULT, DisplayLanguage.DEFAULT_COUNTRY)

    private var _selectedLocale = MutableStateFlow(defaultLocale)
    val selectedLocale = _selectedLocale.asStateFlow()

    private var _supportedLocales = MutableStateFlow(listOf(defaultLocale))
    val supportedLocales = _supportedLocales.asStateFlow()

    private var _isSystemLocale = MutableStateFlow(true)
    val isSystemLocale = _isSystemLocale.asStateFlow()

    init {
        _supportedLocales.value = getSupportedAppLocales()
        _selectedLocale.value = getSelectedLocale()
    }

    private fun getSelectedLocale(): Locale {
        return if (AppCompatDelegate.getApplicationLocales().isEmpty) {
            // no specific app language was set
            // -> use one from the device if possible (but use the order as prioritization)
            useDeviceLocaleOrDefault()
        } else {
            useAppSpecificLocale()
        }
    }

    private fun useDeviceLocaleOrDefault(): Locale {
        _isSystemLocale.value = true
        val supportedLanguages = getSupportedAppLocales().map { it.language }.toSet()
        val systemLocales = Resources.getSystem().configuration.locales.toListOfLocales()
        val preferredLocale = systemLocales.firstOrNull { it.language in supportedLanguages } ?: defaultLocale
        return preferredLocale
    }

    private fun useAppSpecificLocale(): Locale {
        _isSystemLocale.value = false
        return AppCompatDelegate.getApplicationLocales()[0] ?: defaultLocale
    }

    fun checkLocaleChangedInSettings() {
        val currentLocale = getCurrentAppLocale()
        val isCurrentLocaleSystemDefault = AppCompatDelegate.getApplicationLocales().isEmpty
        if (currentLocale.language != selectedLocale.value.language || isSystemLocale.value != isCurrentLocaleSystemDefault) {
            _isSystemLocale.value = isCurrentLocaleSystemDefault
            _selectedLocale.value = currentLocale
        }
    }

    fun onUpdateLocale(locale: Locale) {
        _isSystemLocale.value = false
        _selectedLocale.value = locale
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(locale.language))
    }

    fun useSystemDefaultLocale() {
        _isSystemLocale.value = true
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList())
    }
}
