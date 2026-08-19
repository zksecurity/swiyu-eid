package ch.admin.foitt.wallet.platform.locale.domain.usecase.implementation

import android.content.res.Configuration
import android.content.res.Resources
import android.os.LocaleList
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import ch.admin.foitt.wallet.platform.database.domain.model.DisplayLanguage
import ch.admin.foitt.wallet.platform.locale.LocaleCompat
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetCurrentAppLocale
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetSupportedAppLocales
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class GetCurrentAppLocaleImplTest {

    @MockK
    private lateinit var mockGetSupportedAppLocales: GetSupportedAppLocales

    @MockK
    private lateinit var mockAppLocales: LocaleListCompat

    @MockK
    private lateinit var mockLocales: LocaleList

    private lateinit var useCase: GetCurrentAppLocale

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)
        useCase = GetCurrentAppLocaleImpl(
            getSupportedAppLocales = mockGetSupportedAppLocales
        )

        setupDefaultMocks()
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `using device locale, both locales supported returns the first`() = runTest {
        every { mockAppLocales.isEmpty } returns true

        every { mockLocales[0] } returns LocaleCompat.of("de", "CH")
        every { mockLocales[1] } returns LocaleCompat.of("de", "DE")
        every { mockLocales.size() } returns 2

        val result = useCase()

        assertEquals(LocaleCompat.of("de", "CH"), result)
    }

    @Test
    fun `using device locale, one locale not supported, one supported returns the supported`() = runTest {
        every { mockAppLocales.isEmpty } returns true

        every { mockLocales[0] } returns LocaleCompat.of("es", "ES")
        every { mockLocales[1] } returns LocaleCompat.of("de", "CH")
        every { mockLocales.size() } returns 2

        val result = useCase()

        assertEquals(LocaleCompat.of("de", "CH"), result)
    }

    @Test
    fun `using device locale, no locale supported returns the default locale`() = runTest {
        every { mockAppLocales.isEmpty } returns true

        every { mockLocales[0] } returns LocaleCompat.of("es", "ES")
        every { mockLocales.size() } returns 1

        val result = useCase()

        assertEquals(LocaleCompat.of(DisplayLanguage.DEFAULT, DisplayLanguage.DEFAULT_COUNTRY), result)
    }

    @Test
    fun `using app specific locale, returns the first locale`() = runTest {
        every { mockAppLocales.isEmpty } returns false
        every { mockAppLocales.size() } returns 1
        every { mockAppLocales[0] } returns LocaleCompat.of("de", "CH")

        val result = useCase()

        assertEquals(LocaleCompat.of("de", "CH"), result)
    }

    @Test
    fun `using app specific locale, no locale provided returns the default locale`() = runTest {
        every { mockAppLocales.isEmpty } returns false
        every { mockAppLocales.size() } returns 1
        every { mockAppLocales[0] } returns null

        val result = useCase()

        assertEquals(LocaleCompat.of(DisplayLanguage.DEFAULT, DisplayLanguage.DEFAULT_COUNTRY), result)
    }

    private fun setupDefaultMocks() {
        coEvery {
            mockGetSupportedAppLocales()
        } returns listOf(LocaleCompat.of("de"), LocaleCompat.of("en"), LocaleCompat.of("fr"), LocaleCompat.of("it"), LocaleCompat.of("rm"))

        mockkStatic(AppCompatDelegate::class)
        every { AppCompatDelegate.getApplicationLocales() } returns mockAppLocales

        mockkStatic(Resources::class)
        val mockResources = mockk<Resources>()
        val mockConfiguration = mockk<Configuration>()

        every { Resources.getSystem() } returns mockResources
        every { mockResources.configuration } returns mockConfiguration
        every { mockConfiguration.locales } returns mockLocales
    }
}
