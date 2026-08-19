package ch.admin.foitt.wallet.platform.ssi.domain.usecase.implementation

import ch.admin.foitt.wallet.platform.locale.LocaleCompat
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetCurrentAppLocale
import ch.admin.foitt.wallet.platform.locale.domain.usecase.GetLocalizedDisplay
import ch.admin.foitt.wallet.platform.ssi.domain.model.CredentialClaimText
import ch.admin.foitt.wallet.platform.ssi.domain.usecase.MapToCredentialClaimData
import ch.admin.foitt.wallet.platform.ssi.domain.usecase.implementation.MockCredentialClaim.buildClaimWithDateTime
import ch.admin.foitt.wallet.platform.ssi.domain.usecase.implementation.MockCredentialClaim.credentialClaimDisplay
import ch.admin.foitt.wallet.platform.ssi.domain.usecase.implementation.MockCredentialClaim.credentialClaimDisplays
import ch.admin.foitt.wallet.platform.utils.base64NonUrlStringToByteArray
import com.github.michaelbull.result.get
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.time.ZoneId
import java.util.TimeZone

@RunWith(Parameterized::class)
class MapToCredentialClaimDataImplInstrumentationTest(
    val value: String,
    val outputPattern: String?,
    val expected: String,
    val locale: String
) {

    private lateinit var mapToCredentialClaimData: MapToCredentialClaimData

    @MockK
    private lateinit var mockGetLocalizedDisplay: GetLocalizedDisplay

    @MockK
    private val mockGetCurrentAppLocale: GetCurrentAppLocale = mockk<GetCurrentAppLocale>()

    @Before
    fun setUp() {
        MockKAnnotations.init(this)

        TimeZone.setDefault(TimeZone.getTimeZone(ZoneId.of("Europe/Zurich")))

        mockkStatic("ch.admin.foitt.wallet.platform.utils.StringUtilsKt")
        every { base64NonUrlStringToByteArray(any()) } returns byteArrayOf()

        mapToCredentialClaimData = MapToCredentialClaimDataImpl(
            getLocalizedDisplay = mockGetLocalizedDisplay,
            getCurrentAppLocale = mockGetCurrentAppLocale
        )

        coEvery { mockGetLocalizedDisplay(displays = credentialClaimDisplays) } returns credentialClaimDisplay
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun runDataTest() = runTest {
        coEvery { mockGetCurrentAppLocale.invoke() } returns LocaleCompat.of(locale)

        val claimWithDateTime = buildClaimWithDateTime(
            value = value,
            valueDisplayInfo = outputPattern
        )

        val data = mapToCredentialClaimData(claimWithDateTime).get()
        assertNotNull(data)

        assertTrue(
            data is CredentialClaimText,
            "DateTime valueType should return ${CredentialClaimText::class.simpleName}"
        )
        val actual = (data as CredentialClaimText).value
        assertEquals("Expected: $expected, actual: $actual", expected, actual)
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters
        fun data(): List<Array<out String?>> {
            // input, output pattern, expected output, locale
            return listOf(
                // return input as is in case of invalid input and/or invalid or null output pattern
                arrayOf("12345678", null, "12345678", "de"),
                arrayOf("International Talk Like A Pirate Day", "invalid pattern", "International Talk Like A Pirate Day", "de"),
                arrayOf("2007-04-05T14:30Z", "invalid pattern", "2007-04-05T14:30Z", "de"),
                arrayOf("International Talk Like A Pirate Day", "DATE_TIME", "International Talk Like A Pirate Day", "de"),

                // valid dates localized into German
                arrayOf("2007-04-05T14:30:40.12Z", "DATE_TIME_TIMEZONE_SECONDS_FRACTION", "05.04.2007, 16:30:40,120", "de"),
                arrayOf("2007-04-05T14:30:40Z", "DATE_TIME_TIMEZONE_SECONDS", "05.04.2007, 16:30:40", "de"),
                arrayOf("2007-04-05T14:30Z", "DATE_TIME_TIMEZONE", "05.04.2007, 16:30", "de"),
                arrayOf("2007-04-05T14:30+05:00", "DATE_TIME_TIMEZONE", "05.04.2007, 11:30", "de"),
                arrayOf("2007-04-05T14:30-05:00", "DATE_TIME_TIMEZONE", "05.04.2007, 21:30", "de"),

                arrayOf("2007-04-05T14:30:40.12Z", "DATE_TIME_SECONDS_FRACTION", "05.04.2007, 14:30:40,120", "de"),
                arrayOf("2007-04-05T14:30:40Z", "DATE_TIME_SECONDS", "05.04.2007, 14:30:40", "de"),
                arrayOf("2007-04-05T14:30Z", "DATE_TIME", "05.04.2007, 14:30", "de"),

                arrayOf("2007-04-05T00:00Z", "DATE_TIMEZONE", "05.04.2007", "de"),
                arrayOf("2007-04-05T00:00+08:00", "DATE_TIMEZONE", "04.04.2007", "de"),
                arrayOf("2007-04-05T00:00Z", "DATE", "05.04.2007", "de"),

                arrayOf("2007-04-05T00:01:02.12Z", "TIME_TIMEZONE_SECONDS_FRACTION", "02:01:02,120", "de"),
                arrayOf("2007-04-05T00:01:02Z", "TIME_TIMEZONE_SECONDS", "02:01:02", "de"),
                arrayOf("2007-04-05T00:01Z", "TIME_TIMEZONE", "02:01", "de"),

                arrayOf("2007-04-05T01:23:45.67Z", "TIME_SECONDS_FRACTION", "01:23:45,670", "de"),
                arrayOf("2007-04-05T01:23:45.67Z", "TIME_SECONDS", "01:23:45", "de"),
                arrayOf("2007-04-05T01:23:45.67Z", "TIME", "01:23", "de"),

                arrayOf("2023-10-01T00:00Z", "YEAR_MONTH", "Oktober 2023", "de"),
                arrayOf("2023-01-01T00:00Z", "YEAR", "2023", "de"),

                // valid dates localized into English
                arrayOf("2007-04-05T14:30:40.12Z", "DATE_TIME_TIMEZONE_SECONDS_FRACTION", "04/05/2007, 16:30:40.120", "en"),
                arrayOf("2007-04-05T14:30:40Z", "DATE_TIME_TIMEZONE_SECONDS", "04/05/2007, 16:30:40", "en"),
                arrayOf("2007-04-05T14:30Z", "DATE_TIME_TIMEZONE", "04/05/2007, 16:30", "en"),
                arrayOf("2007-04-05T14:30+05:00", "DATE_TIME_TIMEZONE", "04/05/2007, 11:30", "en"),
                arrayOf("2007-04-05T14:30-05:00", "DATE_TIME_TIMEZONE", "04/05/2007, 21:30", "en"),

                arrayOf("2007-04-05T14:30:40.12Z", "DATE_TIME_SECONDS_FRACTION", "04/05/2007, 14:30:40.120", "en"),
                arrayOf("2007-04-05T14:30:40Z", "DATE_TIME_SECONDS", "04/05/2007, 14:30:40", "en"),
                arrayOf("2007-04-05T14:30Z", "DATE_TIME", "04/05/2007, 14:30", "en"),

                arrayOf("2007-04-05T00:00Z", "DATE_TIMEZONE", "04/05/2007", "en"),
                arrayOf("2007-04-05T00:00+08:00", "DATE_TIMEZONE", "04/04/2007", "en"),
                arrayOf("2007-04-05T00:00Z", "DATE", "04/05/2007", "en"),

                arrayOf("2007-04-05T00:01:02.12Z", "TIME_TIMEZONE_SECONDS_FRACTION", "02:01:02.120", "en"),
                arrayOf("2007-04-05T00:01:02Z", "TIME_TIMEZONE_SECONDS", "02:01:02", "en"),
                arrayOf("2007-04-05T00:01Z", "TIME_TIMEZONE", "02:01", "en"),

                arrayOf("2007-04-05T01:23:45.67Z", "TIME_SECONDS_FRACTION", "01:23:45.670", "en"),
                arrayOf("2007-04-05T01:23:45.67Z", "TIME_SECONDS", "01:23:45", "en"),
                arrayOf("2007-04-05T01:23:45.67Z", "TIME", "01:23", "en"),

                arrayOf("2023-10-01T00:00Z", "YEAR_MONTH", "October 2023", "en"),
                arrayOf("2023-01-01T00:00Z", "YEAR", "2023", "en"),
            )
        }
    }
}
