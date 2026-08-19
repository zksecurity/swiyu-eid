package ch.admin.foitt.wallet.platform.oca.domain.usecase.implementation

import android.R.attr.logo
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaCredentialData
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.BrandingOverlay1x1
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.MetaOverlay1x0
import ch.admin.foitt.wallet.platform.oca.domain.usecase.GenerateOcaCredentialData
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.BRANDING_BACKGROUND_COLOR
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.BRANDING_DARK_THEME
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.BRANDING_LIGHT_THEME
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.BRANDING_LOGO
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.BRANDING_PRIMARY_FIELD
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.DIGEST
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.LANGUAGE_DE
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.LANGUAGE_EN
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.META_DESCRIPTION
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.META_NAME
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.ocaSimpleBranding
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.ocaSimpleMeta
import ch.admin.foitt.wallet.platform.oca.mock.ocaMocks.OcaMocks.simpleCaptureBase
import ch.admin.foitt.wallet.util.assertTrue
import io.mockk.MockKAnnotations
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class GenerateOcaCredentialDataImplTest {

    private lateinit var useCase: GenerateOcaCredentialData

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)

        useCase = GenerateOcaCredentialDataImpl()
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `Generator correctly processes overlays`() = runTest {
        val overlayBundleAttributes = useCase(rootCaptureBase = simpleCaptureBase, overlays = overlaysMetaAndBranding)

        val expectedCredentialData = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_EN,
            name = META_NAME,
            theme = BRANDING_LIGHT_THEME,
            description = BRANDING_PRIMARY_FIELD,
            logoData = BRANDING_LOGO,
            backgroundColor = BRANDING_BACKGROUND_COLOR,
        )

        assertEquals(1, overlayBundleAttributes.size)
        assertEquals(expectedCredentialData, overlayBundleAttributes[0])
    }

    @Test
    fun `Generator correctly processes data when only meta overlay exists`() = runTest {
        val overlayBundleAttributes = useCase(rootCaptureBase = simpleCaptureBase, overlays = ocaSimpleMeta.overlays)

        val expectedCredentialData = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_EN,
            name = META_NAME,
            description = META_DESCRIPTION,
            theme = null,
            logoData = null,
            backgroundColor = null,
        )

        assertEquals(1, overlayBundleAttributes.size)
        assertEquals(expectedCredentialData, overlayBundleAttributes[0])
    }

    @Test
    fun `Generator correctly processes data when only branding overlay exists`() = runTest {
        val overlayBundleAttributes =
            useCase(rootCaptureBase = simpleCaptureBase, overlays = ocaSimpleBranding.overlays)

        val expectedCredentialData = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_EN,
            name = null,
            theme = BRANDING_LIGHT_THEME,
            description = BRANDING_PRIMARY_FIELD,
            logoData = BRANDING_LOGO,
            backgroundColor = BRANDING_BACKGROUND_COLOR,
        )

        assertEquals(1, overlayBundleAttributes.size)
        assertEquals(expectedCredentialData, overlayBundleAttributes[0])
    }

    @Test
    fun `Generator returns empty list when neither branding nor meta overlays exist`() = runTest {
        val overlayBundleAttributes = useCase(rootCaptureBase = simpleCaptureBase, overlays = emptyList())

        assertEquals(0, overlayBundleAttributes.size)
    }

    @Test
    fun `Generator correctly processes data when there are overlays for multiple languages and themes`() = runTest {
        val overlayBundleAttributes = useCase(rootCaptureBase = simpleCaptureBase, overlays = overlaysMultipleLanguages)

        val expectedCredentialDataDe = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_DE,
            name = META_NAME,
            description = META_DESCRIPTION,
            theme = null,
            logoData = null,
            backgroundColor = null,
        )

        val expectedCredentialDataEnLight = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_EN,
            name = null,
            theme = BRANDING_LIGHT_THEME,
            description = BRANDING_PRIMARY_FIELD,
            logoData = BRANDING_LOGO,
            backgroundColor = BRANDING_BACKGROUND_COLOR,
        )

        val expectedCredentialDataEnDark = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_EN,
            name = null,
            theme = BRANDING_DARK_THEME,
            description = BRANDING_PRIMARY_FIELD,
            logoData = BRANDING_LOGO,
            backgroundColor = BRANDING_BACKGROUND_COLOR,
        )

        val expectedCredentialDataEnNoTheme = OcaCredentialData(
            captureBaseDigest = simpleCaptureBase.digest,
            locale = LANGUAGE_EN,
            name = null,
            theme = null,
            description = BRANDING_PRIMARY_FIELD,
            logoData = BRANDING_LOGO,
            backgroundColor = BRANDING_BACKGROUND_COLOR,
        )

        assertEquals(4, overlayBundleAttributes.size)
        assertTrue(overlayBundleAttributes.contains(expectedCredentialDataDe))
        assertTrue(overlayBundleAttributes.contains(expectedCredentialDataEnLight))
        assertTrue(overlayBundleAttributes.contains(expectedCredentialDataEnDark))
        assertTrue(overlayBundleAttributes.contains(expectedCredentialDataEnNoTheme))
    }

    private val overlaysMetaAndBranding = ocaSimpleMeta.overlays + ocaSimpleBranding.overlays

    private val overlaysMultipleLanguages = listOf(
        MetaOverlay1x0(
            captureBaseDigest = DIGEST,
            language = LANGUAGE_DE,
            name = META_NAME,
            description = META_DESCRIPTION
        ),
        BrandingOverlay1x1(
            captureBaseDigest = DIGEST,
            language = LANGUAGE_EN,
            theme = null,
            logo = BRANDING_LOGO,
            primaryBackgroundColor = BRANDING_BACKGROUND_COLOR,
            primaryField = BRANDING_PRIMARY_FIELD,
        ),
        BrandingOverlay1x1(
            captureBaseDigest = DIGEST,
            language = LANGUAGE_EN,
            theme = BRANDING_LIGHT_THEME,
            logo = BRANDING_LOGO,
            primaryBackgroundColor = BRANDING_BACKGROUND_COLOR,
            primaryField = BRANDING_PRIMARY_FIELD,
        ),
        BrandingOverlay1x1(
            captureBaseDigest = DIGEST,
            language = LANGUAGE_EN,
            theme = BRANDING_DARK_THEME,
            logo = BRANDING_LOGO,
            primaryBackgroundColor = BRANDING_BACKGROUND_COLOR,
            primaryField = BRANDING_PRIMARY_FIELD,
        )
    )
}
