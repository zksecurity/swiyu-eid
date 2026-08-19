package ch.admin.foitt.wallet.platform.oca.mock

import ch.admin.foitt.wallet.platform.oca.domain.model.AttributeType
import ch.admin.foitt.wallet.platform.oca.domain.model.CaptureBase1x0
import ch.admin.foitt.wallet.platform.oca.domain.model.OcaBundle
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.EntryCodeOverlay
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.EntryCodeOverlay1x0
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.EntryOverlay
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.EntryOverlay1x0
import ch.admin.foitt.wallet.platform.oca.domain.model.overlays.LabelOverlay1x0

object OverlayMocks {

    val ocaBundleWithInvalidOverlayReferences = OcaBundle(
        captureBases = listOf(
            CaptureBase1x0(
                digest = "validDigest",
                attributes = mapOf(
                    "attributeKey" to AttributeType.Text,
                )
            ),
        ),
        overlays = listOf(
            LabelOverlay1x0(
                captureBaseDigest = "invalidReference",
                language = "en",
                attributeLabels = mapOf(
                    "attributeKey" to "label"
                )
            )
        )
    )

    val ocaBundleWithInvalidOverlayAttributeKey = OcaBundle(
        captureBases = listOf(
            CaptureBase1x0(
                digest = "validDigest",
                attributes = mapOf(
                    "attributeKey" to AttributeType.Text,
                )
            ),
        ),
        overlays = listOf(
            LabelOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "en",
                attributeLabels = mapOf(
                    "nonMatchingAttributeKey" to "label"
                )
            )
        )
    )

    /*
    val ocaWithComplexClusterOverlay = OcaBundle(
        captureBases = listOf(
            CaptureBase1x0(
                digest = "validDigest",
                attributes = mapOf(
                    "attributeKey" to AttributeType.Text,
                    "attribute2Key" to AttributeType.Text,
                    "attribute3Key" to AttributeType.Text,
                    "attribute4Key" to AttributeType.Text,
                    "attribute5Key" to AttributeType.Text,
                    "attribute6Key" to AttributeType.Text,
                    "attribute7Key" to AttributeType.Text,
                ),
            ),
            CaptureBase1x0(
                digest = "validDigest2",
                attributes = mapOf(
                    "captureBase2attributeKey" to AttributeType.Text,
                ),
            ),
        ),
        overlays = listOf(
            OrderingOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "en",
                clusterOrder = mapOf("main" to 2, "additional" to 1),
                clusterLabels = mapOf("main" to "mainLabel", "additional" to "additionalLabel"),
                attributeClusterOrder = mapOf(
                    "main" to mapOf("attributeKey" to 2, "attribute2Key" to 1),
                    "additional" to mapOf("attribute3Key" to 1)
                ),
            ),
            OrderingOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "de",
                clusterOrder = mapOf("cluster2" to 2, "cluster1" to 1),
                clusterLabels = mapOf(),
                attributeClusterOrder = mapOf(
                    "cluster1" to mapOf("attribute4Key" to 2, "attribute5Key" to 1),
                    "cluster2" to mapOf("attribute6Key" to 1)
                ),
            ),
            OrderingOverlay1x0(
                captureBaseDigest = "validDigest2",
                language = "en",
                clusterOrder = mapOf("main2" to 2),
                clusterLabels = mapOf("main2" to "main2Label"),
                attributeClusterOrder = mapOf(
                    "main2" to mapOf("captureBase2attributeKey" to 2),
                ),
            )
        )
    )

     */

    val ocaBundleWithValidEntryAndEntryCodeOverlays = getOcaWithEntryAndEntryCodeOverlay(
        entryCodeOverlay = listOf(
            EntryCodeOverlay1x0(
                captureBaseDigest = "validDigest",
                attributeEntryCodes = mapOf(
                    "attributeKey" to listOf("A", "B"),
                    "attribute2Key" to listOf("C", "D"),
                )
            ),
        ),
        entryOverlay = listOf(
            EntryOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "en",
                attributeEntries = mapOf(
                    "attributeKey" to mapOf(
                        "A" to "A label",
                        "B" to "B label",
                    )
                )
            ),
            EntryOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "de",
                attributeEntries = mapOf(
                    "attribute2Key" to mapOf(
                        "D" to "D label",
                        "C" to "C label",
                    )
                )
            ),
        )
    )

    val ocaBundleWithoutEntryButWithEntryCodeOverlay = getOcaWithEntryAndEntryCodeOverlay(
        entryCodeOverlay = listOf(
            EntryCodeOverlay1x0(
                captureBaseDigest = "validDigest",
                attributeEntryCodes = mapOf(
                    "attributeKey" to listOf("A", "B"),
                    "attribute2Key" to listOf("C", "D"),
                )
            ),
        ),
        entryOverlay = emptyList()
    )

    val ocaBundleWithoutEntryButWithMultipleEntryCodeOverlays = getOcaWithEntryAndEntryCodeOverlay(
        entryCodeOverlay = listOf(
            EntryCodeOverlay1x0(
                captureBaseDigest = "validDigest",
                attributeEntryCodes = mapOf(
                    "attributeKey" to listOf("A", "B"),
                )
            ),
            EntryCodeOverlay1x0(
                captureBaseDigest = "validDigest",
                attributeEntryCodes = mapOf(
                    "attribute2Key" to listOf("C", "D"),
                )
            ),
        ),
        entryOverlay = emptyList()
    )

    val ocaBundleWithEntryButWithoutEntryCodeOverlay =
        getOcaWithEntryAndEntryCodeOverlay(entryCodeOverlay = emptyList())

    val ocaBundleWithEntryKeyNotInEntryCodes = getOcaWithEntryAndEntryCodeOverlay(
        entryOverlay = listOf(
            EntryOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "en",
                attributeEntries = mapOf(
                    "attributeKey" to mapOf(
                        "C" to "C label",
                    )
                )
            ),
        )
    )

    private fun getOcaWithEntryAndEntryCodeOverlay(
        entryCodeOverlay: List<EntryCodeOverlay> = listOf(
            EntryCodeOverlay1x0(
                captureBaseDigest = "validDigest",
                attributeEntryCodes = mapOf(
                    "attributeKey" to listOf("A", "B"),
                )
            ),
        ),
        entryOverlay: List<EntryOverlay> = listOf(
            EntryOverlay1x0(
                captureBaseDigest = "validDigest",
                language = "en",
                attributeEntries = mapOf(
                    "attributeKey" to mapOf(
                        "A" to "A label",
                        "B" to "B label",
                    )
                )
            ),
        )
    ) = OcaBundle(
        captureBases = listOf(
            CaptureBase1x0(
                digest = "validDigest",
                attributes = mapOf(
                    "attributeKey" to AttributeType.Text,
                    "attribute2Key" to AttributeType.Text,
                )
            )
        ),
        overlays = entryCodeOverlay + entryOverlay
    )
}
