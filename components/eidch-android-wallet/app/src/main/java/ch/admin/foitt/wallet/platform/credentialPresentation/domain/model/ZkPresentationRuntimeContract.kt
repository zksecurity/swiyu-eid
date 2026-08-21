package ch.admin.foitt.wallet.platform.credentialPresentation.domain.model

import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.LocalDate

private const val AgeProfile = "swiyu-age18-status-2k-v0"
private const val AgeCircuit = "swiyu_age18_status_2k"
private val ChallengeDomain = "swiyu-show-v0\u0000".toByteArray(StandardCharsets.UTF_8)
private val P256ScalarOrder = BigInteger(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
)

data class ZkPresentationChallengeHash(
    val digest: ByteArray,
    val scalar: BigInteger,
)

/** Exact host implementation of zkID's canonical age-profile challenge hash. */
fun ZkPresentationChallenge.hashForAgeProfile(): ZkPresentationChallengeHash {
    val policy = policy
    require(policy.profile == AgeProfile) { "Unsupported ZK challenge profile" }
    require(policy.circuitIds == listOf(AgeCircuit)) { "Unsupported ZK challenge circuit" }
    val cutoffDate = policy.parameters.getValue("cutoff_date").jsonPrimitive.content
    val parsedCutoffDate = LocalDate.parse(cutoffDate)
    require(parsedCutoffDate.year in 1900..2199) { "cutoff_date year must be in 1900..2199" }
    val currentTime = policy.parameters.getValue("current_time").jsonPrimitive.long
    require(currentTime >= 0) { "current_time must be non-negative" }
    val statusListSnapshot = policy.parameters.getValue("status_list_snapshot").jsonPrimitive.content

    val encoded = ByteArrayOutputStream().apply {
        write(ChallengeDomain)
        listOf(
            nonce,
            clientId,
            responseUri,
            state,
            queryId,
            policy.profile,
            cutoffDate,
            currentTime.toString(),
            statusListSnapshot,
        ).forEach { field -> writeLengthPrefixed(field) }
    }.toByteArray()
    val digest = MessageDigest.getInstance("SHA-256").digest(encoded)
    return ZkPresentationChallengeHash(
        digest = digest,
        scalar = BigInteger(1, digest).mod(P256ScalarOrder),
    )
}

private fun ByteArrayOutputStream.writeLengthPrefixed(value: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    require(bytes.size in 1..4096) { "ZK challenge field length must be in 1..4096" }
    write(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
    write(bytes)
}
