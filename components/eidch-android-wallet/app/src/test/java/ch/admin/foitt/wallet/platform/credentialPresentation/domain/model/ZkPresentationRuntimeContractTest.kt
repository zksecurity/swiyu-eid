package ch.admin.foitt.wallet.platform.credentialPresentation.domain.model

import ch.admin.foitt.wallet.util.SafeJsonTestInstance
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class ZkPresentationRuntimeContractTest {

    private val json = SafeJsonTestInstance.json
    private val vector = json.decodeFromString<RuntimeVector>(loadFixture())

    @Test
    fun `Kotlin challenge hash matches the shared zkID vector`() {
        val hash = vector.request.challenge.hashForAgeProfile()

        assertEquals(vector.expected.challengeSha256, hash.digest.toHex())
        assertEquals(vector.expected.challengeScalar, hash.scalar.toString())
    }

    @Test
    fun `serialized request keeps the versioned mobile runtime ABI`() {
        val serialized = json.encodeToString(vector.request)

        assertTrue(serialized.contains("\"schema\":\"$ZkPresentationRuntimeRequestSchema\""))
        assertTrue(serialized.contains("\"credential_id\":42"))
        assertTrue(serialized.contains("\"circuit_ids\":[\"swiyu_age18_status_2k\"]"))
        assertFalse(serialized.contains("credentialId"))
        assertFalse(serialized.contains("circuitIds"))
    }

    private fun loadFixture(): String {
        val relativePath = Path.of("integration/contracts/fixtures/mobile-runtime-v1.json")
        val fixture = generateSequence(Path.of("").toAbsolutePath()) { path -> path.parent }
            .map { path -> path.resolve(relativePath) }
            .firstOrNull { path -> Files.isRegularFile(path) }
            ?: error("Could not locate $relativePath from the test working directory")
        return fixture.toFile().readText(Charsets.UTF_8)
    }

    private fun ByteArray.toHex() = joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }

    @Serializable
    private data class RuntimeVector(
        val request: ZkPresentationRuntimeRequest,
        val expected: Expected,
    )

    @Serializable
    private data class Expected(
        @SerialName("challenge_sha256")
        val challengeSha256: String,
        @SerialName("challenge_scalar")
        val challengeScalar: String,
    )
}
