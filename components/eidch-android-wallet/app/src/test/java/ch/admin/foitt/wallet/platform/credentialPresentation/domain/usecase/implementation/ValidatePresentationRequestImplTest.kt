package ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.anycredential.Validity
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.AuthorizationRequest
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.RequestObject
import ch.admin.foitt.openid4vc.domain.model.presentationRequest.RequestObjectVerificationOutcome
import ch.admin.foitt.openid4vc.domain.model.vcSdJwt.VcSdJwtError
import ch.admin.foitt.openid4vc.domain.usecase.VerifyRequestObjectSignature
import ch.admin.foitt.wallet.platform.credentialPresentation.domain.model.CredentialPresentationError
import ch.admin.foitt.wallet.platform.credentialPresentation.domain.model.VerificationProcessType
import ch.admin.foitt.wallet.platform.credentialPresentation.domain.usecase.ValidatePresentationRequest
import ch.admin.foitt.wallet.platform.credentialPresentation.mock.MockPresentationRequest
import ch.admin.foitt.wallet.platform.credentialPresentation.mock.MockPresentationRequest.CLIENT_ID
import ch.admin.foitt.wallet.platform.credentialPresentation.mock.MockPresentationRequest.CLIENT_ID_WITH_PREFIX
import ch.admin.foitt.wallet.platform.environmentSetup.domain.repository.EnvironmentSetupRepository
import ch.admin.foitt.wallet.util.SafeJsonTestInstance
import ch.admin.foitt.wallet.util.assertErrorType
import ch.admin.foitt.wallet.util.assertOk
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.impl.annotations.SpyK
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory

class ValidatePresentationRequestImplTest {

    private val testSafeJson = SafeJsonTestInstance.safeJson

    @MockK
    private lateinit var mockRequestObject: RequestObject

    @MockK
    private lateinit var mockEnvironmentSetupRepository: EnvironmentSetupRepository

    @MockK
    private lateinit var mockVerifyRequestObjectSignature: VerifyRequestObjectSignature

    @SpyK
    private var mockPresentationJwt: Jwt = Jwt(MockPresentationRequest.VALID_JWT)

    private lateinit var useCase: ValidatePresentationRequest

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)
        useCase = ValidatePresentationRequestImpl(
            safeJson = testSafeJson,
            environmentSetupRepository = mockEnvironmentSetupRepository,
            verifyRequestObjectSignature = mockVerifyRequestObjectSignature,
        )

        setupDefaultMocks()
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `A valid jwt presentation request returns Ok`() = runTest {
        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `A signed ZK policy is parsed and indexed by DCQL query id`() = runTest {
        every { mockPresentationJwt.payloadJson } returns authorizationRequestWithZkPolicy()

        val result = useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()

        val policy = result.zkPresentationPolicies.getValue("id")
        assertEquals("swiyu-age18-status-2k-v0", policy.profile)
        assertEquals("swiyu_age18_status_2k", policy.circuitId)
        assertEquals("2008-08-20", policy.cutoffDate)
        assertEquals("snapshot-2026-08-20", policy.statusListSnapshot)
        assertEquals(1787184000L, policy.currentTime)
    }

    @Test
    fun `A ZK policy is rejected when request-object signature verification is disabled`() = runTest {
        every { mockPresentationJwt.payloadJson } returns authorizationRequestWithZkPolicy()
        every { mockEnvironmentSetupRepository.verifyRequestObjectSignature } returns false

        useCase(VerificationProcessType.NETWORK, mockRequestObject)
            .assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `An unsupported ZK circuit is rejected`() = runTest {
        every { mockPresentationJwt.payloadJson } returns authorizationRequestWithZkPolicy(
            circuitId = "unsupported"
        )

        useCase(VerificationProcessType.NETWORK, mockRequestObject)
            .assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @TestFactory
    fun `A ZK policy is rejected when its DCQL query does not describe the age predicate`(): List<DynamicTest> {
        val invalidQueries = listOf<Pair<String, MutableMap<String, JsonElement>.() -> Unit>>(
            "wrong credential format" to {
                put("format", JsonPrimitive("vc+sd-jwt"))
            },
            "multiple presentations" to {
                put("multiple", JsonPrimitive(true))
            },
            "missing explicit holder binding" to {
                remove("require_cryptographic_holder_binding")
            },
            "claim sets" to {
                put("claim_sets", JsonArray(listOf(JsonArray(listOf(JsonPrimitive("birthdate"))))))
            },
            "wrong claim path" to {
                put("claims", JsonArray(listOf(buildJsonObject {
                    put("id", "given_name")
                    put("path", JsonArray(listOf(JsonPrimitive("given_name"))))
                })))
            },
            "requested birthdate disclosure value" to {
                put("claims", JsonArray(listOf(buildJsonObject {
                    put("id", "birthdate")
                    put("path", JsonArray(listOf(JsonPrimitive("birthdate"))))
                    put("values", JsonArray(listOf(JsonPrimitive("2000-01-01"))))
                })))
            },
        )

        return invalidQueries.map { (name, mutation) ->
            DynamicTest.dynamicTest(name) {
                runTest {
                    every { mockPresentationJwt.payloadJson } returns authorizationRequestWithZkPolicy(mutation = mutation)

                    useCase(VerificationProcessType.NETWORK, mockRequestObject)
                        .assertErrorType(CredentialPresentationError.InvalidRequest::class)
                }
            }
        }
    }

    @Test
    fun `A valid jwt presentation request with client ID prefix on request object returns Ok`() = runTest {
        every { mockRequestObject.clientId } returns CLIENT_ID_WITH_PREFIX

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `A valid jwt presentation request with client ID prefix on authorization request returns Ok`() = runTest {
        every { mockPresentationJwt.payloadJson } returns
            MockPresentationRequest.authorizationRequest.copy(clientId = CLIENT_ID_WITH_PREFIX).toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `A valid jwt presentation request with client ID prefix everywhere returns Ok`() = runTest {
        every { mockRequestObject.clientId } returns CLIENT_ID_WITH_PREFIX
        every { mockPresentationJwt.payloadJson } returns
            MockPresentationRequest.authorizationRequest.copy(clientId = CLIENT_ID_WITH_PREFIX).toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `A valid proximity jwt presentation request returns Ok`() = runTest {
        useCase(VerificationProcessType.PROXIMITY, mockRequestObject).assertOk()
    }

    @TestFactory
    fun `Request object jwt missing or containing invalid header typ returns an error`(): List<DynamicTest> {
        val input = listOf(null, "otherType")

        return input.map {
            DynamicTest.dynamicTest("Input: $it should return an unexpected error") {
                runTest {
                    every { mockPresentationJwt.type } returns it

                    useCase(
                        VerificationProcessType.NETWORK,
                        mockRequestObject
                    ).assertErrorType(CredentialPresentationError.Unexpected::class)
                }
            }
        }
    }

    @TestFactory
    fun `Request object jwt missing parameter returns unexpected error`(): List<DynamicTest> {
        val input = listOf("client_id", "response_uri")
        return input.map {
            DynamicTest.dynamicTest("Request object jwt missing $it returns an error") {
                runTest {
                    val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
                        remove(it)
                    }.let { json -> JsonObject(json) }
                    every { mockPresentationJwt.payloadJson } returns payloadJson
                    useCase(
                        VerificationProcessType.NETWORK,
                        mockRequestObject
                    ).assertErrorType(CredentialPresentationError.Unexpected::class)
                }
            }
        }
    }

    @Test
    fun `Request object clientId not matching jwt client_id returns an error`() = runTest {
        coEvery { mockRequestObject.clientId } returns "other client id"

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.Unexpected::class)
    }

    @Test
    fun `Request object jwt missing response_uri claim returns an error`() = runTest {
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            remove("response_uri")
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.Unexpected::class)
    }

    @Test
    fun `Proximity request object jwt missing response_uri claim returns success`() = runTest {
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            remove("response_uri")
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson

        useCase(VerificationProcessType.PROXIMITY, mockRequestObject).assertOk()
    }

    @Test
    fun `Request object jwt with an invalid jwt alg header returns an invalid presentation error`() = runTest {
        every { mockPresentationJwt.algorithm } returns INVALID_JWT_ALGORITHM

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `Request object jwt missing kid header returns an invalid presentation error`(): Unit = runTest {
        every { mockPresentationJwt.keyId } returns null

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `Proximity request object jwt missing kid header returns success`(): Unit = runTest {
        every { mockPresentationJwt.keyId } returns null

        useCase(VerificationProcessType.PROXIMITY, mockRequestObject).assertOk()
    }

    @Test
    fun `Request object jwt that is not yet valid returns an invalid presentation error`() = runTest {
        every { mockPresentationJwt.jwtValidity } returns Validity.NotYetValid(java.time.Instant.now())

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `Request object jwt that is expired returns an invalid presentation error`() = runTest {
        every { mockPresentationJwt.jwtValidity } returns Validity.Expired(java.time.Instant.now())

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `Request object jwt with missing aud claim returns success`() = runTest {
        // payloadJson has no "aud" key since AuthorizationRequest has no aud field
        every { mockPresentationJwt.payloadJson } returns MockPresentationRequest.authorizationRequest.toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `Request object jwt with static discovery aud claim returns success`() = runTest {
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            put("aud", JsonPrimitive("https://self-issued.me/v2"))
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `Request object jwt with other aud claim returns error`() = runTest {
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            put("aud", JsonPrimitive("otherAudience"))
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `ValidatePresentationRequest maps errors from verifying request object signature`(): Unit = runTest {
        coEvery {
            mockVerifyRequestObjectSignature(any(), any())
        } returns Err(VcSdJwtError.InvalidJwt)

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `DID_PATH verification outcome results in null verifierAttestationTrusted`() = runTest {
        coEvery { mockVerifyRequestObjectSignature(any(), any()) } returns Ok(RequestObjectVerificationOutcome.DID_PATH)

        val result = useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
        assertNull(result.verifierAttestationTrusted)
    }

    @Test
    fun `ATTESTATION_UNTRUSTED verification outcome over network returns an UnknownVerifier error`() = runTest {
        coEvery {
            mockVerifyRequestObjectSignature(any(), any())
        } returns Ok(RequestObjectVerificationOutcome.ATTESTATION_UNTRUSTED)

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.UnknownVerifier::class)
    }

    @Test
    fun `ATTESTATION_UNTRUSTED verification outcome over proximity returns success with verifierAttestationTrusted = false`() = runTest {
        coEvery {
            mockVerifyRequestObjectSignature(any(), any())
        } returns Ok(RequestObjectVerificationOutcome.ATTESTATION_UNTRUSTED)

        val result = useCase(VerificationProcessType.PROXIMITY, mockRequestObject).assertOk()
        assertEquals(false, result.verifierAttestationTrusted)
    }

    @Test
    fun `verifier_attestation client_id over network returns an InvalidRequest error`() = runTest {
        val attestationClientId = "verifier_attestation:verifier.example.org"
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            put("client_id", JsonPrimitive(attestationClientId))
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson
        coEvery { mockRequestObject.clientId } returns attestationClientId

        useCase(VerificationProcessType.NETWORK, mockRequestObject)
            .assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `verifier_attestation client_id over proximity is still accepted`() = runTest {
        val attestationClientId = "verifier_attestation:verifier.example.org"
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            put("client_id", JsonPrimitive(attestationClientId))
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson
        coEvery { mockRequestObject.clientId } returns attestationClientId
        coEvery {
            mockVerifyRequestObjectSignature(any(), any())
        } returns Ok(RequestObjectVerificationOutcome.ATTESTATION_TRUSTED)

        val result = useCase(VerificationProcessType.PROXIMITY, mockRequestObject).assertOk()
        assertEquals(true, result.verifierAttestationTrusted)
    }

    @Test
    fun `Disabled request object signature verification results in null verifierAttestationTrusted`() = runTest {
        every { mockEnvironmentSetupRepository.verifyRequestObjectSignature } returns false

        val result = useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
        assertNull(result.verifierAttestationTrusted)
    }

    @Test
    fun `Request object jwt containing an authorization request with the transaction_data field returns an error`() = runTest {
        val payloadJson = MockPresentationRequest.authorizationRequest.toJsonObject().toMutableMap().apply {
            put("transaction_data", JsonPrimitive("data"))
        }.let { JsonObject(it) }
        every { mockPresentationJwt.payloadJson } returns payloadJson

        useCase(
            VerificationProcessType.NETWORK,
            mockRequestObject
        ).assertErrorType(CredentialPresentationError.InvalidTransactionData::class)
    }

    @Test
    fun `Request object jwt containing an invalid authorization request returns an error`() = runTest {
        every { mockPresentationJwt.payloadJson } returns JsonObject(mapOf("invalid" to JsonPrimitive("data")))

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.Unexpected::class)
    }

    // authorization request validation
    @Test
    fun `Authorization request with an invalid response_type (something else than 'vp_token') returns an invalid presentation error`() =
        runTest {
            val presentationJson = MockPresentationRequest.authorizationRequest
                .copy(responseType = INVALID_RESPONSE_TYPE)
                .toJsonObject()

            every { mockPresentationJwt.payloadJson } returns presentationJson

            useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
        }

    @Test
    fun `Authorization request with an invalid response_mode returns an invalid presentation error`() =
        runTest {
            val presentationJson = MockPresentationRequest.authorizationRequest
                .copy(responseMode = INVALID_RESPONSE_MODE)
                .toJsonObject()
            every { mockPresentationJwt.payloadJson } returns presentationJson

            useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
        }

    @Test
    fun `Authorization request with response_mode 'direct_post(dot)jwt' but missing client metadata returns an invalid presentation error`() =
        runTest {
            val presentationJson = MockPresentationRequest.authorizationRequestDirectPostJwt
                .copy(clientMetaData = null)
                .toJsonObject()
            every { mockPresentationJwt.payloadJson } returns presentationJson

            useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
        }

    @Test
    fun `Authorization request with response_mode 'direct_post(dot)jwt' and client metadata returns success`() = runTest {
        every {
            mockPresentationJwt.payloadJson
        } returns MockPresentationRequest.authorizationRequestDirectPostJwt.toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `Authorization request with empty DCQL query claims returns an invalid presentation error`(): Unit = runTest {
        every {
            mockPresentationJwt.payloadJson
        } returns MockPresentationRequest.invalidPresentationRequestClaims().toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `Authorization request with missing presentation definition and missing DCQL query returns an invalid presentation error`(): Unit =
        runTest {
            every {
                mockPresentationJwt.payloadJson
            } returns MockPresentationRequest.invalidPresentationRequestPresentationRequestDCQL().toJsonObject()

            useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
        }

    @Test
    fun `DCQL Authorization request using holder binding and not containing state returns success`(): Unit = runTest {
        every {
            mockPresentationJwt.payloadJson
        } returns MockPresentationRequest.authorizationRequestDCQL.toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `DCQL Authorization request using holder binding and containing state returns success`(): Unit = runTest {
        every {
            mockPresentationJwt.payloadJson
        } returns MockPresentationRequest.authorizationRequestDCQLHolderBindingAndState.toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    @Test
    fun `DCQL Authorization request not using holder binding and missing state returns an invalid presentation error`(): Unit = runTest {
        every {
            mockPresentationJwt.payloadJson
        } returns MockPresentationRequest.invalidDCQLPresentationRequestState().toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertErrorType(CredentialPresentationError.InvalidRequest::class)
    }

    @Test
    fun `DCQL Authorization request not using holder binding and containing state returns success`(): Unit = runTest {
        every {
            mockPresentationJwt.payloadJson
        } returns MockPresentationRequest.authorizationRequestDCQLNoHolderBinding.toJsonObject()

        useCase(VerificationProcessType.NETWORK, mockRequestObject).assertOk()
    }

    private fun setupDefaultMocks() {
        coEvery { mockRequestObject.jwt } returns mockPresentationJwt
        coEvery { mockRequestObject.clientId } returns CLIENT_ID

        every { mockPresentationJwt.payloadJson } returns MockPresentationRequest.authorizationRequest.toJsonObject()
        every { mockPresentationJwt.algorithm } returns SigningAlgorithm.ES256.stdName
        every { mockPresentationJwt.keyId } returns "keyId"
        every { mockPresentationJwt.jwtValidity } returns Validity.Valid
        every { mockPresentationJwt.type } returns "oauth-authz-req+jwt"

        coEvery { mockEnvironmentSetupRepository.attestationsServiceTrustedDids } returns emptyList()
        every { mockEnvironmentSetupRepository.verifyRequestObjectSignature } returns true

        coEvery {
            mockVerifyRequestObjectSignature(any(), any())
        } returns Ok(RequestObjectVerificationOutcome.DID_PATH)
    }

    private fun AuthorizationRequest.toJsonObject(): JsonObject =
        testSafeJson.json.encodeToJsonElement(value = this).jsonObject

    private fun authorizationRequestWithZkPolicy(
        circuitId: String = "swiyu_age18_status_2k",
        mutation: MutableMap<String, JsonElement>.() -> Unit = {},
    ): JsonObject {
        val payload = MockPresentationRequest.authorizationRequest.toJsonObject()
        val dcqlQuery = payload.getValue("dcql_query").jsonObject
        val credentials = dcqlQuery.getValue("credentials").jsonArray
        val credential = credentials.first().jsonObject.toMutableMap().apply {
            put("format", JsonPrimitive("dc+sd-jwt"))
            put("multiple", JsonPrimitive(false))
            put("require_cryptographic_holder_binding", JsonPrimitive(true))
            put("claims", JsonArray(listOf(buildJsonObject {
                put("id", "birthdate")
                put("path", JsonArray(listOf(JsonPrimitive("birthdate"))))
            })))
            put("x_swiyu_zkp", buildJsonObject {
                put("profile", "swiyu-age18-status-2k-v0")
                put("circuit_id", circuitId)
                put("cutoff_date", "2008-08-20")
                put("status_list_snapshot", "snapshot-2026-08-20")
                put("current_time", 1787184000L)
            })
            mutation()
        }.let(::JsonObject)
        val dcqlWithPolicy = dcqlQuery.toMutableMap().apply {
            put("credentials", JsonArray(listOf(credential)))
        }.let(::JsonObject)

        return payload.toMutableMap().apply {
            put("dcql_query", dcqlWithPolicy)
        }.let(::JsonObject)
    }

    private companion object {
        const val INVALID_RESPONSE_TYPE = "invalid response_type"
        const val INVALID_RESPONSE_MODE = "invalid response_mode"
        const val INVALID_JWT_ALGORITHM = "HS256"
    }
}
