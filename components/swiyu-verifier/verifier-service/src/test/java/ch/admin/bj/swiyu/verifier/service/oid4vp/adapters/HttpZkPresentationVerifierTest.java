package ch.admin.bj.swiyu.verifier.service.oid4vp.adapters;

import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.common.config.ZkVerifierSidecarProperties;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationException;
import ch.admin.bj.swiyu.verifier.domain.management.ConfigurationOverride;
import ch.admin.bj.swiyu.verifier.domain.management.Management;
import ch.admin.bj.swiyu.verifier.domain.management.TrustAnchor;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlClaim;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredential;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredentialMeta;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Proxy;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpZkPresentationVerifierTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private ZkVerifierSidecarProperties properties;
    private ApplicationProperties applicationProperties;
    private Management management;
    private DcqlCredential credential;
    private long policyCurrentTime;

    @BeforeEach
    void setUp() {
        properties = new ZkVerifierSidecarProperties();
        properties.setEndpoint("http://127.0.0.1:7788/v1/verify");
        properties.setTimeout(Duration.ofSeconds(2));

        applicationProperties = new ApplicationProperties();
        applicationProperties.setExternalUrl("https://default.example");
        applicationProperties.setClientId("default-verifier");
        applicationProperties.setClientIdPrefix("did");

        management = mock(Management.class);
        var managementId = UUID.fromString("8c8ad4f0-5153-4e69-b02c-6c49af46c616");
        when(management.getId()).thenReturn(managementId);
        when(management.getRequestNonce()).thenReturn("server-nonce");
        when(management.getOauthState()).thenReturn("server-state");
        when(management.getConfigurationOverride()).thenReturn(ConfigurationOverride.builder()
                .externalUrl("https://session.example")
                .verifierDid("session-verifier")
                .build());
        when(management.getAcceptedIssuerDids()).thenReturn(List.of("did:example:issuer"));
        when(management.getTrustAnchors()).thenReturn(List.of(
                new TrustAnchor("did:example:anchor", "https://trust.example")));

        policyCurrentTime = Instant.now().getEpochSecond();
        var policy = new ZkPresentationPolicy(
                "swiyu-age18-status-2k-v0",
                "swiyu_age18_status_2k",
                "2008-07-15",
                "snapshot-2026-07-15",
                policyCurrentTime);
        credential = new DcqlCredential(
                "age-query",
                "dc+sd-jwt",
                new DcqlCredentialMeta(null, List.of("urn:example:identity"), null),
                List.of(new DcqlClaim("birthdate", List.of("birthdate"), null)),
                true,
                false,
                policy);
    }

    @Test
    void verify_sendsExactEnvelopeAndOnlyServerDerivedExpectedContext() throws Exception {
        var capturedBody = new AtomicReference<String>();
        HttpZkPresentationVerifier.SidecarTransport transport = (endpoint, body, timeout) -> {
            assertEquals("http://127.0.0.1:7788/v1/verify", endpoint.toString());
            assertEquals(Duration.ofSeconds(2), timeout);
            capturedBody.set(body);
            return new HttpZkPresentationVerifier.SidecarHttpResponse(200, validResponse());
        };
        var verifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, transport);

        var result = verifier.verify("opaque-proof-envelope", management, credential);

        assertTrue(result.predicateSatisfied());
        assertTrue(result.statusValid());
        var request = objectMapper.readTree(capturedBody.get());
        assertEquals("opaque-proof-envelope", request.path("proof_envelope").asText());
        var expected = request.path("expected");
        assertEquals("server-nonce", expected.path("nonce").asText());
        assertEquals("did:session-verifier", expected.path("client_id").asText());
        assertEquals("https://session.example/oid4vp/api/request-object/"
                        + "8c8ad4f0-5153-4e69-b02c-6c49af46c616/response-data",
                expected.path("response_uri").asText());
        assertEquals("server-state", expected.path("state").asText());
        assertEquals("age-query", expected.path("query_id").asText());
        assertEquals("swiyu-age18-status-2k-v0", expected.path("profile").asText());
        assertEquals("swiyu_age18_status_2k", expected.path("circuit_id").asText());
        assertEquals("2008-07-15", expected.path("cutoff_date").asText());
        assertEquals(policyCurrentTime, expected.path("current_time").asLong());
        assertEquals("snapshot-2026-07-15", expected.path("status_list_snapshot").asText());
        assertEquals("urn:example:identity", expected.path("vct_values").get(0).asText());
        assertEquals("did:example:issuer", expected.path("accepted_issuer_dids").get(0).asText());
        assertFalse(expected.has("predicate_satisfied"));
        assertFalse(expected.has("status_valid"));
    }

    @Test
    void verify_rejectsSidecarNegativeResult() {
        HttpZkPresentationVerifier.SidecarTransport transport = (endpoint, body, timeout) ->
                new HttpZkPresentationVerifier.SidecarHttpResponse(200,
                        "{\"verified\":false}");
        var verifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, transport);

        assertThrows(VerificationException.class,
                () -> verifier.verify("opaque-proof-envelope", management, credential));
    }

    @Test
    void verify_rejectsSidecarTransportError() {
        HttpZkPresentationVerifier.SidecarTransport transport = (endpoint, body, timeout) -> {
            throw new IOException("sidecar unavailable");
        };
        var verifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, transport);

        assertThrows(VerificationException.class,
                () -> verifier.verify("opaque-proof-envelope", management, credential));
    }

    @Test
    void verify_rejectsNonLoopbackOrMissingEndpointBeforeTransport() {
        var transportCalled = new AtomicBoolean(false);
        HttpZkPresentationVerifier.SidecarTransport transport = (endpoint, body, timeout) -> {
            transportCalled.set(true);
            return new HttpZkPresentationVerifier.SidecarHttpResponse(200, validResponse());
        };
        var verifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, transport);

        properties.setEndpoint("https://proof.example/v1/verify");
        assertThrows(VerificationException.class,
                () -> verifier.verify("opaque-proof-envelope", management, credential));
        properties.setEndpoint(null);
        assertThrows(VerificationException.class,
                () -> verifier.verify("opaque-proof-envelope", management, credential));
        assertFalse(transportCalled.get());
    }

    @Test
    void verify_rejectsPolicyTimeThatAgedAfterRequestCreation() {
        var transportCalled = new AtomicBoolean(false);
        HttpZkPresentationVerifier.SidecarTransport transport = (endpoint, body, timeout) -> {
            transportCalled.set(true);
            return new HttpZkPresentationVerifier.SidecarHttpResponse(200, validResponse());
        };
        var stalePolicy = new ZkPresentationPolicy(
                "swiyu-age18-status-2k-v0",
                "swiyu_age18_status_2k",
                "2008-07-15",
                "snapshot-2026-07-15",
                policyCurrentTime - 301);
        credential.setZkPresentationPolicy(stalePolicy);
        var verifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, transport);

        assertThrows(VerificationException.class,
                () -> verifier.verify("opaque-proof-envelope", management, credential));
        assertFalse(transportCalled.get());
    }

    @Test
    void verify_rejectsMalformedOrOversizedResponse() {
        HttpZkPresentationVerifier.SidecarTransport malformed = (endpoint, body, timeout) ->
                new HttpZkPresentationVerifier.SidecarHttpResponse(200, "not-json");
        var malformedVerifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, malformed);
        assertThrows(VerificationException.class,
                () -> malformedVerifier.verify("opaque-proof-envelope", management, credential));

        properties.setMaxResponseBytes(1_024);
        HttpZkPresentationVerifier.SidecarTransport oversized = (endpoint, body, timeout) ->
                new HttpZkPresentationVerifier.SidecarHttpResponse(200, "x".repeat(1_025));
        var oversizedVerifier = new HttpZkPresentationVerifier(
                properties, applicationProperties, objectMapper, oversized);
        assertThrows(VerificationException.class,
                () -> oversizedVerifier.verify("opaque-proof-envelope", management, credential));
    }

    @Test
    void verify_rejectsUnknownDuplicateTrailingOrCoercedResponseJson() {
        var permissiveApplicationMapper = new ObjectMapper().rebuild()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .build();
        var invalidResponses = List.of(
                validResponse().replace(
                        "\"status_list_snapshot\": \"snapshot-2026-07-15\"",
                        "\"status_list_snapshot\": \"snapshot-2026-07-15\", \"unexpected\": true"),
                validResponse().replace(
                        "\"verified\": true",
                        "\"verified\": false, \"verified\": true"),
                validResponse() + "{}",
                validResponse().replace("\"verified\": true", "\"verified\": \"true\"")
        );

        for (var response : invalidResponses) {
            HttpZkPresentationVerifier.SidecarTransport transport = (endpoint, body, timeout) ->
                    new HttpZkPresentationVerifier.SidecarHttpResponse(200, response);
            var verifier = new HttpZkPresentationVerifier(
                    properties, applicationProperties, permissiveApplicationMapper, transport);

            assertThrows(VerificationException.class,
                    () -> verifier.verify("opaque-proof-envelope", management, credential));
        }
    }

    @Test
    void jdkTransportForcesDirectConnections() {
        var client = HttpZkPresentationVerifier.buildDirectHttpClient(Duration.ofSeconds(2));
        var proxySelector = client.proxy().orElseThrow();

        assertEquals(List.of(Proxy.NO_PROXY),
                proxySelector.select(URI.create("http://127.0.0.1:7788/v1/verify")));
    }

    @Test
    void limitedSubscriberAcceptsExactLimitAndCancelsBeforeOverflow() {
        var accepted = new HttpZkPresentationVerifier.LimitedUtf8BodySubscriber(4);
        var acceptedCancelled = new AtomicBoolean(false);
        accepted.onSubscribe(subscription(acceptedCancelled));
        accepted.onNext(List.of(ByteBuffer.wrap("test".getBytes(StandardCharsets.UTF_8))));
        accepted.onComplete();

        assertEquals("test", accepted.getBody().toCompletableFuture().join());
        assertFalse(acceptedCancelled.get());

        var rejected = new HttpZkPresentationVerifier.LimitedUtf8BodySubscriber(4);
        var rejectedCancelled = new AtomicBoolean(false);
        rejected.onSubscribe(subscription(rejectedCancelled));
        rejected.onNext(List.of(ByteBuffer.wrap(new byte[5])));

        assertTrue(rejectedCancelled.get());
        assertThrows(CompletionException.class,
                () -> rejected.getBody().toCompletableFuture().join());
    }

    @Test
    void limitedSubscriberRejectsMalformedUtf8() {
        var subscriber = new HttpZkPresentationVerifier.LimitedUtf8BodySubscriber(2);
        subscriber.onSubscribe(subscription(new AtomicBoolean(false)));
        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[]{(byte) 0xc3, 0x28})));
        subscriber.onComplete();

        assertThrows(CompletionException.class,
                () -> subscriber.getBody().toCompletableFuture().join());
    }

    private static Flow.Subscription subscription(AtomicBoolean cancelled) {
        return new Flow.Subscription() {
            @Override
            public void request(long count) {
                // The focused subscriber test pushes batches explicitly.
            }

            @Override
            public void cancel() {
                cancelled.set(true);
            }
        };
    }

    private static String validResponse() {
        return """
                {
                  "verified": true,
                  "profile": "swiyu-age18-status-2k-v0",
                  "circuit_id": "swiyu_age18_status_2k",
                  "predicate_satisfied": true,
                  "status_valid": true,
                  "status_list_snapshot": "snapshot-2026-07-15"
                }
                """;
    }
}
