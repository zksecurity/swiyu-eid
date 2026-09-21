package ch.admin.bj.swiyu.verifier.infrastructure.web.oid4vp;

import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategy;
import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.common.config.HSMProperties;
import ch.admin.bj.swiyu.verifier.common.config.WebhookProperties;
import ch.admin.bj.swiyu.verifier.common.config.ZkVerifierSidecarProperties;
import ch.admin.bj.swiyu.verifier.common.exception.ProcessClosedException;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationException;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationNotFoundException;
import ch.admin.bj.swiyu.verifier.domain.SdJwt;
import ch.admin.bj.swiyu.verifier.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.verifier.domain.management.Management;
import ch.admin.bj.swiyu.verifier.domain.management.ManagementRepository;
import ch.admin.bj.swiyu.verifier.domain.management.VerificationStatus;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlClaim;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredentialMeta;
import ch.admin.bj.swiyu.verifier.dto.ApiErrorDto;
import ch.admin.bj.swiyu.verifier.dto.VerificationPresentationUnionDto;
import ch.admin.bj.swiyu.verifier.dto.management.CreateVerificationManagementDto;
import ch.admin.bj.swiyu.verifier.infrastructure.web.DefaultExceptionHandler;
import ch.admin.bj.swiyu.verifier.infrastructure.web.management.VerifierManagementController;
import ch.admin.bj.swiyu.verifier.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.verifier.service.JwtSigningService;
import ch.admin.bj.swiyu.verifier.service.OpenIdClientMetadataConfiguration;
import ch.admin.bj.swiyu.verifier.service.callback.CallbackEventProducer;
import ch.admin.bj.swiyu.verifier.service.management.ManagementService;
import ch.admin.bj.swiyu.verifier.service.management.ManagementTransactionalService;
import ch.admin.bj.swiyu.verifier.service.oid4vp.DcqlPresentationVerificationService;
import ch.admin.bj.swiyu.verifier.service.oid4vp.JweDecryptionService;
import ch.admin.bj.swiyu.verifier.service.oid4vp.MetadataService;
import ch.admin.bj.swiyu.verifier.service.oid4vp.PresentationResponseResolver;
import ch.admin.bj.swiyu.verifier.service.oid4vp.PresentationVerificationUsecase;
import ch.admin.bj.swiyu.verifier.service.oid4vp.RequestObjectService;
import ch.admin.bj.swiyu.verifier.service.oid4vp.VerificationMapper;
import ch.admin.bj.swiyu.verifier.service.oid4vp.adapters.HttpZkPresentationVerifier;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.DcqlEvaluator;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.PresentationVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proof-independent transport harness over production OID4VP + {@link HttpZkPresentationVerifier}.
 * Persistence is an in-memory {@link ManagementRepository} (repository port only).
 * Management HTTP is a thin adapter over production {@link ManagementService} /
 * {@link VerifierManagementController}; presentation uses production {@link VerificationController}.
 */
class TranscriptTransportHarnessIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SIGNING_KEY = """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIGYpEuy/ijtVu+QOIsmXiK9HNPQ0bkBX+wvhaFAh/zoKoAoGCCqGSM49
            AwEHoUQDQgAEoqBwmYd3RAHs+sFe/U7UFTXbkWmPAaqKTHCvsV8tvxWeng+OkMo1
            8QOT2rDNk+qMBrCJnyyiRU6jMdH4q3z1Pg==
            -----END EC PRIVATE KEY-----
            """;
    private static final String SNAPSHOT = "snapshot-transcript-harness";
    private static final String ENVELOPE = "{\"schema\":\"swiyu-zkp-envelope-v1\",\"proof\":\"opaque-transport\"}";
    private static final String EPFL_ISSUER_X =
            "e14492964d758e7de59e3adade4b3337cdc112e8bd37933c3769a2feb2d44de8";
    private static final String EPFL_ISSUER_Y =
            "abb82c578d7685444f97c9e59070e65a1810b4a5d82135f8a3c5994dbf39d884";

    @Test
    void rejectingSidecarIsCalledAndVerificationFails() throws Exception {
        try (var sidecar = SidecarStub.rejecting();
             var harness = Harness.start(0, sidecar.uri(), null)) {
            var id = createVerification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            var post = postResponse(harness.baseUri(), id, state, ENVELOPE);
            assertEquals(400, post.statusCode());
            assertTrue(sidecar.posts.get() >= 1, "HttpZkPresentationVerifier must POST the loopback sidecar");
            var captured = JSON.readTree(sidecar.lastBody.get(0));
            assertEquals(ENVELOPE, captured.path("proof_envelope").asText());
            assertEquals("age", captured.path("expected").path("query_id").asText());
            var mgmt = getManagement(harness.baseUri(), id);
            assertEquals("FAILED", mgmt.path("state").asText());
        }
    }

    @Test
    void missingStateRejectedAndReplayRejected() throws Exception {
        try (var sidecar = SidecarStub.rejecting();
             var harness = Harness.start(0, sidecar.uri(), null)) {
            var id = createVerification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            var missing = postResponse(harness.baseUri(), id, null, ENVELOPE);
            assertTrue(missing.statusCode() >= 400);
            assertEquals(0, sidecar.posts.get());
            assertEquals("PENDING", getManagement(harness.baseUri(), id).path("state").asText());

            var first = postResponse(harness.baseUri(), id, state, ENVELOPE);
            assertEquals(400, first.statusCode());
            var replay = postResponse(harness.baseUri(), id, state, ENVELOPE);
            assertEquals(410, replay.statusCode());
            assertEquals("FAILED", getManagement(harness.baseUri(), id).path("state").asText());
        }
    }

    @Test
    void acceptingSidecarYieldsSuccessWalletResponseWithoutBirthdate() throws Exception {
        try (var sidecar = SidecarStub.accepting();
             var harness = Harness.start(0, sidecar.uri(), null)) {
            var id = createVerification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            assertEquals(3, jwt.split("\\.").length);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            var post = postResponse(harness.baseUri(), id, state, ENVELOPE);
            assertEquals(200, post.statusCode());
            var mgmt = getManagement(harness.baseUri(), id);
            assertEquals("SUCCESS", mgmt.path("state").asText());
            var wallet = mgmt.path("wallet_response").path("credential_subject_data").toString();
            assertTrue(wallet.contains("predicate_satisfied"));
            assertFalse(wallet.contains("birthdate"));
            assertTrue(sidecar.lastBody.getFirst().contains("\"proof_envelope\""));
        }
    }

    @Test
    void nativeVerificationMayTakeMoreThanTenSeconds() throws Exception {
        try (var sidecar = SidecarStub.accepting(); var harness = Harness.start(0, sidecar.uri(), null)) {
            sidecar.delayMillis = 11_000;
            var id = createVerification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            assertEquals(200, postResponse(harness.baseUri(), id, state, ENVELOPE).statusCode());
            assertEquals("SUCCESS", getManagement(harness.baseUri(), id).path("state").asText());
        }
    }

    @Test
    void epflProfileRoutesToSidecarWithServerDerivedChallenge() throws Exception {
        try (var sidecar = SidecarStub.acceptingEpfl();
             var harness = Harness.start(0, sidecar.uri(), null)) {
            var id = createEpflVerification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            var post = postResponse(harness.baseUri(), id, state, ENVELOPE, "birth_date");
            assertEquals(200, post.statusCode());
            assertTrue(sidecar.posts.get() >= 1);
            var captured = JSON.readTree(sidecar.lastBody.getFirst());
            var expected = captured.path("expected");
            assertEquals("birth_date", expected.path("query_id").asText());
            assertEquals(20240101, expected.path("now_date").asInt());
            assertEquals(64, expected.path("challenge_nonce").asText().length());
            assertFalse(expected.has("status_list_snapshot"));
            assertEquals("SUCCESS", getManagement(harness.baseUri(), id).path("state").asText());
        }
    }

    @Test
    void openAcAge25ProfileRoutesToSidecarWithNowDateAndNoStatus() throws Exception {
        try (var sidecar = SidecarStub.acceptingEpfl();
             var harness = Harness.start(0, sidecar.uri(), null)) {
            var id = createOpenAcAge25Verification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            var post = postResponse(harness.baseUri(), id, state, ENVELOPE, "birth_date");
            assertEquals(200, post.statusCode());
            assertTrue(sidecar.posts.get() >= 1);
            var captured = JSON.readTree(sidecar.lastBody.getFirst());
            var expected = captured.path("expected");
            assertEquals("birth_date", expected.path("query_id").asText());
            assertEquals("openac-age25-jwt-v0", expected.path("profile").asText());
            assertEquals("swiyu_age25_jwt", expected.path("circuit_id").asText());
            assertEquals(20240101, expected.path("now_date").asInt());
            assertFalse(expected.has("status_list_snapshot"));
            assertFalse(expected.has("cutoff_date"));
            assertFalse(expected.has("challenge_nonce"));
            assertEquals("SUCCESS", getManagement(harness.baseUri(), id).path("state").asText());
        }
    }

    @Test
    void epflWrongNonceRejectedBySidecar() throws Exception {
        try (var sidecar = SidecarStub.rejectingEpfl();
             var harness = Harness.start(0, sidecar.uri(), null)) {
            var id = createEpflVerification(harness.baseUri());
            var jwt = fetchSignedRequestObject(harness.baseUri(), id);
            var state = SignedJWT.parse(jwt).getJWTClaimsSet().getStringClaim("state");
            assertEquals(400, postResponse(harness.baseUri(), id, state, ENVELOPE, "birth_date").statusCode());
            assertEquals("FAILED", getManagement(harness.baseUri(), id).path("state").asText());
        }
    }

    @Test
    void explicitStopFileConsumesOneArgument() throws Exception {
        Path directory = Files.createTempDirectory("swiyu-transcript-stop-test-");
        Path stop = directory.resolve("stop");
        Path ready = directory.resolve("ready.json");
        Files.writeString(stop, "stop");
        try {
            main(new String[]{"--port", "0", "--sidecar", "http://127.0.0.1:9999/verify",
                    "--ready-file", ready.toString(), "--stop-file", stop.toString()});
            assertTrue(Files.exists(ready));
        } finally {
            Files.deleteIfExists(ready);
            Files.deleteIfExists(stop);
            Files.deleteIfExists(directory);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 0;
        String sidecar = null;
        Path readyFile = null;
        Path stopFile = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port" -> port = Integer.parseInt(args[++i]);
                case "--sidecar" -> sidecar = args[++i];
                case "--ready-file" -> readyFile = Path.of(args[++i]);
                case "--stop-file" -> stopFile = Path.of(args[++i]);
                default -> throw new IllegalArgumentException("Unknown argument: " + args[i]);
            }
        }
        if (sidecar == null || sidecar.isBlank()) {
            throw new IllegalArgumentException("--sidecar http://127.0.0.1:PORT/verify is required");
        }
        URI sidecarUri = URI.create(sidecar);
        String host = sidecarUri.getHost();
        if (!"http".equalsIgnoreCase(sidecarUri.getScheme())
                || host == null
                || !("127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host))) {
            throw new IllegalArgumentException("sidecar must be an http loopback URL");
        }
        if (stopFile == null && readyFile != null) {
            stopFile = readyFile.resolveSibling(readyFile.getFileName() + ".stop");
        }
        if (stopFile == null) {
            stopFile = Path.of(System.getProperty("java.io.tmpdir"),
                    "swiyu-transcript-java-harness-" + ProcessHandle.current().pid() + ".stop");
        }
        try (var harness = Harness.start(port, URI.create(sidecar), readyFile)) {
            System.out.println("transcript-java-harness listening on " + harness.baseUri()
                    + " sidecar=" + sidecar + " stop-file=" + stopFile.toAbsolutePath());
            while (!Files.exists(stopFile)) {
                Thread.sleep(200);
            }
        }
    }

    private static UUID createEpflVerification(URI base) throws Exception {
        String body = """
                {
                  "accepted_issuer_dids": ["did:example:epfl-test-issuer"],
                  "jwt_secured_authorization_request": true,
                  "response_mode": "direct_post",
                  "dcql_query": {
                    "credentials": [{
                      "id": "birth_date",
                      "format": "dc+sd-jwt",
                      "meta": {"vct_values": ["https://example.ch/vct/epfl-d10-test"]},
                      "require_cryptographic_holder_binding": true,
                      "claims": [{"id": "birth_date", "path": ["birth_date"]}],
                      "x_swiyu_zkp": {
                        "profile": "epfl-d10-swiyu-jwt-age25-v0",
                        "circuit_id": "d10_swiyu_jwt",
                        "now_date": 20240101,
                        "issuer_pub_x": "%s",
                        "issuer_pub_y": "%s"
                      }
                    }]
                  }
                }
                """.formatted(EPFL_ISSUER_X, EPFL_ISSUER_Y);
        var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/management/api/verifications"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return UUID.fromString(JSON.readTree(response.body()).path("id").asText());
    }

    private static UUID createOpenAcAge25Verification(URI base) throws Exception {
        String body = """
                {
                  "accepted_issuer_dids": ["did:example:epfl-test-issuer"],
                  "jwt_secured_authorization_request": true,
                  "response_mode": "direct_post",
                  "dcql_query": {
                    "credentials": [{
                      "id": "birth_date",
                      "format": "dc+sd-jwt",
                      "meta": {"vct_values": ["https://example.ch/vct/epfl-d10-test"]},
                      "require_cryptographic_holder_binding": true,
                      "claims": [{"id": "birth_date", "path": ["birth_date"]}],
                      "x_swiyu_zkp": {
                        "profile": "openac-age25-jwt-v0",
                        "circuit_id": "swiyu_age25_jwt",
                        "now_date": 20240101
                      }
                    }]
                  }
                }
                """;
        var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/management/api/verifications"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return UUID.fromString(JSON.readTree(response.body()).path("id").asText());
    }

    private static UUID createVerification(URI base) throws Exception {
        long now = Instant.now().getEpochSecond();
        String body = """
                {
                  "accepted_issuer_dids": ["did:example:issuer"],
                  "jwt_secured_authorization_request": true,
                  "response_mode": "direct_post",
                  "dcql_query": {
                    "credentials": [{
                      "id": "age",
                      "format": "dc+sd-jwt",
                      "meta": {"vct_values": ["urn:example:identity"]},
                      "require_cryptographic_holder_binding": true,
                      "claims": [{"id": "birthdate", "path": ["birthdate"]}],
                      "x_swiyu_zkp": {
                        "profile": "swiyu-age18-status-2k-v0",
                        "circuit_id": "swiyu_age18_status_2k",
                        "cutoff_date": "2008-08-20",
                        "status_list_snapshot": "%s",
                        "current_time": %d
                      }
                    }]
                  }
                }
                """.formatted(SNAPSHOT, now);
        var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/management/api/verifications"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return UUID.fromString(JSON.readTree(response.body()).path("id").asText());
    }

    private static String fetchSignedRequestObject(URI base, UUID id) throws Exception {
        var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/oid4vp/api/request-object/" + id))
                        .timeout(Duration.ofSeconds(30))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.headers().firstValue("Date").isPresent());
        return response.body();
    }

    private static HttpResponse<String> postResponse(URI base, UUID id, String state, String envelope)
            throws Exception {
        return postResponse(base, id, state, envelope, "age");
    }

    private static HttpResponse<String> postResponse(
            URI base, UUID id, String state, String envelope, String credentialId
    ) throws Exception {
        var vpToken = JSON.writeValueAsString(Map.of(credentialId, List.of(envelope)));
        var form = new StringBuilder();
        if (state != null) {
            form.append("state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8)).append('&');
        }
        form.append("vp_token=").append(URLEncoder.encode(vpToken, StandardCharsets.UTF_8));
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/oid4vp/api/request-object/" + id + "/response-data"))
                        .timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static JsonNode getManagement(URI base, UUID id) throws Exception {
        var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/management/api/verifications/" + id))
                        .timeout(Duration.ofSeconds(30))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return JSON.readTree(response.body());
    }

    static final class SidecarStub implements AutoCloseable {
        private final HttpServer server;
        private final boolean accept;
        volatile long delayMillis = 0;
        final AtomicInteger posts = new AtomicInteger();
        final List<String> lastBody = new ArrayList<>();

        static SidecarStub rejecting() throws IOException {
            return new SidecarStub(false, false);
        }

        static SidecarStub accepting() throws IOException {
            return new SidecarStub(true, false);
        }

        static SidecarStub acceptingEpfl() throws IOException {
            return new SidecarStub(true, true);
        }

        static SidecarStub rejectingEpfl() throws IOException {
            return new SidecarStub(false, true);
        }

        private final boolean epfl;

        private SidecarStub(boolean accept, boolean epfl) throws IOException {
            this.accept = accept;
            this.epfl = epfl;
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/verify", this::handle);
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
        }

        URI uri() {
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/verify");
        }

        private void handle(HttpExchange exchange) throws IOException {
            posts.incrementAndGet();
            try { Thread.sleep(delayMillis); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            lastBody.add(body);
            String response;
            if (accept) {
                var expected = JSON.readTree(body).path("expected");
                String profile = expected.path("profile").asText();
                if (epfl || profile.startsWith("epfl-") || "openac-age25-jwt-v0".equals(profile)) {
                    response = """
                            {"verified":true,"profile":"%s","circuit_id":"%s","predicate_satisfied":true}
                            """.formatted(
                            expected.path("profile").asText(),
                            expected.path("circuit_id").asText());
                } else {
                    response = """
                            {"verified":true,"profile":"%s","circuit_id":"%s","predicate_satisfied":true,"status_valid":true,"status_list_snapshot":"%s"}
                            """.formatted(
                            expected.path("profile").asText(),
                            expected.path("circuit_id").asText(),
                            expected.path("status_list_snapshot").asText());
                }
            } else {
                response = "{\"verified\":false}";
            }
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    static final class Harness implements AutoCloseable {
        private final HttpServer server;
        private final ApplicationProperties properties;
        final ManagementRepository repository;
        final VerificationController presentationController;
        final VerifierManagementController managementController;
        private final DefaultExceptionHandler errors = new DefaultExceptionHandler();

        static Harness start(int port, URI sidecar, Path readyFile) throws IOException {
            var harness = new Harness(port, sidecar);
            if (readyFile != null) {
                Files.createDirectories(readyFile.toAbsolutePath().getParent());
                Files.writeString(readyFile, """
                        {"port":%d,"base_url":"%s","pid":%d,"sidecar":"%s"}
                        """.formatted(harness.port(), harness.baseUri(), ProcessHandle.current().pid(), sidecar));
            }
            return harness;
        }

        private Harness(int port, URI sidecar) throws IOException {
            this.repository = memoryRepository();
            this.properties = applicationProperties("http://127.0.0.1:0");
            var objectMapper = new ObjectMapper();
            var sidecarProps = new ZkVerifierSidecarProperties();
            sidecarProps.setEndpoint(sidecar.toString());
            // Preserve the production timeout; native verification includes cold key loading.
            var zkVerifier = new HttpZkPresentationVerifier(sidecarProps, properties, objectMapper);

            var webhook = new WebhookProperties();
            var callbacks = new CallbackEventProducer(webhook, callbackRepository());
            var tx = new ManagementTransactionalService(repository, properties);
            var managementService = new ManagementService(properties, tx, Optional.empty());
            this.managementController = new VerifierManagementController(managementService);

            var metadataConfig = new OpenIdClientMetadataConfiguration(
                    properties, objectMapper, Validation.buildDefaultValidatorFactory().getValidator());
            metadataConfig.setClientMetadataResource(clientMetadataResource());
            var metadataService = new MetadataService(metadataConfig, objectMapper);
            var jwtSigning = new JwtSigningService(properties, new JwsSignatureFacade(
                    new JwsSignatureService(
                            new KeyManagementStrategyFactory(Map.of("key", new KeyStrategy())),
                            objectMapper)));
            var requestObjectService = new RequestObjectService(
                    properties, repository, objectMapper, jwtSigning, metadataService, Optional.empty());
            var resolver = new PresentationResponseResolver(new JweDecryptionService(objectMapper, properties));
            var dcql = new DcqlPresentationVerificationService(
                    unusedPresentationVerifier(),
                    unusedDcqlEvaluator(),
                    objectMapper,
                    properties,
                    Optional.of(zkVerifier));
            var usecase = new PresentationVerificationUsecase(callbacks, dcql, managementService);
            this.presentationController = new VerificationController(
                    requestObjectService, resolver, usecase, managementService, metadataService);

            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            server.createContext("/", this::dispatch);
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            properties.setExternalUrl("http://127.0.0.1:" + server.getAddress().getPort());
        }

        URI baseUri() {
            return URI.create("http://127.0.0.1:" + port());
        }

        int port() {
            return server.getAddress().getPort();
        }

        private void dispatch(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod();
                String path = exchange.getRequestURI().getPath();
                if ("POST".equals(method) && "/management/api/verifications".equals(path)) {
                    var dto = JSON.readValue(readBody(exchange), CreateVerificationManagementDto.class);
                    writeJson(exchange, 200, managementController.createVerification(dto));
                    return;
                }
                if ("GET".equals(method) && path.startsWith("/management/api/verifications/")) {
                    UUID id = UUID.fromString(path.substring("/management/api/verifications/".length()));
                    writeJson(exchange, 200, managementController.getVerification(id, null));
                    return;
                }
                if ("GET".equals(method) && path.startsWith("/oid4vp/api/request-object/")
                        && !path.contains("/response-data")) {
                    UUID id = UUID.fromString(path.substring("/oid4vp/api/request-object/".length()));
                    var entity = presentationController.getRequestObject(id);
                    writeBytes(exchange, 200, "application/oauth-authz-req+jwt",
                            String.valueOf(entity.getBody()).getBytes(StandardCharsets.UTF_8));
                    return;
                }
                if ("POST".equals(method) && path.endsWith("/response-data")
                        && path.startsWith("/oid4vp/api/request-object/")) {
                    String idPart = path.substring("/oid4vp/api/request-object/".length(),
                            path.length() - "/response-data".length());
                    if (idPart.endsWith("/")) {
                        idPart = idPart.substring(0, idPart.length() - 1);
                    }
                    UUID id = UUID.fromString(idPart);
                    var form = parseForm(readBody(exchange));
                    var union = new VerificationPresentationUnionDto();
                    union.setState(form.get("state"));
                    union.setVp_token(form.get("vp_token"));
                    String version = header(exchange, "SWIYU-API-Version");
                    writeJson(exchange, 200,
                            presentationController.receiveVerificationPresentation(version, id, union));
                    return;
                }
                writeJson(exchange, 404, ApiErrorDto.builder()
                        .status(org.springframework.http.HttpStatus.NOT_FOUND)
                        .errorDescription("not found")
                        .build());
            } catch (VerificationException e) {
                writeJson(exchange, 400, VerificationMapper.toVerificationErrorResponseDto(e));
            } catch (ProcessClosedException e) {
                writeResponseEntity(exchange, errors.handleProcessAlreadyClosedException(e));
            } catch (VerificationNotFoundException e) {
                writeJson(exchange, 404, ApiErrorDto.builder()
                        .status(org.springframework.http.HttpStatus.NOT_FOUND)
                        .errorDetails(e.getMessage())
                        .build());
            } catch (IllegalArgumentException e) {
                writeResponseEntity(exchange, errors.handleIllegalArgumentException(e));
            } catch (java.util.NoSuchElementException e) {
                writeResponseEntity(exchange, errors.handleNoSuchElementException(e));
            } catch (Exception e) {
                writeJson(exchange, 500, ApiErrorDto.builder()
                        .status(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR)
                        .errorDescription(e.getMessage())
                        .build());
            } finally {
                exchange.close();
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static ApplicationProperties applicationProperties(String externalUrl) {
        var properties = new ApplicationProperties();
        properties.setExternalUrl(externalUrl);
        properties.setClientId("did:example:12345");
        properties.setClientIdPrefix("");
        properties.setDeeplinkSchema("swiyu-verify");
        properties.setSigningKey(SIGNING_KEY);
        properties.setSigningKeyVerificationMethod("did:example:12345#key-1");
        properties.setKeyManagementMethod("key");
        properties.setHsm(new HSMProperties());
        properties.setVerificationTTL(900);
        properties.setMaxVcsAccepted(1);
        properties.setMaxCompressedCipherTextLength(20_971_520);
        properties.setRequestObjectTTLSeconds(600);
        properties.setAcceptedRegistryHosts(List.of("example.com"));
        properties.setTemplateReplacement(Map.of("client-id", "did:example:12345"));
        return properties;
    }

    private static Resource clientMetadataResource() {
        Resource classpath = new ClassPathResource("client_metadata.json");
        if (classpath.exists()) {
            return classpath;
        }
        Path file = Path.of("src/main/resources/client_metadata.json");
        if (Files.exists(file)) {
            return new FileSystemResource(file);
        }
        Path fromModule = Path.of("verifier-application/src/main/resources/client_metadata.json");
        if (Files.exists(fromModule)) {
            return new FileSystemResource(fromModule);
        }
        throw new IllegalStateException("client_metadata.json not found on classpath or disk");
    }

    private static ManagementRepository memoryRepository() {
        var store = new ConcurrentHashMap<UUID, Management>();
        InvocationHandler handler = (proxy, method, args) -> invokeRepo(store, method, args, proxy);
        return (ManagementRepository) Proxy.newProxyInstance(
                ManagementRepository.class.getClassLoader(),
                new Class<?>[]{ManagementRepository.class},
                handler);
    }

    private static Object invokeRepo(ConcurrentHashMap<UUID, Management> store, Method method, Object[] args, Object proxy) {
        if (method.getDeclaringClass() == Object.class) {
            return switch (method.getName()) {
                case "toString" -> "InMemoryManagementRepository";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new UnsupportedOperationException(method.getName());
            };
        }
        return switch (method.getName()) {
            case "save" -> {
                Management entity = (Management) args[0];
                store.put(entity.getId(), entity);
                yield entity;
            }
            case "findById" -> Optional.ofNullable(store.get((UUID) args[0]));
            case "deleteById" -> {
                store.remove((UUID) args[0]);
                yield null;
            }
            case "deleteByExpiresAtIsBefore" -> {
                long expiresAt = (Long) args[0];
                store.entrySet().removeIf(e -> e.getValue().getExpiresAt() < expiresAt);
                yield null;
            }
            case "deleteAll" -> {
                store.clear();
                yield null;
            }
            default -> throw new UnsupportedOperationException("ManagementRepository." + method.getName());
        };
    }

    private static CallbackEventRepository callbackRepository() {
        return (CallbackEventRepository) Proxy.newProxyInstance(
                CallbackEventRepository.class.getClassLoader(),
                new Class<?>[]{CallbackEventRepository.class},
                (proxy, method, args) -> {
                    if ("save".equals(method.getName())) {
                        return args[0];
                    }
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "toString" -> "noop-callback-repo";
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == args[0];
                            default -> null;
                        };
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static PresentationVerifier unusedPresentationVerifier() {
        return (String vpToken, Management management, ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredential credential) -> {
            throw new IllegalStateException("SD-JWT PresentationVerifier is not used on the ZK harness path");
        };
    }

    private static DcqlEvaluator unusedDcqlEvaluator() {
        return new DcqlEvaluator() {
            @Override
            public List<SdJwt> filterByVct(List<SdJwt> sdJwts, DcqlCredentialMeta meta) {
                throw new IllegalStateException("DcqlEvaluator is not used on the ZK harness path");
            }

            @Override
            public void validateRequestedClaims(SdJwt sdJwt, List<DcqlClaim> requestedClaims) {
                throw new IllegalStateException("DcqlEvaluator is not used on the ZK harness path");
            }
        };
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseForm(String body) {
        var map = new LinkedHashMap<String, String>();
        if (body == null || body.isBlank()) {
            return map;
        }
        for (String pair : body.split("&")) {
            int idx = pair.indexOf('=');
            String key = URLDecoder.decode(idx < 0 ? pair : pair.substring(0, idx), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(idx < 0 ? "" : pair.substring(idx + 1), StandardCharsets.UTF_8);
            map.put(key, value);
        }
        return map;
    }

    private static String header(HttpExchange exchange, String name) {
        return exchange.getRequestHeaders().getFirst(name);
    }

    private static void writeJson(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        writeBytes(exchange, status, "application/json", bytes);
    }

    private static void writeResponseEntity(HttpExchange exchange, ResponseEntity<?> entity) throws IOException {
        int status = entity.getStatusCode().value();
        Object body = entity.getBody();
        if (body == null) {
            exchange.sendResponseHeaders(status, -1);
            return;
        }
        writeJson(exchange, status, body);
    }

    private static void writeBytes(HttpExchange exchange, int status, String contentType, byte[] bytes)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
