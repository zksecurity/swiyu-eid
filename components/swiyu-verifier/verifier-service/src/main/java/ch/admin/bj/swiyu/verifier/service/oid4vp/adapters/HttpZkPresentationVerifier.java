package ch.admin.bj.swiyu.verifier.service.oid4vp.adapters;

import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.common.config.ZkVerifierSidecarProperties;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.verifier.domain.management.Management;
import ch.admin.bj.swiyu.verifier.domain.management.TrustAnchor;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredential;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.ZkPresentationVerificationResult;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.ZkPresentationVerifier;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

import static ch.admin.bj.swiyu.verifier.common.exception.VerificationException.submissionError;

/**
 * Loopback HTTP adapter for the local Circom/Spartan verifier sidecar.
 *
 * <p>Java supplies every expected session value from the persisted, signed
 * request. The sidecar owns issuer-key/trust resolution and signed status-list
 * snapshot resolution, and returns only a boolean plus non-sensitive outputs.
 * Proof-envelope hints are never used as expected values.</p>
 */
@Component
@ConditionalOnProperty(prefix = "swiyu.zkp.sidecar", name = "endpoint")
public final class HttpZkPresentationVerifier implements ZkPresentationVerifier {

    private static final int MAX_PROOF_ENVELOPE_BYTES = 2_097_152;
    private static final long MAX_POLICY_TIME_SKEW_SECONDS = 300;

    private final ZkVerifierSidecarProperties properties;
    private final ApplicationProperties applicationProperties;
    private final ObjectMapper objectMapper;
    private final ObjectReader sidecarResponseReader;
    private final SidecarTransport transport;
    private final Clock clock;

    public HttpZkPresentationVerifier(
            ZkVerifierSidecarProperties properties,
            ApplicationProperties applicationProperties,
            ObjectMapper objectMapper
    ) {
        this(properties, applicationProperties, objectMapper,
                new JdkSidecarTransport(properties.getTimeout(), properties.getMaxResponseBytes()), Clock.systemUTC());
    }

    HttpZkPresentationVerifier(
            ZkVerifierSidecarProperties properties,
            ApplicationProperties applicationProperties,
            ObjectMapper objectMapper,
            SidecarTransport transport
    ) {
        this(properties, applicationProperties, objectMapper, transport, Clock.systemUTC());
    }

    HttpZkPresentationVerifier(
            ZkVerifierSidecarProperties properties,
            ApplicationProperties applicationProperties,
            ObjectMapper objectMapper,
            SidecarTransport transport,
            Clock clock
    ) {
        this.properties = properties;
        this.applicationProperties = applicationProperties;
        this.objectMapper = objectMapper;
        this.sidecarResponseReader = createStrictSidecarResponseReader(objectMapper);
        this.transport = transport;
        this.clock = clock;
    }

    @Override
    public ZkPresentationVerificationResult verify(
            String vpToken,
            Management management,
            DcqlCredential dcqlCredential
    ) {
        if (vpToken == null || vpToken.isBlank()
                || vpToken.getBytes(StandardCharsets.UTF_8).length > MAX_PROOF_ENVELOPE_BYTES) {
            throw rejected("ZK proof envelope is missing or too large");
        }
        var policy = dcqlCredential.getZkPresentationPolicy();
        if (policy == null) {
            throw rejected("ZK verification requires a signed policy");
        }
        validatePolicyTime(policy.currentTime());

        URI endpoint = validateLoopbackEndpoint(properties.getEndpoint());
        var override = management.getConfigurationOverride();
        String externalUrl = override.externalUrlOrDefault(applicationProperties.getExternalUrl());
        String clientId = override.verifierDidOrDefaultWithPrefix(applicationProperties);
        String responseUri = "%s/oid4vp/api/request-object/%s/response-data"
                .formatted(externalUrl, management.getId());

        var expected = new ExpectedContext(
                management.getRequestNonce(),
                clientId,
                responseUri,
                management.getOauthState(),
                dcqlCredential.getId(),
                policy.profile(),
                policy.circuitId(),
                policy.cutoffDate(),
                policy.currentTime(),
                policy.statusListSnapshot(),
                dcqlCredential.getMeta().getVctValues(),
                nullToEmpty(management.getAcceptedIssuerDids()),
                nullToEmpty(management.getTrustAnchors())
        );

        String requestBody;
        try {
            requestBody = objectMapper.writeValueAsString(new SidecarRequest(vpToken, expected));
        } catch (JacksonException e) {
            throw submissionError(e, VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "Unable to create ZK verifier request");
        }

        SidecarHttpResponse httpResponse;
        try {
            httpResponse = transport.post(endpoint, requestBody, properties.getTimeout());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw submissionError(e, VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK verifier request was interrupted");
        } catch (IOException | RuntimeException e) {
            throw submissionError(e, VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK verifier sidecar is unavailable");
        }

        if (httpResponse.statusCode() != 200 || httpResponse.body() == null
                || httpResponse.body().getBytes(StandardCharsets.UTF_8).length > properties.getMaxResponseBytes()) {
            throw rejected("ZK verifier sidecar rejected the presentation");
        }

        SidecarResponse response;
        try {
            response = sidecarResponseReader.readValue(httpResponse.body());
        } catch (JacksonException e) {
            throw submissionError(e, VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK verifier sidecar returned an invalid response");
        }
        if (response == null || !Boolean.TRUE.equals(response.verified())
                || response.profile() == null || response.circuitId() == null
                || response.predicateSatisfied() == null || response.statusValid() == null
                || response.statusListSnapshot() == null) {
            throw rejected("ZK verifier sidecar rejected the presentation");
        }

        return new ZkPresentationVerificationResult(
                response.profile(),
                response.circuitId(),
                response.predicateSatisfied(),
                response.statusValid(),
                response.statusListSnapshot()
        );
    }

    private static URI validateLoopbackEndpoint(String configuredEndpoint) {
        final URI endpoint;
        try {
            endpoint = URI.create(configuredEndpoint == null ? "" : configuredEndpoint);
        } catch (IllegalArgumentException e) {
            throw submissionError(e, VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK verifier sidecar endpoint is invalid");
        }
        String host = endpoint.getHost();
        boolean loopback = "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "[::1]".equals(host)
                || "::1".equals(host);
        if (!"http".equalsIgnoreCase(endpoint.getScheme()) || !loopback || endpoint.getPort() <= 0
                || endpoint.getRawUserInfo() != null || endpoint.getRawQuery() != null
                || endpoint.getRawFragment() != null || endpoint.getPath() == null
                || endpoint.getPath().isBlank() || "/".equals(endpoint.getPath())) {
            throw rejected("ZK verifier sidecar endpoint must be an explicit loopback HTTP endpoint");
        }
        return endpoint;
    }

    private static ObjectReader createStrictSidecarResponseReader(ObjectMapper objectMapper) {
        return objectMapper.rebuild()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .build()
                .readerFor(SidecarResponse.class);
    }

    private static <T> List<T> nullToEmpty(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private void validatePolicyTime(Long policyTime) {
        long receiptTime = Instant.now(clock).getEpochSecond();
        if (policyTime == null || policyTime < receiptTime - MAX_POLICY_TIME_SKEW_SECONDS
                || policyTime > receiptTime + MAX_POLICY_TIME_SKEW_SECONDS) {
            throw rejected("ZK presentation policy time is no longer fresh");
        }
    }

    private static RuntimeException rejected(String description) {
        return submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, description);
    }

    record SidecarRequest(
            @JsonProperty("proof_envelope") String proofEnvelope,
            @JsonProperty("expected") ExpectedContext expected
    ) {
    }

    record ExpectedContext(
            @JsonProperty("nonce") String nonce,
            @JsonProperty("client_id") String clientId,
            @JsonProperty("response_uri") String responseUri,
            @JsonProperty("state") String state,
            @JsonProperty("query_id") String queryId,
            @JsonProperty("profile") String profile,
            @JsonProperty("circuit_id") String circuitId,
            @JsonProperty("cutoff_date") String cutoffDate,
            @JsonProperty("current_time") Long currentTime,
            @JsonProperty("status_list_snapshot") String statusListSnapshot,
            @JsonProperty("vct_values") List<String> vctValues,
            @JsonProperty("accepted_issuer_dids") List<String> acceptedIssuerDids,
            @JsonProperty("trust_anchors") List<TrustAnchor> trustAnchors
    ) {
    }

    record SidecarResponse(
            @JsonProperty("verified") Boolean verified,
            @JsonProperty("profile") String profile,
            @JsonProperty("circuit_id") String circuitId,
            @JsonProperty("predicate_satisfied") Boolean predicateSatisfied,
            @JsonProperty("status_valid") Boolean statusValid,
            @JsonProperty("status_list_snapshot") String statusListSnapshot
    ) {
    }

    record SidecarHttpResponse(int statusCode, String body) {
    }

    @FunctionalInterface
    interface SidecarTransport {
        SidecarHttpResponse post(URI endpoint, String requestBody, Duration timeout)
                throws IOException, InterruptedException;
    }

    static HttpClient buildDirectHttpClient(Duration connectTimeout) {
        return HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .proxy(HttpClient.Builder.NO_PROXY)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static final class JdkSidecarTransport implements SidecarTransport {

        private final HttpClient httpClient;
        private final int maxResponseBytes;

        private JdkSidecarTransport(Duration connectTimeout, int maxResponseBytes) {
            this.httpClient = buildDirectHttpClient(connectTimeout);
            this.maxResponseBytes = maxResponseBytes;
        }

        @Override
        public SidecarHttpResponse post(URI endpoint, String requestBody, Duration timeout)
                throws IOException, InterruptedException {
            var request = HttpRequest.newBuilder(endpoint)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                    .build();
            var response = httpClient.send(request,
                    ignored -> new LimitedUtf8BodySubscriber(maxResponseBytes));
            return new SidecarHttpResponse(response.statusCode(), response.body());
        }
    }

    /**
     * Accumulates a response only while it remains within the configured byte
     * bound. Cancelling at the subscriber boundary avoids first materialising an
     * attacker-sized byte array or String.
     */
    static final class LimitedUtf8BodySubscriber implements HttpResponse.BodySubscriber<String> {

        private static final int COPY_BUFFER_BYTES = 8_192;

        private final int maxBytes;
        private final ByteArrayOutputStream bytes;
        private final CompletableFuture<String> body = new CompletableFuture<>();
        private Flow.Subscription subscription;
        private boolean completed;

        LimitedUtf8BodySubscriber(int maxBytes) {
            if (maxBytes <= 0) {
                throw new IllegalArgumentException("max response bytes must be positive");
            }
            this.maxBytes = maxBytes;
            this.bytes = new ByteArrayOutputStream(Math.min(maxBytes, COPY_BUFFER_BYTES));
        }

        @Override
        public CompletionStage<String> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription newSubscription) {
            if (subscription != null) {
                newSubscription.cancel();
                return;
            }
            subscription = newSubscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            if (completed) {
                return;
            }

            long remainingCapacity = maxBytes - (long) bytes.size();
            for (var buffer : buffers) {
                if (buffer.remaining() > remainingCapacity) {
                    fail(new IOException("ZK verifier sidecar response exceeded the configured limit"));
                    return;
                }
                remainingCapacity -= buffer.remaining();
            }

            var copyBuffer = new byte[COPY_BUFFER_BYTES];
            for (var buffer : buffers) {
                while (buffer.hasRemaining()) {
                    int length = Math.min(buffer.remaining(), copyBuffer.length);
                    buffer.get(copyBuffer, 0, length);
                    bytes.write(copyBuffer, 0, length);
                }
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable error) {
            if (!completed) {
                completed = true;
                body.completeExceptionally(error);
            }
        }

        @Override
        public void onComplete() {
            if (completed) {
                return;
            }
            completed = true;
            try {
                var decoder = StandardCharsets.UTF_8.newDecoder();
                body.complete(decoder.decode(ByteBuffer.wrap(bytes.toByteArray())).toString());
            } catch (IOException e) {
                body.completeExceptionally(e);
            }
        }

        private void fail(IOException error) {
            completed = true;
            subscription.cancel();
            body.completeExceptionally(error);
        }
    }
}
