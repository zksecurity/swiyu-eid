package ch.admin.bj.swiyu.verifier.service.oid4vp.adapters;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Canonical OID4VP session challenge digest for the EPFL d10 profile.
 *
 * <p>Version 1 uses domain {@code swiyu-show-v1\0} and length-prefixed UTF-8
 * fields in a fixed order. {@code policy_inputs} is compact canonical JSON with
 * sorted keys.</p>
 */
public final class EpflChallengeBinding {

    static final String DOMAIN = "swiyu-show-v1\u0000";
    static final String PROFILE = "epfl-d10-swiyu-jwt-age25-v0";
    static final String CIRCUIT_ID = "d10_swiyu_jwt";
    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
    private static final ObjectMapper CANONICAL_JSON = new ObjectMapper();

    private EpflChallengeBinding() {
    }

    public record SessionContext(
            String nonce,
            String clientId,
            String responseUri,
            String state,
            String queryId,
            String profile,
            String circuitId,
            int nowDate,
            String issuerPubX,
            String issuerPubY
    ) {
    }

    public static String policyInputsJson(SessionContext context) {
        try {
            Map<String, Object> inputs = new TreeMap<>();
            inputs.put("circuit_id", context.circuitId());
            inputs.put("issuer_pub_x", context.issuerPubX());
            inputs.put("issuer_pub_y", context.issuerPubY());
            inputs.put("now_date", context.nowDate());
            return CANONICAL_JSON.writeValueAsString(inputs);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("Unable to encode EPFL policy_inputs", e);
        }
    }

    public static byte[] digest(SessionContext context) {
        validateContext(context);
        String policyInputs = policyInputsJson(context);
        return digest(
                context.nonce(),
                context.clientId(),
                context.responseUri(),
                context.state(),
                context.queryId(),
                context.profile(),
                policyInputs);
    }

    public static String digestHex(SessionContext context) {
        return HexFormat.of().formatHex(digest(context));
    }

    public static byte[] digest(
            String nonce,
            String clientId,
            String responseUri,
            String state,
            String queryId,
            String profile,
            String policyInputsJson
    ) {
        validateUtf8Field("nonce", nonce);
        validateUtf8Field("client_id", clientId);
        validateUtf8Field("response_uri", responseUri);
        validateUtf8Field("state", state);
        validateUtf8Field("query_id", queryId);
        validateUtf8Field("profile", profile);
        validateUtf8Field("policy_inputs", policyInputsJson);
        if (!PROFILE.equals(profile)) {
            throw new IllegalArgumentException("Unsupported EPFL profile: " + profile);
        }

        var encoded = new ByteArrayOutputStream();
        encoded.writeBytes(DOMAIN.getBytes(StandardCharsets.UTF_8));
        for (String field : List.of(
                nonce, clientId, responseUri, state, queryId, profile, policyInputsJson)) {
            writeLengthPrefixed(encoded, field);
        }
        try {
            return MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static List<Integer> digestAsU8List(SessionContext context) {
        byte[] digest = digest(context);
        var values = new java.util.ArrayList<Integer>(digest.length);
        for (byte value : digest) {
            values.add(value & 0xff);
        }
        return values;
    }

    private static void validateContext(SessionContext context) {
        if (context == null) {
            throw new IllegalArgumentException("EPFL session context is required");
        }
        if (!PROFILE.equals(context.profile())) {
            throw new IllegalArgumentException("Unsupported EPFL profile: " + context.profile());
        }
        if (!CIRCUIT_ID.equals(context.circuitId())) {
            throw new IllegalArgumentException("Unsupported EPFL circuit_id: " + context.circuitId());
        }
        if (context.nowDate() < 19000101 || context.nowDate() > 21991231) {
            throw new IllegalArgumentException("now_date must be a plausible YYYYMMDD value");
        }
        if (!HEX64.matcher(context.issuerPubX()).matches()
                || !HEX64.matcher(context.issuerPubY()).matches()) {
            throw new IllegalArgumentException("issuer_pub_x/y must be 64-char lowercase hex");
        }
        digest(
                context.nonce(),
                context.clientId(),
                context.responseUri(),
                context.state(),
                context.queryId(),
                context.profile(),
                policyInputsJson(context));
    }

    private static void writeLengthPrefixed(ByteArrayOutputStream buffer, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 1 || bytes.length > 4096) {
            throw new IllegalArgumentException("EPFL challenge field UTF-8 length must be in 1..4096");
        }
        buffer.write((bytes.length >>> 24) & 0xff);
        buffer.write((bytes.length >>> 16) & 0xff);
        buffer.write((bytes.length >>> 8) & 0xff);
        buffer.write(bytes.length & 0xff);
        buffer.writeBytes(bytes);
    }

    private static void validateUtf8Field(String label, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
        int length = value.getBytes(StandardCharsets.UTF_8).length;
        if (length < 1 || length > 4096) {
            throw new IllegalArgumentException(label + " UTF-8 length must be in 1..4096");
        }
    }
}
