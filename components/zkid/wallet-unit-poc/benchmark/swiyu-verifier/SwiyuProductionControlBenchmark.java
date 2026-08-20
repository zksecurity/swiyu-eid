package ch.admin.bj.swiyu.verifier.benchmark;

import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.common.config.VerificationProperties;
import ch.admin.bj.swiyu.verifier.domain.SdJwt;
import ch.admin.bj.swiyu.verifier.domain.management.ConfigurationOverride;
import ch.admin.bj.swiyu.verifier.domain.management.Management;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlClaim;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredential;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredentialMeta;
import ch.admin.bj.swiyu.verifier.domain.statuslist.StatusListReference;
import ch.admin.bj.swiyu.verifier.domain.statuslist.StatusListReferenceFactory;
import ch.admin.bj.swiyu.verifier.service.dcql.DcqlUtil;
import ch.admin.bj.swiyu.verifier.service.oid4vp.DcqlVpTokenVerifier;
import ch.admin.bj.swiyu.verifier.service.oid4vp.IssuerTrustValidator;
import ch.admin.bj.swiyu.verifier.service.oid4vp.SdJwtVpTokenVerifier;
import ch.admin.bj.swiyu.verifier.service.publickey.IssuerPublicKeyLoader;
import ch.admin.bj.swiyu.verifier.service.publickey.LoadingPublicKeyOfIssuerFailedException;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Offline benchmark driver around the production swiyu-verifier SD-JWT/DCQL
 * classes. Issuer-key and status resolution are deliberately preloaded so the
 * timed treatment contains no network I/O, matching the ZK benchmark boundary.
 */
public final class SwiyuProductionControlBenchmark {
    private static final String ISSUER = "did:example:issuer";
    private static final String KID = ISSUER + "#key-1";
    private static final String VCT = "https://example.ch/vct/person";
    private static final String NONCE = "n-7f3f778d0be4474e";
    private static final String AUDIENCE = "x509_san_dns:verifier.example.ch";
    private static final int STATUS_INDEX = 42;
    private static final String STATUS_URI = "https://status.example.ch/lists/2026-07";

    private SwiyuProductionControlBenchmark() {}

    public static void main(String[] args) throws Exception {
        var iterations = integerArg(args, "--iterations", 1_000);
        var warmups = integerArg(args, "--warmups", 100);
        var run = integerArg(args, "--run", 1);
        var fixture = Fixture.create();

        for (var i = 0; i < warmups; i++) fixture.verifyOnce();

        var cpu = ManagementFactory.getThreadMXBean();
        var cpuBefore = cpu.isCurrentThreadCpuTimeSupported() ? cpu.getCurrentThreadCpuTime() : -1L;
        var wallBefore = System.nanoTime();
        for (var i = 0; i < iterations; i++) fixture.verifyOnce();
        var wallNanos = System.nanoTime() - wallBefore;
        var cpuNanos = cpuBefore < 0 ? -1L : cpu.getCurrentThreadCpuTime() - cpuBefore;

        var report = Map.of(
                "schema", "swiyu.production-sd-jwt-dcql-control-worker.v1",
                "run", run,
                "iterations", iterations,
                "warmups", warmups,
                "source", Map.of(
                        "commit", environment("SWIYU_VERIFIER_COMMIT"),
                        "treeSha256", environment("SWIYU_VERIFIER_TREE_SHA256")),
                "boundary", Map.of(
                        "productionClasses", List.of(
                                "SdJwtVpTokenVerifier", "DcqlVpTokenVerifier", "DcqlUtil"),
                        "preloaded", List.of("issuer public key", "VALID status decision"),
                        "excluded", List.of("DID/status network I/O", "database/session/controller work")),
                "policy", Map.of(
                        "vct", VCT,
                        "claim", List.of("age_over_18", true),
                        "holderBinding", true,
                        "status", "VALID"),
                "timing", Map.of(
                        "wallMsPerOperation", wallNanos / 1_000_000.0 / iterations,
                        "cpuMsPerOperation", cpuNanos < 0 ? -1.0 : cpuNanos / 1_000_000.0 / iterations,
                        "totalWallMs", wallNanos / 1_000_000.0,
                        "totalCpuMs", cpuNanos < 0 ? -1.0 : cpuNanos / 1_000_000.0),
                "sizes", Map.of("transmittedPresentationBytes",
                        fixture.presentation.getBytes(StandardCharsets.UTF_8).length),
                "processPeakRssBytes", processPeakRssBytes());
        System.out.println(new ObjectMapper().writeValueAsString(report));
    }

    private record Fixture(
            String presentation,
            DcqlVpTokenVerifier verifier,
            Management management,
            DcqlCredential credential,
            DcqlCredentialMeta meta,
            List<DcqlClaim> claims
    ) {
        static Fixture create() throws Exception {
            var issuerKey = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
            var holderKey = new ECKeyGenerator(Curve.P_256).generate();
            var now = Instant.now().getEpochSecond();
            var disclosure = new Disclosure("abcdefghijklmnop", "age_over_18", true);
            var builder = new SDObjectBuilder();
            builder.putSDClaim(disclosure);
            builder.putClaim("iss", ISSUER);
            builder.putClaim("iat", now);
            builder.putClaim("nbf", now - 60);
            builder.putClaim("exp", now + 3_600);
            builder.putClaim("vct", VCT);
            builder.putClaim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
            builder.putClaim("status", Map.of("status_list", Map.of(
                    "idx", STATUS_INDEX, "uri", STATUS_URI)));
            var issuerJwt = sign(builder.build(), issuerKey, KID, "dc+sd-jwt");
            var credential = new SDJWT(issuerJwt, List.of(disclosure)).toString();
            var presentation = credential + keyBinding(credential, holderKey, now);

            var application = new ApplicationProperties();
            application.setClientId(AUDIENCE);
            var verification = new VerificationProperties();
            verification.setAcceptableProofTimeWindowSeconds(120);
            verification.setObjectSizeLimit(1_000_000);

            var keyLoader = new PreloadedIssuerPublicKeyLoader(issuerKey.toPublicKey());
            var statusFactory = new PreloadedValidStatusFactory(verification);
            var sdJwtVerifier = new SdJwtVpTokenVerifier(
                    keyLoader, statusFactory, application, verification);
            var trust = new IssuerTrustValidator(null, Optional.empty());
            var verifier = new DcqlVpTokenVerifier(sdJwtVerifier, trust);
            var management = Management.builder()
                    .id(UUID.fromString("00000000-0000-0000-0000-000000000042"))
                    .requestNonce(NONCE)
                    .acceptedIssuerDids(List.of(ISSUER))
                    .trustAnchors(List.of())
                    .configurationOverride(new ConfigurationOverride(null, null, null, null, null, null))
                    .build();
            var meta = DcqlCredentialMeta.builder().vctValues(List.of(VCT)).build();
            var claims = List.of(DcqlClaim.builder()
                    .path(List.of("age_over_18")).values(List.of(true)).build());
            var query = DcqlCredential.builder()
                    .id("age-over-18")
                    .format("dc+sd-jwt")
                    .meta(meta)
                    .claims(claims)
                    .requireCryptographicHolderBinding(true)
                    .build();
            return new Fixture(presentation, verifier, management, query, meta, claims);
        }

        void verifyOnce() {
            var verified = verifier.verifyVpTokenForDCQLRequest(
                    new SdJwt(presentation), management, credential);
            var matching = DcqlUtil.filterByVct(List.of(verified), meta);
            if (matching.size() != 1) throw new IllegalStateException("VCT filter rejected fixture");
            DcqlUtil.validateRequestedClaims(matching.getFirst(), claims);
        }
    }

    private static final class PreloadedIssuerPublicKeyLoader extends IssuerPublicKeyLoader {
        private final PublicKey key;

        private PreloadedIssuerPublicKeyLoader(PublicKey key) {
            super(null, new ObjectMapper());
            this.key = key;
        }

        @Override
        public PublicKey loadPublicKey(String issuer, String kid)
                throws LoadingPublicKeyOfIssuerFailedException {
            if (!ISSUER.equals(issuer) || !KID.equals(kid)) {
                throw new LoadingPublicKeyOfIssuerFailedException("unexpected issuer or kid", null);
            }
            return key;
        }
    }

    private static final class PreloadedValidStatusFactory extends StatusListReferenceFactory {
        private final StatusListReference valid = new StatusListReference(null, Map.of(), null, ISSUER, 0) {
            @Override public void verifyStatus() {}
            @Override protected String getStatusListRegistryUri() { return STATUS_URI; }
            @Override protected void verifyJWT(SignedJWT ignored) {}
        };

        private PreloadedValidStatusFactory(VerificationProperties verification) {
            super(null, null, verification);
        }

        @Override
        public List<StatusListReference> createStatusListReferences(
                Map<String, Object> claims, Management management) {
            var status = (Map<?, ?>) claims.get("status");
            var statusList = status == null ? null : (Map<?, ?>) status.get("status_list");
            var statusIndex = statusList == null ? null : statusList.get("idx");
            if (statusList == null || !STATUS_URI.equals(statusList.get("uri"))
                    || !(statusIndex instanceof Number number)
                    || number.intValue() != STATUS_INDEX) {
                throw new IllegalArgumentException("status reference does not match policy");
            }
            return List.of(valid);
        }
    }

    private static String sign(Map<String, Object> claims, ECKey key, String kid, String type)
            throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(kid).type(new JOSEObjectType(type)).build();
        var jwt = new SignedJWT(header, JWTClaimsSet.parse(claims));
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String keyBinding(String sdJwt, ECKey holderKey, long now) throws Exception {
        var hash = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(sdJwt.getBytes(StandardCharsets.UTF_8)));
        var claims = new JWTClaimsSet.Builder()
                .claim("sd_hash", hash)
                .issueTime(java.util.Date.from(Instant.ofEpochSecond(now)))
                .audience(AUDIENCE)
                .claim("nonce", NONCE)
                .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt")).build(), claims);
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }

    private static long processPeakRssBytes() {
        try {
            for (var line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("VmHWM:")) {
                    return Long.parseLong(line.replaceAll("[^0-9]", "")) * 1_024L;
                }
            }
        } catch (IOException ignored) {
            // The final pinned treatment is Linux; zero is a visible unsupported sentinel elsewhere.
        }
        return 0L;
    }

    private static int integerArg(String[] args, String name, int fallback) {
        for (var i = 0; i + 1 < args.length; i++) {
            if (name.equals(args[i])) return Integer.parseInt(args[i + 1]);
        }
        return fallback;
    }

    private static String environment(String name) {
        return Optional.ofNullable(System.getenv(name)).orElse("unknown");
    }
}
