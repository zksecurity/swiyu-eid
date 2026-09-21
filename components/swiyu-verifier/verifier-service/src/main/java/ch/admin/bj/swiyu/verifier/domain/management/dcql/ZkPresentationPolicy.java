package ch.admin.bj.swiyu.verifier.domain.management.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Persisted form of the experimental swiyu ZK presentation policy.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ZkPresentationPolicy(

        @JsonProperty("profile")
        String profile,

        @JsonProperty("circuit_id")
        String circuitId,

        @JsonProperty("cutoff_date")
        String cutoffDate,

        /**
         * Opaque identifier for a status-list snapshot configured in the local
         * verifier sidecar. The URI, root and status-list index remain private.
         */
        @JsonProperty("status_list_snapshot")
        String statusListSnapshot,

        /**
         * Unix time frozen when the signed request object is created. The proof
         * evaluates credential validity at this exact instant.
         */
        @JsonProperty("current_time")
        Long currentTime,

        /**
         * EPFL d10 reference date encoded as YYYYMMDD.
         */
        @JsonProperty("now_date")
        Integer nowDate,

        /**
         * Trusted issuer public key X coordinate as 64-char lowercase hex.
         */
        @JsonProperty("issuer_pub_x")
        String issuerPubX,

        /**
         * Trusted issuer public key Y coordinate as 64-char lowercase hex.
         */
        @JsonProperty("issuer_pub_y")
        String issuerPubY
) {
    public static final String OPENAC_PROFILE = "swiyu-age18-status-2k-v0";
    public static final String OPENAC_CIRCUIT_ID = "swiyu_age18_status_2k";
    public static final String OPENAC_AGE25_PROFILE = "openac-age25-jwt-v0";
    public static final String OPENAC_AGE25_CIRCUIT_ID = "swiyu_age25_jwt";
    public static final String EPFL_PROFILE = "epfl-d10-swiyu-jwt-age25-v0";
    public static final String EPFL_CIRCUIT_ID = "d10_swiyu_jwt";

    /** Backward-compatible alias for the OpenAC profile. */
    public static final String SUPPORTED_PROFILE = OPENAC_PROFILE;
    /** Backward-compatible alias for the OpenAC circuit id. */
    public static final String SUPPORTED_CIRCUIT_ID = OPENAC_CIRCUIT_ID;

    public boolean isEpflProfile() {
        return EPFL_PROFILE.equals(profile);
    }

    public boolean isOpenAcAge25Profile() {
        return OPENAC_AGE25_PROFILE.equals(profile);
    }

    /** Shared age-25 claim: no status list in the signed policy or verifier result. */
    public boolean omitsStatusList() {
        return isEpflProfile() || isOpenAcAge25Profile();
    }
}
