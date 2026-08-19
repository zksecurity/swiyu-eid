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
        Long currentTime
) {
    public static final String SUPPORTED_PROFILE = "swiyu-age18-status-2k-v0";
    public static final String SUPPORTED_CIRCUIT_ID = "swiyu_age18_status_2k";
}
