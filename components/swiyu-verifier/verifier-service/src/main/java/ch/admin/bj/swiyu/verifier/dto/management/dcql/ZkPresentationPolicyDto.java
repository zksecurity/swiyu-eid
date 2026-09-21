package ch.admin.bj.swiyu.verifier.dto.management.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * Experimental, vendor-specific ZK presentation policy carried inside one DCQL
 * credential query. Keeping the policy on the credential query means it is
 * persisted with the existing {@code dcql_query} JSON and covered by the
 * request-object signature without introducing another protocol endpoint.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Experimental swiyu ZK presentation policy")
public record ZkPresentationPolicyDto(

        @JsonProperty("profile")
        @NotBlank
        String profile,

        @JsonProperty("circuit_id")
        @NotBlank
        String circuitId,

        @JsonProperty("cutoff_date")
        @Pattern(
                regexp = "^(19\\d{2}|20\\d{2}|21\\d{2})-\\d{2}-\\d{2}$",
                message = "cutoff_date must use YYYY-MM-DD with a year from 1900 through 2199")
        String cutoffDate,

        @JsonProperty("status_list_snapshot")
        @Size(max = 256)
        @Pattern(regexp = "^[A-Za-z0-9._~:-]+$", message = "status_list_snapshot must be an opaque snapshot id")
        String statusListSnapshot,

        @JsonProperty("current_time")
        @Positive
        Long currentTime,

        @JsonProperty("now_date")
        Integer nowDate,

        @JsonProperty("issuer_pub_x")
        @Pattern(regexp = "^[0-9a-f]{64}$", message = "issuer_pub_x must be 64-char lowercase hex")
        String issuerPubX,

        @JsonProperty("issuer_pub_y")
        @Pattern(regexp = "^[0-9a-f]{64}$", message = "issuer_pub_y must be 64-char lowercase hex")
        String issuerPubY
) {
}
