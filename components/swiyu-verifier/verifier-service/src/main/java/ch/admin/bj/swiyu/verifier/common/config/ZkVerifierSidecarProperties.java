package ch.admin.bj.swiyu.verifier.common.config;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Local-only connection settings for the experimental ZK proof verifier.
 *
 * <p>The endpoint is deliberately optional: when it is absent Spring does not
 * register the adapter and a ZK presentation fails closed in the DCQL service.</p>
 */
@Data
@Validated
@ConfigurationProperties(prefix = "swiyu.zkp.sidecar")
public class ZkVerifierSidecarProperties {

    @Nullable
    private String endpoint;

    @NotNull
    /**
     * The final research relation verifies in roughly nine seconds on the
     * measured development machine. Keep enough cold-start margin to match
     * the sidecar's bounded native-verifier timeout.
     */
    private Duration timeout = Duration.ofSeconds(120);

    @Min(1_024)
    @Max(1_048_576)
    private int maxResponseBytes = 65_536;
}
