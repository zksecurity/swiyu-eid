package ch.admin.bj.swiyu.verifier.service.oid4vp.ports;

import ch.admin.bj.swiyu.verifier.domain.management.Management;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.DcqlCredential;

/**
 * Port for cryptographically verifying a policy-bound ZK presentation.
 *
 * <p>The production adapter sends the exact envelope plus expected values from
 * the persisted signed request to a local verifier sidecar. The sidecar owns
 * issuer-key/trust resolution and signed status-list snapshot resolution. It
 * must derive returned values from proof verification, never envelope hints.</p>
 */
@FunctionalInterface
public interface ZkPresentationVerifier {
    ZkPresentationVerificationResult verify(
            String vpToken,
            Management management,
            DcqlCredential dcqlCredential
    );
}
