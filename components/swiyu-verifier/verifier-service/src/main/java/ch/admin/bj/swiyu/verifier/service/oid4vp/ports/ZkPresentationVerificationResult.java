package ch.admin.bj.swiyu.verifier.service.oid4vp.ports;

/**
 * Minimal authoritative values returned by a ZK verifier implementation.
 * It intentionally contains neither the hidden birthdate nor a holder key.
 */
public record ZkPresentationVerificationResult(
        String profile,
        String circuitId,
        boolean predicateSatisfied,
        boolean statusValid,
        String statusListSnapshot
) {
}
