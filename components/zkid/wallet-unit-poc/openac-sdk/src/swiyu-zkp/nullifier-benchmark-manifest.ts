/**
 * Frozen semantic inputs shared by the ZK fixture and ordinary SD-JWT control.
 * This is benchmark provenance, not a production program configuration.
 */
export const SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS = Object.freeze({
  registryNamespace: "swiyu-benefit-claims",
  verifierOrigin: "x509_san_dns:verifier.example.ch",
  program: "age-gated-campaign-redemption",
  claimType: "one-redemption-per-credential",
  epoch: 202603n,
  eligibilityPolicy: "age-over-18-valid-status",
});

export const SWIYU_BENCHMARK_NULLIFIER_CREDENTIAL_UID_HEX =
  "3e68b40a9d9d742257cd42f486cb26be56da87ab6e983ddea2aa832bf1a374d9";

export const SWIYU_BENCHMARK_NULLIFIER_HOLDER_SECRET_HEX =
  "965350ef5810607210bc1671b0ebc8428f28be496e81bba9a7196d20f17aee7d";
