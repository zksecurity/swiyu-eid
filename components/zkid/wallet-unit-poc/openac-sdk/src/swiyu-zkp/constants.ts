/** Fixed opt-in profile identifiers shared with the verifier integration. */
export const SWIYU_AGE18_STATUS_PROFILE =
  "swiyu-age18-status-2k-v0" as const;
export const SWIYU_AGE18_STATUS_CIRCUIT =
  "swiyu_age18_status_2k" as const;

export const SWIYU_PROOF_ENVELOPE_VERSION = "swiyu-zkp-proof-v0" as const;

export const SWIYU_MESSAGE_BYTES = 1920;
export const SWIYU_MAX_B64_HEADER_BYTES = 256;
export const SWIYU_MAX_B64_PAYLOAD_BYTES = 1600;
export const SWIYU_DISCLOSURE_PADDED_BYTES = 128;
export const SWIYU_MAX_DISCLOSURES = 64;
export const SWIYU_MAX_AUX_DISCLOSURE_B64_BYTES = 16_384;
export const SWIYU_STATUS_DEPTH = 17;
export const SWIYU_MAX_STATUS_LIST_LENGTH = 1 << SWIYU_STATUS_DEPTH;
export const SWIYU_STRING_SLOT_BYTES = 112;
export const SWIYU_PROFILE_VERSION = "swiss-profile-vc:1.0.0" as const;

/** P-256 base field, which is also the `secq256r1` Circom R1CS field. */
export const SWIYU_P256_BASE_FIELD = BigInt(
  "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
);

/** P-256 scalar order used for ECDSA and challenge-scalar reduction only. */
export const SWIYU_P256_SCALAR_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);

export const SWIYU_CIRCUIT_FIELD = SWIYU_P256_BASE_FIELD;
