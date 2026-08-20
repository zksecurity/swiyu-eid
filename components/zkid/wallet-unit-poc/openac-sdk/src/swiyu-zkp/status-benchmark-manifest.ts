/** Shared packed-status fixture for the base-age and age+nullifier A/Bs. */
export const SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2 = Object.freeze({
  treeProfile: "packed-status-chunk-ternary-merkle-v2" as const,
  chunkBytes: 64,
  treeDepth: 6,
  listLength: 65_536,
  epoch: 172,
  statusValue: 0 as const,
  snapshotRoot: "8931f6a85f7db62ba4d1546343c0f54e290c93197a8db2d4a54cb377e968a3ef",
});

/** Explicit A/B routing identities; they never alias legacy proof keys. */
export const SWIYU_PACKED_STATUS_SHOW_PROFILES_V2 = Object.freeze({
  age: Object.freeze({
    profile: "swiyu.age-over-18.packed-status-chunk.v2",
    circuitId: "swiyu_age18_show_packed_chunk_v2",
  }),
  residence: Object.freeze({
    profile: "swiyu.residence-eligibility.packed-status-chunk.v2",
    circuitId: "swiyu_residence_show_packed_chunk_v2",
  }),
  ageNullifier: Object.freeze({
    profile: "swiyu.age-over-18.scoped-nullifier.packed-status-chunk.v2",
    circuitId: "swiyu_nullifier_age18_show_packed_chunk_v2",
  }),
});
