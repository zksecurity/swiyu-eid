import { SWIYU_BENCHMARK_RESIDENCE } from "./residence-benchmark-manifest.js";
import { computeSwiyuResidencePolicyChallengeHash } from "./residence-eligibility.js";

/** Exact policy-domain-separated scalar signed by the benchmark holder. */
export function computeSwiyuBenchmarkResidenceChallengeHash(
  baseChallengeHash: bigint,
): bigint {
  return computeSwiyuResidencePolicyChallengeHash(
    baseChallengeHash,
    SWIYU_BENCHMARK_RESIDENCE.policy,
  );
}
