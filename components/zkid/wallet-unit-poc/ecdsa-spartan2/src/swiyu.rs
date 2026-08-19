//! Serialized, single-proof APIs for the fixed swiyu profile.

use crate::{
    circuits::swiyu_circuit::{SwiyuCircuit, SWIYU_PUBLIC_VALUE_COUNT},
    parse_witness, prove_circuit_in_memory, Scalar, E,
};
use ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};

pub const SWIYU_SCALAR_BYTES: usize = 32;
pub const SWIYU_PUBLIC_CONTEXT_BYTES: usize = SWIYU_PUBLIC_VALUE_COUNT * SWIYU_SCALAR_BYTES;

/// Serialized setup artifacts. Byte vectors avoid exposing Rust/bincode types
/// through the native or WASM boundary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiyuSetupResult {
    pub pk: Vec<u8>,
    pub vk: Vec<u8>,
}

/// A single proof and the public values bound into its Fiat-Shamir transcript.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiyuProofResult {
    pub proof: Vec<u8>,
    pub public_values: Vec<Vec<u8>>,
}

/// Verification is total over untrusted bytes: malformed input is represented
/// as `valid = false`, not a panic or partially decoded proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiyuVerifyResult {
    pub valid: bool,
    pub public_values: Vec<Vec<u8>>,
    pub error: Option<String>,
}

impl SwiyuVerifyResult {
    fn invalid(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            public_values: Vec::new(),
            error: Some(error.into()),
        }
    }
}

fn encode_scalar(value: &Scalar) -> Vec<u8> {
    value.to_repr().as_ref().to_vec()
}

fn encode_public_values(values: &[Scalar]) -> Vec<Vec<u8>> {
    values.iter().map(encode_scalar).collect()
}

fn decode_public_context(bytes: &[u8]) -> Result<Vec<Scalar>, String> {
    if bytes.len() != SWIYU_PUBLIC_CONTEXT_BYTES {
        return Err(format!(
            "expected {SWIYU_PUBLIC_CONTEXT_BYTES} public-context bytes, got {}",
            bytes.len()
        ));
    }

    bytes
        .chunks_exact(SWIYU_SCALAR_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let mut repr = <Scalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            Scalar::from_repr(repr)
                .into_option()
                .ok_or_else(|| format!("public context scalar {index} is not canonical"))
        })
        .collect()
}

fn validate_expected_public_values(values: &[Scalar]) -> Result<(), String> {
    if values.len() != SWIYU_PUBLIC_VALUE_COUNT {
        return Err(format!(
            "expected {SWIYU_PUBLIC_VALUE_COUNT} public values, got {}",
            values.len()
        ));
    }
    if values[0] != Scalar::ONE {
        return Err("expressionResult must equal one".to_string());
    }
    Ok(())
}

fn verify_decoded(
    proof: &R1CSSNARK<E>,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    expected: &[Scalar],
) -> SwiyuVerifyResult {
    if let Err(error) = validate_expected_public_values(expected) {
        return SwiyuVerifyResult::invalid(error);
    }

    let actual = match proof.verify(vk) {
        Ok(values) => values,
        Err(error) => {
            return SwiyuVerifyResult::invalid(format!("proof verification failed: {error:?}"))
        }
    };

    if actual.len() != SWIYU_PUBLIC_VALUE_COUNT {
        return SwiyuVerifyResult::invalid(format!(
            "proof exposed {} public values, expected {SWIYU_PUBLIC_VALUE_COUNT}",
            actual.len()
        ));
    }
    if actual != expected {
        return SwiyuVerifyResult::invalid("proof public context mismatch");
    }

    SwiyuVerifyResult {
        valid: true,
        public_values: encode_public_values(&actual),
        error: None,
    }
}

/// Generate a proving/verifying key pair for the fixed swiyu R1CS.
pub fn setup_swiyu() -> Result<SwiyuSetupResult, String> {
    let (pk, vk) = R1CSSNARK::<E>::setup(SwiyuCircuit::default())
        .map_err(|error| format!("swiyu setup failed: {error:?}"))?;
    Ok(SwiyuSetupResult {
        pk: bincode::serialize(&pk)
            .map_err(|error| format!("proving-key serialization failed: {error}"))?,
        vk: bincode::serialize(&vk)
            .map_err(|error| format!("verifying-key serialization failed: {error}"))?,
    })
}

/// Prove from already parsed scalar witness values.
pub fn prove_swiyu_from_witness(
    pk_bytes: &[u8],
    witness: Vec<Scalar>,
) -> Result<SwiyuProofResult, String> {
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = bincode::deserialize(pk_bytes)
        .map_err(|error| format!("proving-key deserialization failed: {error}"))?;
    let circuit = SwiyuCircuit::with_witness(witness);
    let public_values = spartan2::traits::circuit::SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|error| format!("public-value extraction failed: {error:?}"))?;
    validate_expected_public_values(&public_values)?;
    let (proof, _instance, _witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|error| format!("swiyu proving failed: {error:?}"))?;

    Ok(SwiyuProofResult {
        proof: bincode::serialize(&proof)
            .map_err(|error| format!("proof serialization failed: {error}"))?,
        public_values: encode_public_values(&public_values),
    })
}

/// Parse a Circom `.wtns` and produce one session-bound proof.
pub fn prove_swiyu_from_wtns(
    pk_bytes: &[u8],
    witness_wtns_bytes: &[u8],
) -> Result<SwiyuProofResult, String> {
    let witness = parse_witness(witness_wtns_bytes)
        .map_err(|error| format!("witness parsing failed: {error:?}"))?;
    prove_swiyu_from_witness(pk_bytes, witness)
}

/// Verify a serialized proof against all ten expected public values.
///
/// `expected_public_context` is ten canonical, little-endian 32-byte field
/// elements concatenated in Circom witness order. Supplying the proof alone is
/// insufficient: the caller must bind its issuer/challenge/time/policy/status
/// expectations here.
pub fn verify_swiyu(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    expected_public_context: &[u8],
) -> SwiyuVerifyResult {
    let expected = match decode_public_context(expected_public_context) {
        Ok(values) => values,
        Err(error) => return SwiyuVerifyResult::invalid(error),
    };
    if let Err(error) = validate_expected_public_values(&expected) {
        return SwiyuVerifyResult::invalid(error);
    }
    let proof: R1CSSNARK<E> = match bincode::deserialize(proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            return SwiyuVerifyResult::invalid(format!("proof deserialization failed: {error}"))
        }
    };
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey = match bincode::deserialize(vk_bytes)
    {
        Ok(vk) => vk,
        Err(error) => {
            return SwiyuVerifyResult::invalid(format!(
                "verifying-key deserialization failed: {error}"
            ))
        }
    };

    verify_decoded(&proof, &vk, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
    use spartan2::traits::circuit::SpartanCircuit;

    #[derive(Clone, Debug)]
    struct NinePublicCircuit {
        values: [Scalar; SWIYU_PUBLIC_VALUE_COUNT],
    }

    impl SpartanCircuit<E> for NinePublicCircuit {
        fn synthesize<CS: ConstraintSystem<Scalar>>(
            &self,
            cs: &mut CS,
            _: &[AllocatedNum<Scalar>],
            _: &[AllocatedNum<Scalar>],
            _: Option<&[Scalar]>,
        ) -> Result<(), SynthesisError> {
            for (index, value) in self.values.iter().copied().enumerate() {
                let allocated =
                    AllocatedNum::alloc(cs.namespace(|| format!("value_{index}")), || Ok(value))?;
                cs.enforce(
                    || format!("value_{index}_identity"),
                    |lc| lc + allocated.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + allocated.get_variable(),
                );
                allocated.inputize(cs.namespace(|| format!("public_{index}")))?;
            }
            Ok(())
        }

        fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
            Ok(self.values.to_vec())
        }

        fn shared<CS: ConstraintSystem<Scalar>>(
            &self,
            _cs: &mut CS,
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            Ok(Vec::new())
        }

        fn precommitted<CS: ConstraintSystem<Scalar>>(
            &self,
            _cs: &mut CS,
            _shared: &[AllocatedNum<Scalar>],
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            Ok(Vec::new())
        }

        fn num_challenges(&self) -> usize {
            0
        }
    }

    fn context(values: &[Scalar]) -> Vec<u8> {
        values.iter().flat_map(encode_scalar).collect()
    }

    #[test]
    fn malformed_proof_is_a_failed_verification() {
        let expected = context(&vec![Scalar::ONE; SWIYU_PUBLIC_VALUE_COUNT]);
        let result = verify_swiyu(b"not a proof", b"not a key", &expected);
        assert!(!result.valid);
        assert!(result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("proof deserialization failed")));
    }

    #[test]
    fn wrong_sized_or_false_context_is_rejected_before_crypto() {
        // The former nine-scalar (288-byte) context must fail closed after the
        // status snapshot moved to two SHA-256 limbs.
        let wrong_size = verify_swiyu(&[], &[], &[0; SWIYU_PUBLIC_CONTEXT_BYTES - 32]);
        assert!(!wrong_size.valid);
        assert!(wrong_size
            .error
            .as_deref()
            .is_some_and(|error| error.contains("expected 320")));

        let false_result = context(&vec![Scalar::ZERO; SWIYU_PUBLIC_VALUE_COUNT]);
        let rejected = verify_swiyu(&[], &[], &false_result);
        assert!(!rejected.valid);
        assert_eq!(
            rejected.error.as_deref(),
            Some("expressionResult must equal one")
        );
    }

    #[test]
    fn scalar_context_encoding_is_canonical_little_endian() {
        let mut expected = [0_u8; SWIYU_SCALAR_BYTES];
        expected[0] = 42;
        assert_eq!(encode_scalar(&Scalar::from(42_u64)), expected);
        assert_eq!(
            decode_public_context(&context(&vec![Scalar::ONE; SWIYU_PUBLIC_VALUE_COUNT]))
                .expect("round trip"),
            vec![Scalar::ONE; SWIYU_PUBLIC_VALUE_COUNT]
        );
    }

    #[test]
    fn boundary_results_round_trip_without_rust_crypto_types() {
        let setup = SwiyuSetupResult {
            pk: vec![1, 2, 3],
            vk: vec![4, 5],
        };
        let proof = SwiyuProofResult {
            proof: vec![6, 7],
            public_values: vec![vec![0; SWIYU_SCALAR_BYTES]; SWIYU_PUBLIC_VALUE_COUNT],
        };
        let verified = SwiyuVerifyResult {
            valid: true,
            public_values: proof.public_values.clone(),
            error: None,
        };

        let setup_json = serde_json::to_vec(&setup).expect("serialize setup");
        assert_eq!(
            serde_json::from_slice::<SwiyuSetupResult>(&setup_json).expect("deserialize setup"),
            setup
        );
        let proof_bytes = bincode::serialize(&proof).expect("serialize proof result");
        assert_eq!(
            bincode::deserialize::<SwiyuProofResult>(&proof_bytes)
                .expect("deserialize proof result"),
            proof
        );
        let verify_json = serde_json::to_vec(&verified).expect("serialize verify result");
        assert_eq!(
            serde_json::from_slice::<SwiyuVerifyResult>(&verify_json)
                .expect("deserialize verify result"),
            verified
        );
    }

    #[test]
    fn valid_proof_fails_against_wrong_public_context() {
        let mut values = [Scalar::ONE; SWIYU_PUBLIC_VALUE_COUNT];
        for (index, value) in values.iter_mut().enumerate().skip(1) {
            *value = Scalar::from(index as u64 + 10);
        }
        let circuit = NinePublicCircuit { values };
        let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("test setup");
        let (proof, _, _) = prove_circuit_in_memory(circuit, &pk).expect("test proof");

        assert!(verify_decoded(&proof, &vk, &values).valid);
        let mut wrong_context = values;
        wrong_context[3] += Scalar::ONE;
        let rejected = verify_decoded(&proof, &vk, &wrong_context);
        assert!(!rejected.valid);
        assert_eq!(
            rejected.error.as_deref(),
            Some("proof public context mismatch")
        );
    }
}
