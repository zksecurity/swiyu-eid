//! Spartan wrapper for the fixed swiyu age/status relation.
//!
//! This is deliberately a single circuit with no shared witness.  The public
//! values are copied directly from Circom witness slots 1 through 10, in this
//! order:
//!
//! 0. `expressionResult` (must be one at verification)
//! 1. `issuerPubKeyX`
//! 2. `issuerPubKeyY`
//! 3. `challengeHash`
//! 4. `cutoffDate`
//! 5. `currentTime`
//! 6. `expectedMetadataHashHi`
//! 7. `expectedMetadataHashLo`
//! 8. `expectedStatusSnapshotHashHi`
//! 9. `expectedStatusSnapshotHashLo`

use super::synthesize_witness_only;
#[cfg(feature = "native-witness")]
use crate::parse_witness;
use crate::{paths::PathConfig, Scalar, E};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub const SWIYU_CIRCUIT_NAME: &str = "swiyu_age18_status_2k";
pub const SWIYU_PROFILE_ID: &str = "swiyu-age18-status-2k-v0";
pub const SWIYU_PUBLIC_VALUE_COUNT: usize = 10;
const SWIYU_WITNESS_PREFIX_LEN: usize = 1 + SWIYU_PUBLIC_VALUE_COUNT;

#[cfg(all(feature = "native-witness", has_circuit_swiyu_age18_status_2k))]
witnesscalc_adapter::witness!(swiyu_age18_status_2k);

/// Generate a native Circom witness when the matching C++ circuit was present
/// at build time. Browser builds always provide a `.wtns` through
/// [`SwiyuCircuit::with_witness`].
#[cfg(feature = "native-witness")]
fn call_swiyu_witness(inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    #[cfg(has_circuit_swiyu_age18_status_2k)]
    {
        return swiyu_age18_status_2k_witness(inputs_json)
            .map_err(|_| SynthesisError::Unsatisfiable);
    }

    #[cfg(not(has_circuit_swiyu_age18_status_2k))]
    {
        let _ = inputs_json;
        Err(SynthesisError::AssignmentMissing)
    }
}

fn validate_witness(witness: &[Scalar]) -> Result<(), SynthesisError> {
    if witness.len() < SWIYU_WITNESS_PREFIX_LEN || witness[0] != Scalar::ONE {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(())
}

/// Opt-in wrapper around the `swiyu-age18-status-2k-v0` profile's
/// `swiyu_age18_status_2k.r1cs` relation.
#[derive(Debug, Clone)]
pub struct SwiyuCircuit {
    path_config: PathConfig,
    #[cfg_attr(not(feature = "native-witness"), allow(dead_code))]
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for SwiyuCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl SwiyuCircuit {
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self::new(PathConfig::development(), path.into())
    }

    /// Construct a prover circuit from an externally calculated Circom witness.
    pub fn with_witness(witness: Vec<Scalar>) -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(Some(witness))),
        }
    }

    #[cfg(feature = "native-witness")]
    fn input_json_path(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|path| self.path_config.resolve(path))
            .unwrap_or_else(|| {
                if self.path_config.is_mobile {
                    self.path_config
                        .base_dir
                        .join(format!("{SWIYU_CIRCUIT_NAME}_input.json"))
                } else {
                    self.path_config.base_dir.join(format!(
                        "../circom/inputs/{SWIYU_CIRCUIT_NAME}/default.json"
                    ))
                }
            })
    }

    /// The exact R1CS used by setup. The size is part of the fixed profile name;
    /// it is not selected through the generic JWT size setting.
    pub fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path(SWIYU_CIRCUIT_NAME)
    }

    fn cached_witness(&self) -> Result<Option<Vec<Scalar>>, SynthesisError> {
        self.cached_witness
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        if let Some(witness) = self.cached_witness()? {
            validate_witness(&witness)?;
            return Ok(witness);
        }

        #[cfg(feature = "native-witness")]
        {
            let input_json = std::fs::read_to_string(self.input_json_path())
                .map_err(|_| SynthesisError::AssignmentMissing)?;
            // Reject malformed input here rather than handing implementation-
            // dependent text to witnesscalc.
            serde_json::from_str::<serde_json::Value>(&input_json)
                .map_err(|_| SynthesisError::AssignmentMissing)?;
            let witness = parse_witness(&call_swiyu_witness(&input_json)?)?;
            validate_witness(&witness)?;
            let mut cache = self
                .cached_witness
                .lock()
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            *cache = Some(witness.clone());
            return Ok(witness);
        }

        #[cfg(not(feature = "native-witness"))]
        Err(SynthesisError::AssignmentMissing)
    }
}

impl SpartanCircuit<E> for SwiyuCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        if type_name::<CS>().contains("ShapeCS") {
            let r1cs =
                load_r1cs(self.r1cs_path()).map_err(|_| SynthesisError::AssignmentMissing)?;
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;
        match load_r1cs::<Scalar>(&self.r1cs_path()) {
            Ok(r1cs) => {
                synthesize(cs, r1cs, Some(witness))?;
            }
            // WASM packages carry the proving key and external witness, not the
            // multi-megabyte R1CS. The proving key already contains A/B/C.
            Err(_) => {
                synthesize_witness_only(cs, &witness, SWIYU_PUBLIC_VALUE_COUNT)?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let witness = self.get_or_generate_witness()?;
        validate_witness(&witness)?;
        Ok(witness[1..SWIYU_WITNESS_PREFIX_LEN].to_vec())
    }

    /// The swiyu profile is one session-bound proof; it intentionally has no
    /// Prepare/Show shared commitment surface.
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

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;

    fn witness_with_public_values() -> Vec<Scalar> {
        let mut witness = vec![Scalar::ONE];
        witness.extend((1..=SWIYU_PUBLIC_VALUE_COUNT).map(|value| Scalar::from(value as u64)));
        witness.push(Scalar::from(99_u64));
        witness
    }

    #[test]
    fn public_values_follow_circom_witness_order() {
        let circuit = SwiyuCircuit::with_witness(witness_with_public_values());
        let public = circuit.public_values().expect("valid public values");
        let expected: Vec<_> = (1..=SWIYU_PUBLIC_VALUE_COUNT)
            .map(|value| Scalar::from(value as u64))
            .collect();
        assert_eq!(public, expected);
    }

    #[test]
    fn short_or_noncanonical_witness_prefix_is_rejected() {
        let short = SwiyuCircuit::with_witness(vec![Scalar::ONE; SWIYU_PUBLIC_VALUE_COUNT]);
        assert!(short.public_values().is_err());

        let mut bad_constant = witness_with_public_values();
        bad_constant[0] = Scalar::ZERO;
        assert!(SwiyuCircuit::with_witness(bad_constant)
            .public_values()
            .is_err());
    }

    #[test]
    fn single_proof_relation_has_no_shared_witness() {
        let circuit = SwiyuCircuit::with_witness(witness_with_public_values());
        let mut cs = TestConstraintSystem::<Scalar>::new();
        assert!(circuit
            .shared(&mut cs)
            .expect("shared allocation")
            .is_empty());
    }

    #[test]
    fn fixed_profile_uses_exact_r1cs_path() {
        let circuit = SwiyuCircuit::new(PathConfig::new("/project", false), None);
        assert_eq!(
            circuit.r1cs_path(),
            PathBuf::from(
                "/project/../circom/build/swiyu_age18_status_2k/swiyu_age18_status_2k_js/swiyu_age18_status_2k.r1cs"
            )
        );
        assert_eq!(SWIYU_PROFILE_ID, "swiyu-age18-status-2k-v0");
    }
}
