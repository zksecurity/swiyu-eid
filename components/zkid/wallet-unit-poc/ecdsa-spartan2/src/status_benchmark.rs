//! Same-system, status-only Spartan2 benchmark support for Prototype B.
//!
//! The artifact selector is a closed enum on purpose.  This module is not a
//! generic "prove any R1CS" production API: each accepted profile pins a
//! repository circuit name, public-value count, and root-context positions.

use crate::{parse_witness, prove_circuit_in_memory, Scalar, E};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use serde::Serialize;
use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use std::{
    any::type_name,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

pub const STATUS_BENCHMARK_PUBLIC_VALUE_COUNT: usize = 6;
const WITNESS_PREFIX_LEN: usize = 1 + STATUS_BENCHMARK_PUBLIC_VALUE_COUNT;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusArtifactProfile {
    DenseFixedIndexStatusV1,
    SparseValidNonmembershipV1,
}

impl StatusArtifactProfile {
    pub fn from_id(value: &str) -> Result<Self, String> {
        match value {
            "dense-fixed-index-status-v1" => Ok(Self::DenseFixedIndexStatusV1),
            "sparse-valid-nonmembership-v1" => Ok(Self::SparseValidNonmembershipV1),
            _ => Err(format!(
                "unsupported status artifact profile {value:?}; expected dense-fixed-index-status-v1 or sparse-valid-nonmembership-v1"
            )),
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::DenseFixedIndexStatusV1 => "dense-fixed-index-status-v1",
            Self::SparseValidNonmembershipV1 => "sparse-valid-nonmembership-v1",
        }
    }

    pub const fn circuit_name(self) -> &'static str {
        match self {
            Self::DenseFixedIndexStatusV1 => "swiyu_status_dense_17_bench",
            Self::SparseValidNonmembershipV1 => "swiyu_status_sparse_64_bench",
        }
    }

    pub const fn public_value_count(self) -> usize {
        STATUS_BENCHMARK_PUBLIC_VALUE_COUNT
    }

    /// `valid, epoch, rootHi, rootLo, queryHandleHi, queryHandleLo` in Circom
    /// witness order.
    pub const fn root_public_indices(self) -> [usize; 2] {
        [2, 3]
    }

    pub const fn query_handle_public_indices(self) -> [usize; 2] {
        [4, 5]
    }

    pub fn r1cs_path(self) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../circom/build")
            .join(self.circuit_name())
            .join(format!("{}_js", self.circuit_name()))
            .join(format!("{}.r1cs", self.circuit_name()))
    }
}

#[derive(Clone, Debug)]
struct StatusArtifactCircuit {
    profile: StatusArtifactProfile,
    witness: Option<Arc<Vec<Scalar>>>,
}

impl StatusArtifactCircuit {
    fn shape(profile: StatusArtifactProfile) -> Self {
        Self {
            profile,
            witness: None,
        }
    }

    fn with_witness(profile: StatusArtifactProfile, witness: Vec<Scalar>) -> Result<Self, String> {
        validate_witness(profile, &witness)?;
        Ok(Self {
            profile,
            witness: Some(Arc::new(witness)),
        })
    }

    fn witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        self.witness
            .as_ref()
            .map(|witness| witness.as_ref().clone())
            .ok_or(SynthesisError::AssignmentMissing)
    }
}

fn validate_witness(profile: StatusArtifactProfile, witness: &[Scalar]) -> Result<(), String> {
    if witness.len() < 1 + profile.public_value_count() {
        return Err(format!(
            "{} witness has {} values; expected at least {}",
            profile.id(),
            witness.len(),
            1 + profile.public_value_count()
        ));
    }
    if witness[0] != Scalar::ONE {
        return Err("Circom witness constant must equal one".to_owned());
    }
    if witness[1] != Scalar::ONE {
        return Err("status benchmark valid output must equal one".to_owned());
    }
    Ok(())
}

impl SpartanCircuit<E> for StatusArtifactCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let r1cs = load_r1cs::<Scalar>(self.profile.r1cs_path())
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        if type_name::<CS>().contains("ShapeCS") {
            synthesize(cs, r1cs, None)?;
        } else {
            synthesize(cs, r1cs, Some(self.witness()?))?;
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let witness = self.witness()?;
        validate_witness(self.profile, &witness).map_err(|_| SynthesisError::Unsatisfiable)?;
        Ok(witness[1..WITNESS_PREFIX_LEN].to_vec())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct R1csCompilerStats {
    pub constraints: u32,
    pub wires: u32,
    pub public_outputs: u32,
    pub public_inputs: u32,
    pub private_inputs: u32,
    pub labels: u64,
}

impl R1csCompilerStats {
    pub fn public_values(self) -> u32 {
        self.public_outputs + self.public_inputs
    }
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, String> {
    let mut bytes = [0_u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("read R1CS u32: {error}"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, String> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("read R1CS u64: {error}"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn parse_r1cs_stats<R: Read + Seek>(reader: &mut R) -> Result<R1csCompilerStats, String> {
    let mut magic = [0_u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("read R1CS magic: {error}"))?;
    if &magic != b"r1cs" {
        return Err("invalid R1CS magic".to_owned());
    }
    let version = read_u32(reader)?;
    if version != 1 {
        return Err(format!("unsupported R1CS version {version}"));
    }
    let sections = read_u32(reader)?;
    for _ in 0..sections {
        let section_type = read_u32(reader)?;
        let section_size = read_u64(reader)?;
        if section_type != 1 {
            let offset = i64::try_from(section_size)
                .map_err(|_| "R1CS section is too large to seek".to_owned())?;
            reader
                .seek(SeekFrom::Current(offset))
                .map_err(|error| format!("seek R1CS section: {error}"))?;
            continue;
        }

        if section_size > 4096 {
            return Err(format!("implausible R1CS header size {section_size}"));
        }
        let field_size = read_u32(reader)?;
        reader
            .seek(SeekFrom::Current(i64::from(field_size)))
            .map_err(|error| format!("seek R1CS prime: {error}"))?;
        return Ok(R1csCompilerStats {
            wires: read_u32(reader)?,
            public_outputs: read_u32(reader)?,
            public_inputs: read_u32(reader)?,
            private_inputs: read_u32(reader)?,
            labels: read_u64(reader)?,
            constraints: read_u32(reader)?,
        });
    }
    Err("R1CS header section is missing".to_owned())
}

pub fn read_r1cs_compiler_stats(path: &Path) -> Result<R1csCompilerStats, String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    parse_r1cs_stats(&mut file)
}

fn verify_against_context(
    proof: &R1CSSNARK<E>,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    expected: &[Scalar],
) -> bool {
    proof
        .verify(vk)
        .is_ok_and(|actual| actual.as_slice() == expected)
}

#[derive(Debug, Serialize)]
pub struct StatusProofBenchmarkReport {
    pub profile: &'static str,
    pub circuit: &'static str,
    pub relation: &'static str,
    pub compiler: R1csCompilerStats,
    pub r1cs_bytes: u64,
    pub witness_bytes: usize,
    pub setup_ms: u128,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub proving_key_bytes: u64,
    pub verifying_key_bytes: u64,
    pub proof_bytes: u64,
    pub public_context_bytes: usize,
    pub process_peak_rss_bytes: Option<u64>,
    pub verified: bool,
    pub tampered_public_root_rejected: bool,
    pub tampered_public_query_handle_rejected: bool,
}

fn relation(profile: StatusArtifactProfile) -> &'static str {
    match profile {
        StatusArtifactProfile::DenseFixedIndexStatusV1 => {
            "fixed depth-17 exact two-bit VALID membership"
        }
        StatusArtifactProfile::SparseValidNonmembershipV1 => {
            "depth-64 canonical-empty valid nonmembership"
        }
    }
}

#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage initializes the supplied rusage on success.
    let success = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0;
    if !success {
        return None;
    }
    // SAFETY: guarded by getrusage success above.
    let max_rss = unsafe { usage.assume_init() }.ru_maxrss as u64;
    #[cfg(target_os = "macos")]
    return Some(max_rss);
    #[cfg(not(target_os = "macos"))]
    return Some(max_rss.saturating_mul(1024));
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}

/// Run setup/prove/verify entirely in memory for one closed artifact profile.
/// The caller supplies a Circom `.wtns`; no key or proof files are persisted.
pub fn benchmark_status_profile(
    profile: StatusArtifactProfile,
    witness_wtns: &[u8],
) -> Result<StatusProofBenchmarkReport, String> {
    let r1cs_path = profile.r1cs_path();
    let compiler = read_r1cs_compiler_stats(&r1cs_path)?;
    let r1cs_bytes = std::fs::metadata(&r1cs_path)
        .map_err(|error| format!("stat {}: {error}", r1cs_path.display()))?
        .len();
    if compiler.public_values() as usize != profile.public_value_count() {
        return Err(format!(
            "{} R1CS exposes {} public values; pinned profile requires {}",
            profile.id(),
            compiler.public_values(),
            profile.public_value_count()
        ));
    }

    let witness = parse_witness(witness_wtns)
        .map_err(|error| format!("parse {} witness: {error:?}", profile.id()))?;
    let circuit = StatusArtifactCircuit::with_witness(profile, witness)?;
    let public_values = circuit
        .public_values()
        .map_err(|error| format!("extract public values: {error:?}"))?;

    let started = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(StatusArtifactCircuit::shape(profile))
        .map_err(|error| format!("{} setup failed: {error:?}", profile.id()))?;
    let setup_ms = started.elapsed().as_millis();

    let proving_key_bytes =
        bincode::serialized_size(&pk).map_err(|error| format!("measure proving key: {error}"))?;
    let verifying_key_bytes =
        bincode::serialized_size(&vk).map_err(|error| format!("measure verifying key: {error}"))?;

    let started = Instant::now();
    let (proof, _, _) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|error| format!("{} prove failed: {error:?}", profile.id()))?;
    let prove_ms = started.elapsed().as_millis();
    let proof_bytes =
        bincode::serialized_size(&proof).map_err(|error| format!("measure proof: {error}"))?;

    let started = Instant::now();
    let verified = verify_against_context(&proof, &vk, &public_values);
    let verify_ms = started.elapsed().as_millis();

    let mut tampered_context = public_values.clone();
    let root_index = profile.root_public_indices()[1];
    tampered_context[root_index] += Scalar::ONE;
    let tampered_public_root_rejected = !verify_against_context(&proof, &vk, &tampered_context);

    let mut tampered_handle_context = public_values.clone();
    let handle_index = profile.query_handle_public_indices()[1];
    tampered_handle_context[handle_index] += Scalar::ONE;
    let tampered_public_query_handle_rejected =
        !verify_against_context(&proof, &vk, &tampered_handle_context);

    Ok(StatusProofBenchmarkReport {
        profile: profile.id(),
        circuit: profile.circuit_name(),
        relation: relation(profile),
        compiler,
        r1cs_bytes,
        witness_bytes: witness_wtns.len(),
        setup_ms,
        prove_ms,
        verify_ms,
        proving_key_bytes,
        verifying_key_bytes,
        proof_bytes,
        public_context_bytes: public_values.len() * 32,
        process_peak_rss_bytes: peak_rss_bytes(),
        verified,
        tampered_public_root_rejected,
        tampered_public_query_handle_rejected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn artifact_selector_is_closed_and_pins_public_shape() {
        for (id, expected) in [
            (
                "dense-fixed-index-status-v1",
                StatusArtifactProfile::DenseFixedIndexStatusV1,
            ),
            (
                "sparse-valid-nonmembership-v1",
                StatusArtifactProfile::SparseValidNonmembershipV1,
            ),
        ] {
            let profile = StatusArtifactProfile::from_id(id).expect("known profile");
            assert_eq!(profile, expected);
            assert_eq!(profile.public_value_count(), 6);
            assert_eq!(profile.root_public_indices(), [2, 3]);
            assert_eq!(profile.query_handle_public_indices(), [4, 5]);
        }
        assert!(StatusArtifactProfile::from_id("../../arbitrary.r1cs").is_err());
    }

    #[test]
    fn parses_compiler_counts_from_r1cs_header() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"r1cs");
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&64_u64.to_le_bytes());
        bytes.extend_from_slice(&32_u32.to_le_bytes());
        bytes.extend_from_slice(&[0_u8; 32]);
        bytes.extend_from_slice(&1_001_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&5_u32.to_le_bytes());
        bytes.extend_from_slice(&77_u32.to_le_bytes());
        bytes.extend_from_slice(&2_002_u64.to_le_bytes());
        bytes.extend_from_slice(&999_u32.to_le_bytes());

        let stats = parse_r1cs_stats(&mut Cursor::new(bytes)).expect("valid header");
        assert_eq!(stats.constraints, 999);
        assert_eq!(stats.wires, 1_001);
        assert_eq!(stats.public_values(), 6);
        assert_eq!(stats.private_inputs, 77);
        assert_eq!(stats.labels, 2_002);
    }
}
