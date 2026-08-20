//! ECDSA and JWT circuit implementations using Spartan2
//!
//! This library provides zero-knowledge proof circuits for:
//! - ECDSA signature verification
//! - JWT token validation with selective disclosure
//!
//! The circuits use Spartan2's ZK-SNARK protocol with Hyrax polynomial commitment scheme.

use spartan2::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

pub mod circom_shared;
pub mod circuit_size;
pub mod circuits;
pub mod paths;
pub mod prover;
#[cfg(not(target_arch = "wasm32"))]
pub mod setup;
#[cfg(not(target_arch = "wasm32"))]
pub mod status_benchmark;
pub mod swiyu;
pub mod utils;

// Re-export commonly used types and functions
pub use circuit_size::CircuitSize;
pub use circuits::{
    mdoc_circuit::MdocCircuit,
    prepare_circuit::PrepareCircuit,
    show_circuit::ShowCircuit,
    swiyu_circuit::{SwiyuCircuit, SWIYU_CIRCUIT_NAME, SWIYU_PROFILE_ID, SWIYU_PUBLIC_VALUE_COUNT},
};
pub use paths::PathConfig;
pub use prover::{
    generate_mdoc_witness, generate_prepare_witness, prepare_circuit_assignment_in_memory,
    prove_circuit_in_memory, reblind_in_memory,
};
#[cfg(not(target_arch = "wasm32"))]
pub use prover::{
    generate_shared_blinds, prove_circuit, prove_circuit_with_pk, reblind,
    reblind_with_loaded_data, run_circuit, verify_circuit, verify_circuit_with_loaded_data,
};
#[cfg(not(target_arch = "wasm32"))]
pub use setup::{
    load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
    load_witness, save_keys, setup_circuit_keys, setup_circuit_keys_no_save,
};
#[cfg(not(target_arch = "wasm32"))]
pub use status_benchmark::{
    benchmark_status_profile, read_r1cs_compiler_stats, R1csCompilerStats, StatusArtifactProfile,
    StatusProofBenchmarkReport, STATUS_BENCHMARK_PUBLIC_VALUE_COUNT,
};
pub use swiyu::{
    prove_swiyu_from_witness, prove_swiyu_from_wtns, setup_swiyu, verify_swiyu, SwiyuProofResult,
    SwiyuSetupResult, SwiyuVerifyResult, SWIYU_PUBLIC_CONTEXT_BYTES,
};
pub use utils::{
    bigint_to_scalar, calculate_jwt_output_indices, calculate_mdoc_output_indices,
    convert_bigint_to_scalar, parse_jwt_inputs, parse_mdoc_inputs, parse_show_inputs,
    parse_witness,
};
