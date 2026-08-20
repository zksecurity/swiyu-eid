//! Minimal native lifecycle for the fixed swiyu proof profile.
//!
//! This binary intentionally consumes a Circom `.wtns`: witness generation
//! stays in the wallet SDK, while setup/proving/verification use the exact
//! Spartan relation and stable on-disk key convention.

use ecdsa_spartan2::{
    prove_swiyu_from_wtns, setup_swiyu, verify_swiyu, SWIYU_CIRCUIT_NAME, SWIYU_PROFILE_ID,
};
use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    time::Instant,
};

const PK_NAME: &str = "swiyu_age18_status_2k_proving.key";
const VK_NAME: &str = "swiyu_age18_status_2k_verifying.key";
const PROOF_NAME: &str = "swiyu_age18_status_2k.proof";
const CONTEXT_NAME: &str = "swiyu_age18_status_2k.public-context";

#[derive(Serialize)]
struct BenchmarkReport {
    profile: &'static str,
    circuit: &'static str,
    setup_ms: u128,
    prove_ms: u128,
    verify_ms: u128,
    proving_key_bytes: usize,
    verifying_key_bytes: usize,
    proof_bytes: usize,
    public_context_bytes: usize,
    verified: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  swiyu-profile setup [OUT_DIR]\n  swiyu-profile prove WTNS [OUT_DIR]\n  swiyu-profile verify [OUT_DIR]\n  swiyu-profile benchmark WTNS [OUT_DIR]\n\nRun from wallet-unit-poc/ecdsa-spartan2 so the fixed R1CS path resolves."
    );
    process::exit(2);
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn paths(out: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    (
        out.join(PK_NAME),
        out.join(VK_NAME),
        out.join(PROOF_NAME),
        out.join(CONTEXT_NAME),
    )
}

fn setup(out: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let result = setup_swiyu()?;
    let (pk, vk, _, _) = paths(out);
    write(&pk, &result.pk)?;
    write(&vk, &result.vk)?;
    Ok((result.pk, result.vk))
}

fn prove(wtns: &Path, out: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk_path, _, proof_path, context_path) = paths(out);
    let result = prove_swiyu_from_wtns(&read(&pk_path)?, &read(wtns)?)?;
    let context: Vec<u8> = result.public_values.into_iter().flatten().collect();
    write(&proof_path, &result.proof)?;
    write(&context_path, &context)?;
    Ok((result.proof, context))
}

fn verify(out: &Path) -> Result<bool, String> {
    let (_, vk, proof, context) = paths(out);
    let result = verify_swiyu(&read(&proof)?, &read(&vk)?, &read(&context)?);
    if result.valid {
        Ok(true)
    } else {
        Err(result
            .error
            .unwrap_or_else(|| "verification failed".to_owned()))
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        usage();
    };

    match command {
        "setup" => {
            let out = Path::new(args.get(1).map(String::as_str).unwrap_or("keys"));
            let (pk, vk) = setup(out)?;
            println!(
                "setup profile={} circuit={} pk_bytes={} vk_bytes={}",
                SWIYU_PROFILE_ID,
                SWIYU_CIRCUIT_NAME,
                pk.len(),
                vk.len()
            );
        }
        "prove" => {
            let Some(wtns) = args.get(1) else { usage() };
            let out = Path::new(args.get(2).map(String::as_str).unwrap_or("keys"));
            let (proof, context) = prove(Path::new(wtns), out)?;
            println!(
                "proof_bytes={} context_bytes={}",
                proof.len(),
                context.len()
            );
        }
        "verify" => {
            let out = Path::new(args.get(1).map(String::as_str).unwrap_or("keys"));
            verify(out)?;
            println!(
                "verified profile={} circuit={}",
                SWIYU_PROFILE_ID, SWIYU_CIRCUIT_NAME
            );
        }
        "benchmark" => {
            let Some(wtns) = args.get(1) else { usage() };
            let out = Path::new(args.get(2).map(String::as_str).unwrap_or("keys"));

            let started = Instant::now();
            let (pk, vk) = setup(out)?;
            let setup_ms = started.elapsed().as_millis();

            let started = Instant::now();
            let (proof, context) = prove(Path::new(wtns), out)?;
            let prove_ms = started.elapsed().as_millis();

            let started = Instant::now();
            let verified = verify(out)?;
            let verify_ms = started.elapsed().as_millis();

            let report = BenchmarkReport {
                profile: SWIYU_PROFILE_ID,
                circuit: SWIYU_CIRCUIT_NAME,
                setup_ms,
                prove_ms,
                verify_ms,
                proving_key_bytes: pk.len(),
                verifying_key_bytes: vk.len(),
                proof_bytes: proof.len(),
                public_context_bytes: context.len(),
                verified,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|error| format!("serialize benchmark report: {error}"))?
            );
        }
        _ => usage(),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("swiyu-profile: {error}");
        process::exit(1);
    }
}
