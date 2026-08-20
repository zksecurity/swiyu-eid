//! One-shot CLI for the two closed Prototype B status artifact profiles.

use ecdsa_spartan2::{benchmark_status_profile, StatusArtifactProfile};
use std::{env, fs, path::Path, process};

fn usage() -> ! {
    eprintln!(
        "Usage: status-proof-benchmark PROFILE WTNS\n\nPROFILE must be one of:\n  dense-fixed-index-status-v1\n  sparse-valid-nonmembership-v1"
    );
    process::exit(2);
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let profile = StatusArtifactProfile::from_id(&args.next().unwrap_or_else(|| usage()))?;
    let witness_path = args.next().unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }
    let witness = fs::read(Path::new(&witness_path))
        .map_err(|error| format!("read {witness_path}: {error}"))?;
    let report = benchmark_status_profile(profile, &witness)?;
    if !report.verified
        || !report.tampered_public_root_rejected
        || !report.tampered_public_query_handle_rejected
    {
        return Err("benchmark verification invariant failed".to_owned());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("serialize report: {error}"))?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("status-proof-benchmark: {error}");
        process::exit(1);
    }
}
