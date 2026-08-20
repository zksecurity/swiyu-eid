//! Exact native benchmark for the sound swiyu Prepare/Show experiment.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::reader::load_r1cs;
use ecdsa_spartan2::{
    circom_shared::synthesize_with_shared_outputs, parse_witness,
    prepare_circuit_assignment_in_memory, read_r1cs_compiler_stats, reblind_in_memory, Scalar, E,
};
use ff::{derive::rand_core::OsRng, Field};
use serde::Serialize;
use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

const SHARED_OUTPUTS: usize = 11;

#[derive(Clone, Debug)]
struct SplitCircuit {
    name: &'static str,
    r1cs: PathBuf,
    public_inputs: usize,
    witness: Option<Arc<Vec<Scalar>>>,
}

impl SplitCircuit {
    fn shape(name: &'static str, r1cs: PathBuf, public_inputs: usize) -> Self {
        Self {
            name,
            r1cs,
            public_inputs,
            witness: None,
        }
    }

    fn with_witness(&self, witness: Vec<Scalar>) -> Result<Self, String> {
        if witness.len() <= SHARED_OUTPUTS + self.public_inputs {
            return Err(format!(
                "{} witness is shorter than its public prefix",
                self.name
            ));
        }
        Ok(Self {
            witness: Some(Arc::new(witness)),
            ..self.clone()
        })
    }
}

impl SpartanCircuit<E> for SplitCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let r1cs = load_r1cs(&self.r1cs).map_err(|_| SynthesisError::AssignmentMissing)?;
        synthesize_with_shared_outputs(cs, r1cs, self.witness.as_deref().map(Vec::as_slice), shared)
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(match &self.witness {
            Some(witness) => {
                witness[(1 + SHARED_OUTPUTS)..(1 + SHARED_OUTPUTS + self.public_inputs)].to_vec()
            }
            None => vec![Scalar::ZERO; self.public_inputs],
        })
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        (0..SHARED_OUTPUTS)
            .map(|index| {
                let value = self
                    .witness
                    .as_ref()
                    .map(|witness| witness[1 + index])
                    .unwrap_or(Scalar::ZERO);
                AllocatedNum::alloc(cs.namespace(|| format!("shared_output_{index}")), || {
                    Ok(value)
                })
            })
            .collect()
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

#[derive(Serialize)]
struct StageReport {
    constraints: u32,
    wires: u32,
    r1cs_bytes: u64,
    wasm_bytes: u64,
    witness_bytes: u64,
    witness_handoff_ms: f64,
    setup_ms: f64,
    key_serialization_ms: f64,
    assignment_ms: f64,
    prepared_state_serialization_ms: f64,
    final_proof_ms: f64,
    proof_serialization_ms: f64,
    proof_deserialization_ms: f64,
    verify_ms: f64,
    proving_key_bytes: u64,
    verifying_key_bytes: u64,
    final_proof_bytes: u64,
    pre_reblind_instance_bytes: u64,
    assignment_bytes: u64,
    public_input_count: usize,
    hidden_shared_value_count: usize,
    verified: bool,
}

#[derive(Serialize)]
struct LinkageReport {
    linked_outputs_identical: bool,
    pre_reblind_commitments_differ: bool,
    reblinded_commitments_equal: bool,
    link_randomness_ms: f64,
    unlinked_show_assignment_ms: f64,
    unlinked_show_final_proof_ms: f64,
    unlinked_show_verified: bool,
    unlinked_commitment_rejected: bool,
}

#[derive(Serialize)]
struct Report {
    profile: &'static str,
    generated_at_unix_seconds: u64,
    prepare: StageReport,
    show: StageReport,
    linkage: LinkageReport,
    process_peak_rss_bytes: Option<u64>,
}

#[derive(Serialize)]
struct RepetitionRule {
    first_two_principal_stage_variation_over_15_percent: bool,
    required_runs: usize,
    satisfied: bool,
}

#[derive(Serialize)]
struct TimingStats {
    values: Vec<f64>,
    min: f64,
    median: f64,
    max: f64,
    mean: f64,
    variance: f64,
    standard_deviation: f64,
    coefficient_of_variation: f64,
}

#[derive(Serialize)]
struct TimingSummary {
    prepare_setup_ms: TimingStats,
    prepare_assignment_ms: TimingStats,
    prepare_final_proof_ms: TimingStats,
    prepare_verify_ms: TimingStats,
    show_setup_ms: TimingStats,
    show_assignment_ms: TimingStats,
    show_final_proof_ms: TimingStats,
    show_verify_ms: TimingStats,
}

#[derive(Serialize)]
struct BenchmarkReport {
    profile: &'static str,
    run_count: usize,
    repetition_rule: RepetitionRule,
    timing_milliseconds: TimingSummary,
    raw_runs: Vec<Report>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("swiyu-canton-benchmark: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let output =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom/build/swiyu_canton_benchmark");
    let mut reports = Vec::new();
    reports.push(run_once()?);
    let fixed_single_run = env::var("BENCHMARK_RUNS").as_deref() == Ok("1");
    if !fixed_single_run {
        reports.push(run_once()?);
    }
    let variable = !fixed_single_run && first_two_vary_over_15_percent(&reports);
    let required_runs = if fixed_single_run {
        1
    } else if variable {
        7
    } else {
        3
    };
    while reports.len() < required_runs {
        reports.push(run_once()?);
    }
    for (index, report) in reports.iter().enumerate() {
        let json = serde_json::to_string_pretty(report).map_err(|error| error.to_string())?;
        fs::write(
            output.join(format!("report-run-{}.json", index + 1)),
            format!("{json}\n"),
        )
        .map_err(|error| format!("write raw report: {error}"))?;
    }
    let summary = BenchmarkReport {
        profile: "swiyu.canton-eligibility.prepare-show.v1",
        run_count: reports.len(),
        repetition_rule: RepetitionRule {
            first_two_principal_stage_variation_over_15_percent: variable,
            required_runs,
            satisfied: reports.len() >= required_runs,
        },
        timing_milliseconds: timing_summary(&reports),
        raw_runs: reports,
    };
    let json = serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?;
    fs::write(
        output.join("canton-benchmark-results.json"),
        format!("{json}\n"),
    )
    .map_err(|error| format!("write benchmark summary: {error}"))?;
    println!("{json}");
    Ok(())
}

fn run_once() -> Result<Report, String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom");
    let output = root.join("build/swiyu_canton_benchmark");
    let prepare_shape = SplitCircuit::shape(
        "prepare",
        root.join("build/swiyu_canton_prepare_compact/swiyu_canton_prepare_compact.r1cs"),
        2,
    );
    let show_shape = SplitCircuit::shape(
        "show",
        root.join("build/swiyu_canton_show_split/swiyu_canton_show_split.r1cs"),
        11,
    );
    let prepare_wtns = output.join("prepare.wtns");
    let show_wtns = output.join("show.wtns");
    let prepare_witness_started = Instant::now();
    let prepare_witness = parse_witness(&read(&prepare_wtns)?)
        .map_err(|error| format!("parse prepare witness: {error:?}"))?;
    let prepare_witness_handoff_ms = elapsed_ms(prepare_witness_started);
    let show_witness_started = Instant::now();
    let show_witness = parse_witness(&read(&show_wtns)?)
        .map_err(|error| format!("parse show witness: {error:?}"))?;
    let show_witness_handoff_ms = elapsed_ms(show_witness_started);
    let show_shared_values = show_witness[1..=SHARED_OUTPUTS].to_vec();
    let linked_outputs_identical = prepare_witness[1..=SHARED_OUTPUTS] == show_shared_values;
    if !linked_outputs_identical {
        return Err("Prepare and Show shared output vectors differ".to_owned());
    }

    let prepare_circuit = prepare_shape.with_witness(prepare_witness)?;
    let prepare_expected_public = prepare_circuit
        .public_values()
        .map_err(|error| format!("Prepare public values: {error:?}"))?;
    let started = Instant::now();
    let (prepare_pk, prepare_vk) = R1CSSNARK::<E>::setup(prepare_shape.clone())
        .map_err(|error| format!("Prepare setup: {error:?}"))?;
    let prepare_setup_ms = elapsed_ms(started);
    let prepare_pk_bytes = serialized_size(&prepare_pk)?;
    let prepare_vk_bytes = serialized_size(&prepare_vk)?;
    let key_serialization_started = Instant::now();
    serialize_to_sink(&prepare_pk)?;
    serialize_to_sink(&prepare_vk)?;
    let prepare_key_serialization_ms = elapsed_ms(key_serialization_started);
    let started = Instant::now();
    let (prepare_instance, prepare_assignment) =
        prepare_circuit_assignment_in_memory(prepare_circuit, &prepare_pk)
            .map_err(|error| format!("Prepare assignment: {error:?}"))?;
    let prepare_assignment_ms = elapsed_ms(started);
    let randomness_started = Instant::now();
    let randomness: Vec<Scalar> = (0..prepare_instance.num_shared_rows())
        .map(|_| Scalar::random(&mut OsRng))
        .collect();
    let link_randomness_ms = elapsed_ms(randomness_started);
    let prepare_initial_commitment = bincode::serialize(&prepare_instance.comm_W_shared)
        .map_err(|error| format!("serialize Prepare instance commitment: {error}"))?;
    let prepare_instance_bytes = serialized_size(&prepare_instance)?;
    let prepare_assignment_bytes = serialized_size(&prepare_assignment)?;
    let prepared_state_serialization_started = Instant::now();
    serialize_to_sink(&prepare_instance)?;
    serialize_to_sink(&prepare_assignment)?;
    let prepare_prepared_state_serialization_ms = elapsed_ms(prepared_state_serialization_started);
    let started = Instant::now();
    let (prepare_proof, _, _) = reblind_in_memory(
        &prepare_pk,
        prepare_instance,
        prepare_assignment,
        &randomness,
    )
    .map_err(|error| format!("Prepare reblind: {error:?}"))?;
    let prepare_final_proof_ms = elapsed_ms(started);
    let started = Instant::now();
    let prepare_proof_bytes = bincode::serialize(&prepare_proof)
        .map_err(|error| format!("serialize Prepare proof: {error}"))?;
    let prepare_proof_serialization_ms = elapsed_ms(started);
    drop(prepare_proof);
    let started = Instant::now();
    let prepare_proof: R1CSSNARK<E> = bincode::deserialize(&prepare_proof_bytes)
        .map_err(|error| format!("deserialize Prepare proof: {error}"))?;
    let prepare_proof_deserialization_ms = elapsed_ms(started);
    let prepare_commitment = bincode::serialize(prepare_proof.comm_W_shared())
        .map_err(|error| format!("serialize reblinded Prepare commitment: {error}"))?;
    let started = Instant::now();
    let prepare_verified = prepare_proof
        .verify(&prepare_vk)
        .is_ok_and(|actual| actual == prepare_expected_public);
    let prepare_verify_ms = elapsed_ms(started);
    let prepare_report = artifact_report(
        &root,
        &prepare_shape,
        &prepare_wtns,
        prepare_witness_handoff_ms,
        prepare_setup_ms,
        prepare_key_serialization_ms,
        prepare_assignment_ms,
        prepare_prepared_state_serialization_ms,
        prepare_final_proof_ms,
        prepare_proof_serialization_ms,
        prepare_proof_deserialization_ms,
        prepare_verify_ms,
        prepare_pk_bytes,
        prepare_vk_bytes,
        prepare_proof_bytes.len() as u64,
        prepare_instance_bytes,
        prepare_assignment_bytes,
        prepare_verified,
    )?;
    drop(prepare_proof);
    drop(prepare_proof_bytes);
    drop(prepare_pk);
    drop(prepare_vk);

    let show_circuit = show_shape.with_witness(show_witness)?;
    let show_expected_public = show_circuit
        .public_values()
        .map_err(|error| format!("Show public values: {error:?}"))?;
    let started = Instant::now();
    let (show_pk, show_vk) = R1CSSNARK::<E>::setup(show_shape.clone())
        .map_err(|error| format!("Show setup: {error:?}"))?;
    let show_setup_ms = elapsed_ms(started);
    let show_pk_bytes = serialized_size(&show_pk)?;
    let show_vk_bytes = serialized_size(&show_vk)?;
    let key_serialization_started = Instant::now();
    serialize_to_sink(&show_pk)?;
    serialize_to_sink(&show_vk)?;
    let show_key_serialization_ms = elapsed_ms(key_serialization_started);
    let started = Instant::now();
    let (show_instance, show_assignment) =
        prepare_circuit_assignment_in_memory(show_circuit, &show_pk)
            .map_err(|error| format!("Show assignment: {error:?}"))?;
    let show_assignment_ms = elapsed_ms(started);
    let show_initial_commitment = bincode::serialize(&show_instance.comm_W_shared)
        .map_err(|error| format!("serialize Show instance commitment: {error}"))?;
    let show_instance_bytes = serialized_size(&show_instance)?;
    let show_assignment_bytes = serialized_size(&show_assignment)?;
    let prepared_state_serialization_started = Instant::now();
    serialize_to_sink(&show_instance)?;
    serialize_to_sink(&show_assignment)?;
    let show_prepared_state_serialization_ms = elapsed_ms(prepared_state_serialization_started);
    let started = Instant::now();
    let (show_proof, _, _) =
        reblind_in_memory(&show_pk, show_instance, show_assignment, &randomness)
            .map_err(|error| format!("Show reblind: {error:?}"))?;
    let show_final_proof_ms = elapsed_ms(started);
    let started = Instant::now();
    let show_proof_bytes = bincode::serialize(&show_proof)
        .map_err(|error| format!("serialize Show proof: {error}"))?;
    let show_proof_serialization_ms = elapsed_ms(started);
    drop(show_proof);
    let started = Instant::now();
    let show_proof: R1CSSNARK<E> = bincode::deserialize(&show_proof_bytes)
        .map_err(|error| format!("deserialize Show proof: {error}"))?;
    let show_proof_deserialization_ms = elapsed_ms(started);
    let show_commitment = bincode::serialize(show_proof.comm_W_shared())
        .map_err(|error| format!("serialize reblinded Show commitment: {error}"))?;
    let started = Instant::now();
    let show_verified = show_proof
        .verify(&show_vk)
        .is_ok_and(|actual| actual == show_expected_public);
    let show_verify_ms = elapsed_ms(started);
    let show_report = artifact_report(
        &root,
        &show_shape,
        &show_wtns,
        show_witness_handoff_ms,
        show_setup_ms,
        show_key_serialization_ms,
        show_assignment_ms,
        show_prepared_state_serialization_ms,
        show_final_proof_ms,
        show_proof_serialization_ms,
        show_proof_deserialization_ms,
        show_verify_ms,
        show_pk_bytes,
        show_vk_bytes,
        show_proof_bytes.len() as u64,
        show_instance_bytes,
        show_assignment_bytes,
        show_verified,
    )?;
    // Capture the production linked Prepare/Show peak before running the
    // adversarial unlinked-proof check below. The negative fixture is a
    // soundness test, not part of a wallet presentation lifecycle.
    let process_peak_rss_bytes = peak_rss_bytes();

    let unlinked_wtns = output.join("show-unlinked.wtns");
    let unlinked_witness = parse_witness(&read(&unlinked_wtns)?)
        .map_err(|error| format!("parse unlinked show witness: {error:?}"))?;
    if show_shared_values == unlinked_witness[1..=SHARED_OUTPUTS] {
        return Err("negative fixture did not change a shared output".to_owned());
    }
    let unlinked_circuit = show_shape.with_witness(unlinked_witness)?;
    let started = Instant::now();
    let (unlinked_instance, unlinked_assignment) =
        prepare_circuit_assignment_in_memory(unlinked_circuit, &show_pk)
            .map_err(|error| format!("unlinked Show assignment: {error:?}"))?;
    let unlinked_show_assignment_ms = elapsed_ms(started);
    let started = Instant::now();
    let (unlinked_proof, _, _) = reblind_in_memory(
        &show_pk,
        unlinked_instance,
        unlinked_assignment,
        &randomness,
    )
    .map_err(|error| format!("unlinked Show reblind: {error:?}"))?;
    let unlinked_show_final_proof_ms = elapsed_ms(started);
    let unlinked_show_verified = unlinked_proof.verify(&show_vk).is_ok();
    let unlinked_commitment = bincode::serialize(unlinked_proof.comm_W_shared())
        .map_err(|error| format!("serialize unlinked commitment: {error}"))?;

    let report = Report {
        profile: "swiyu.canton-eligibility.prepare-show.v1",
        generated_at_unix_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        prepare: prepare_report,
        show: show_report,
        linkage: LinkageReport {
            linked_outputs_identical,
            pre_reblind_commitments_differ: prepare_initial_commitment != show_initial_commitment,
            reblinded_commitments_equal: prepare_commitment == show_commitment,
            link_randomness_ms,
            unlinked_show_assignment_ms,
            unlinked_show_final_proof_ms,
            unlinked_show_verified,
            unlinked_commitment_rejected: unlinked_commitment != prepare_commitment,
        },
        process_peak_rss_bytes,
    };
    Ok(report)
}

fn first_two_vary_over_15_percent(reports: &[Report]) -> bool {
    let first = &reports[0];
    let second = &reports[1];
    [
        (first.prepare.setup_ms, second.prepare.setup_ms),
        (first.prepare.assignment_ms, second.prepare.assignment_ms),
        (first.prepare.final_proof_ms, second.prepare.final_proof_ms),
        (first.prepare.verify_ms, second.prepare.verify_ms),
        (first.show.setup_ms, second.show.setup_ms),
        (first.show.assignment_ms, second.show.assignment_ms),
        (first.show.final_proof_ms, second.show.final_proof_ms),
        (first.show.verify_ms, second.show.verify_ms),
    ]
    .into_iter()
    .any(|(a, b)| {
        let pair_mean = (a + b) / 2.0;
        pair_mean > 0.0 && (a - b).abs() / pair_mean > 0.15
    })
}

fn timing_summary(reports: &[Report]) -> TimingSummary {
    TimingSummary {
        prepare_setup_ms: stats(reports.iter().map(|run| run.prepare.setup_ms).collect()),
        prepare_assignment_ms: stats(
            reports
                .iter()
                .map(|run| run.prepare.assignment_ms)
                .collect(),
        ),
        prepare_final_proof_ms: stats(
            reports
                .iter()
                .map(|run| run.prepare.final_proof_ms)
                .collect(),
        ),
        prepare_verify_ms: stats(reports.iter().map(|run| run.prepare.verify_ms).collect()),
        show_setup_ms: stats(reports.iter().map(|run| run.show.setup_ms).collect()),
        show_assignment_ms: stats(reports.iter().map(|run| run.show.assignment_ms).collect()),
        show_final_proof_ms: stats(reports.iter().map(|run| run.show.final_proof_ms).collect()),
        show_verify_ms: stats(reports.iter().map(|run| run.show.verify_ms).collect()),
    }
}

fn stats(values: Vec<f64>) -> TimingStats {
    let mut ordered = values.clone();
    ordered.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = if values.len() > 1 {
        values
            .iter()
            .map(|value| (*value - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64
    } else {
        0.0
    };
    let standard_deviation = variance.sqrt();
    TimingStats {
        values,
        min: ordered[0],
        median: ordered[ordered.len() / 2],
        max: *ordered.last().expect("non-empty timing set"),
        mean,
        variance,
        standard_deviation,
        coefficient_of_variation: if mean == 0.0 {
            0.0
        } else {
            standard_deviation / mean
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn artifact_report(
    root: &Path,
    shape: &SplitCircuit,
    witness: &Path,
    witness_handoff_ms: f64,
    setup_ms: f64,
    key_serialization_ms: f64,
    assignment_ms: f64,
    prepared_state_serialization_ms: f64,
    final_proof_ms: f64,
    proof_serialization_ms: f64,
    proof_deserialization_ms: f64,
    verify_ms: f64,
    proving_key_bytes: u64,
    verifying_key_bytes: u64,
    final_proof_bytes: u64,
    pre_reblind_instance_bytes: u64,
    assignment_bytes: u64,
    verified: bool,
) -> Result<StageReport, String> {
    let compiler = read_r1cs_compiler_stats(&shape.r1cs)?;
    let circuit = if shape.name == "prepare" {
        "swiyu_canton_prepare_compact"
    } else {
        "swiyu_canton_show_split"
    };
    Ok(StageReport {
        constraints: compiler.constraints,
        wires: compiler.wires,
        r1cs_bytes: file_size(&shape.r1cs)?,
        wasm_bytes: file_size(&root.join(format!("build/{circuit}/{circuit}_js/{circuit}.wasm")))?,
        witness_bytes: file_size(witness)?,
        witness_handoff_ms,
        setup_ms,
        key_serialization_ms,
        assignment_ms,
        prepared_state_serialization_ms,
        final_proof_ms,
        proof_serialization_ms,
        proof_deserialization_ms,
        verify_ms,
        proving_key_bytes,
        verifying_key_bytes,
        final_proof_bytes,
        pre_reblind_instance_bytes,
        assignment_bytes,
        public_input_count: shape.public_inputs,
        hidden_shared_value_count: SHARED_OUTPUTS,
        verified,
    })
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn serialized_size<T: Serialize>(value: &T) -> Result<u64, String> {
    bincode::serialized_size(value).map_err(|error| format!("serialized size: {error}"))
}

fn serialize_to_sink<T: Serialize>(value: &T) -> Result<(), String> {
    bincode::serialize_into(std::io::sink(), value)
        .map_err(|error| format!("serialize to sink: {error}"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn file_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| format!("stat {}: {error}", path.display()))
}

#[cfg(target_os = "macos")]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    (result == 0).then(|| unsafe { usage.assume_init().ru_maxrss as u64 })
}

#[cfg(target_os = "linux")]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    (result == 0).then(|| unsafe { usage.assume_init().ru_maxrss as u64 * 1024 })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peak_rss_bytes() -> Option<u64> {
    None
}
