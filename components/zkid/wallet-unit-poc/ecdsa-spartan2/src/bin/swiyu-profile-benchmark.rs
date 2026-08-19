//! Repeated exact benchmark for any linked swiyu Prepare/Show profile.

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
use std::{fs, path::PathBuf, sync::Arc, time::Instant};

#[derive(Clone, Debug)]
struct Circuit {
    r1cs: PathBuf,
    public_inputs: usize,
    shared_outputs: usize,
    witness: Option<Arc<Vec<Scalar>>>,
}

impl Circuit {
    fn shape(r1cs: PathBuf, public_inputs: usize, shared_outputs: usize) -> Self {
        Self {
            r1cs,
            public_inputs,
            shared_outputs,
            witness: None,
        }
    }

    fn with_witness(&self, witness: Vec<Scalar>) -> Self {
        Self {
            witness: Some(Arc::new(witness)),
            ..self.clone()
        }
    }
}

impl SpartanCircuit<E> for Circuit {
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
        Ok(self.witness.as_ref().map_or_else(
            || vec![Scalar::ZERO; self.public_inputs],
            |witness| {
                witness[1 + self.shared_outputs..1 + self.shared_outputs + self.public_inputs]
                    .to_vec()
            },
        ))
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        (0..self.shared_outputs)
            .map(|index| {
                let value = self.witness.as_ref().map_or(Scalar::ZERO, |w| w[1 + index]);
                AllocatedNum::alloc(cs.namespace(|| format!("shared_{index}")), || Ok(value))
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

#[derive(Clone, Serialize)]
struct StageRun {
    witness_handoff_ms: f64,
    setup_ms: f64,
    key_serialization_ms: f64,
    assignment_ms: f64,
    prepared_state_serialization_ms: f64,
    final_proof_ms: f64,
    proof_serialization_ms: f64,
    proof_deserialization_ms: f64,
    verify_ms: f64,
    verified: bool,
}

#[derive(Serialize)]
struct RawRun {
    run: usize,
    prepare: StageRun,
    show: StageRun,
    link_randomness_ms: f64,
    linked_commitments_equal: bool,
}

#[derive(Default, Serialize)]
struct ExactSizes {
    constraints: u32,
    wires: u32,
    r1cs_bytes: u64,
    wasm_bytes: u64,
    witness_bytes: u64,
    proving_key_bytes: u64,
    verifying_key_bytes: u64,
    proof_bytes: u64,
    pre_reblind_instance_bytes: u64,
    assignment_bytes: u64,
    public_input_count: usize,
    hidden_shared_value_count: usize,
}

#[derive(Serialize)]
struct MetricSummary {
    min_ms: f64,
    median_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    sample_variance_ms2: f64,
    sample_standard_deviation_ms: f64,
    coefficient_of_variation: f64,
}

#[derive(Serialize)]
struct NegativeLinkage {
    unlinked_show_verified_independently: bool,
    unlinked_shared_commitment_rejected: bool,
}

#[derive(Serialize)]
struct StageSummary {
    witness_handoff: MetricSummary,
    setup: MetricSummary,
    key_serialization: MetricSummary,
    assignment: MetricSummary,
    prepared_state_serialization: MetricSummary,
    final_proof: MetricSummary,
    proof_serialization: MetricSummary,
    proof_deserialization: MetricSummary,
    verify: MetricSummary,
}

#[derive(Serialize)]
struct Report {
    profile: String,
    prepare_circuit: String,
    show_circuit: String,
    business_statement: String,
    accepted_vct: String,
    repetitions: usize,
    expanded_after_first_two: bool,
    raw_runs: Vec<RawRun>,
    prepare_summary: StageSummary,
    show_summary: StageSummary,
    witness_generation: serde_json::Value,
    exact_sizes: ExactSizeReport,
    negative_linkage: NegativeLinkage,
    production_peak_rss_bytes: Option<u64>,
    peak_rss_after_negative_control_bytes: Option<u64>,
}

#[derive(Serialize)]
struct ExactSizeReport {
    prepare: ExactSizes,
    show: ExactSizes,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("swiyu-split-profile-benchmark: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let requested_repetitions = std::env::var("BENCHMARK_RUNS")
        .ok()
        .map(|value| value.parse::<usize>().map_err(|e| e.to_string()))
        .transpose()?;
    if requested_repetitions.is_some_and(|runs| runs < 1) {
        return Err("BENCHMARK_RUNS must be at least 1".into());
    }
    let mut repetitions = requested_repetitions.unwrap_or(2);

    let circom = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom");
    let profile = env_or(
        "SWIYU_BENCH_PROFILE",
        "swiyu.age-over-18.packed-status-chunk.v2",
    );
    let business_statement = env_or(
        "SWIYU_BENCH_STATEMENT",
        "The holder controls an issuer-authenticated credential satisfying the selected private predicate and current status policy.",
    );
    let accepted_vct = env_or("SWIYU_BENCH_VCT", "https://example.ch/vct/person");
    let fixture_name = env_or(
        "SWIYU_BENCH_FIXTURE_DIR",
        "swiyu_split_benchmark",
    );
    let prepare_name = env_or(
        "SWIYU_BENCH_PREPARE_CIRCUIT",
        "swiyu_age18_prepare_compact",
    );
    let show_name = env_or(
        "SWIYU_BENCH_SHOW_CIRCUIT",
        "swiyu_age18_show_packed_chunk_v2",
    );
    let prepare_public_inputs = env_usize("SWIYU_BENCH_PREPARE_PUBLIC_INPUTS", 2)?;
    let show_public_inputs = env_usize("SWIYU_BENCH_SHOW_PUBLIC_INPUTS", 7)?;
    let shared_outputs = env_usize("SWIYU_BENCH_SHARED_OUTPUTS", 11)?;
    if shared_outputs == 0 {
        return Err("SWIYU_BENCH_SHARED_OUTPUTS must be positive".into());
    }
    let fixture_dir = circom.join(format!("build/{fixture_name}"));
    let prepare_shape = Circuit::shape(
        circom.join(format!("build/{prepare_name}/{prepare_name}.r1cs")),
        prepare_public_inputs,
        shared_outputs,
    );
    let show_shape = Circuit::shape(
        circom.join(format!("build/{show_name}/{show_name}.r1cs")),
        show_public_inputs,
        shared_outputs,
    );
    let prepare_wtns = fixture_dir.join(env_or(
        "SWIYU_BENCH_PREPARE_WITNESS",
        "prepare.wtns",
    ));
    let show_wtns = fixture_dir.join(env_or(
        "SWIYU_BENCH_SHOW_WITNESS",
        "show-packed-v2.wtns",
    ));
    let unlinked_show_wtns = fixture_dir.join(env_or(
        "SWIYU_BENCH_UNLINKED_SHOW_WITNESS",
        "show-unlinked-packed-v2.wtns",
    ));
    let prepare_witness = parse_witness(&read(&prepare_wtns)?)
        .map_err(|error| format!("parse Prepare witness: {error:?}"))?;
    let show_witness = parse_witness(&read(&show_wtns)?)
        .map_err(|error| format!("parse Show witness: {error:?}"))?;
    let unlinked_show_witness = parse_witness(&read(&unlinked_show_wtns)?)
        .map_err(|error| format!("parse unlinked Show witness: {error:?}"))?;
    let witness_metadata = env_or("SWIYU_BENCH_WITNESS_METADATA", "witness-runs.json");
    let witness_generation: serde_json::Value =
        serde_json::from_slice(&read(&fixture_dir.join(&witness_metadata))?)
            .map_err(|error| format!("parse {witness_metadata}: {error}"))?;
    if prepare_witness[1..=shared_outputs] != show_witness[1..=shared_outputs] {
        return Err("Prepare and Show shared outputs differ".into());
    }
    if prepare_witness[1..=shared_outputs] == unlinked_show_witness[1..=shared_outputs] {
        return Err("negative Show witness did not change a shared row".into());
    }
    let prepare_circuit = prepare_shape.with_witness(prepare_witness);
    let show_circuit = show_shape.with_witness(show_witness);
    let unlinked_show_circuit = show_shape.with_witness(unlinked_show_witness);
    let prepare_public = prepare_circuit.public_values().map_err(debug)?;
    let show_public = show_circuit.public_values().map_err(debug)?;

    let mut raw_runs = Vec::with_capacity(repetitions);
    let mut prepare_sizes = exact_relation_sizes(
        &prepare_shape,
        &prepare_wtns,
        circom.join(format!(
            "build/{prepare_name}/{prepare_name}_js/{prepare_name}.wasm"
        )),
        prepare_public_inputs,
    )?;
    let mut show_sizes = exact_relation_sizes(
        &show_shape,
        &show_wtns,
        circom.join(format!("build/{show_name}/{show_name}_js/{show_name}.wasm")),
        show_public_inputs,
    )?;
    let mut linkage_randomness: Option<Vec<Scalar>> = None;
    let mut linked_prepare_commitment: Option<Vec<u8>> = None;

    let mut index = 0;
    while index < repetitions {
        eprintln!(
            "{} benchmark run {}/{}: Prepare",
            profile,
            index + 1,
            repetitions
        );
        let started = Instant::now();
        let prepare_run_witness = parse_witness(&read(&prepare_wtns)?)
            .map_err(|error| format!("parse Prepare witness: {error:?}"))?;
        let prepare_run_circuit = prepare_shape.with_witness(prepare_run_witness);
        let witness_handoff_ms = elapsed_ms(started);
        let started = Instant::now();
        let (prepare_pk, prepare_vk) =
            R1CSSNARK::<E>::setup(prepare_shape.clone()).map_err(debug)?;
        let setup_ms = elapsed_ms(started);
        let started = Instant::now();
        serialize_to_sink(&prepare_pk)?;
        serialize_to_sink(&prepare_vk)?;
        let key_serialization_ms = elapsed_ms(started);
        let prepare_pk_bytes = serialized_size(&prepare_pk)?;
        let prepare_vk_bytes = serialized_size(&prepare_vk)?;
        let started = Instant::now();
        let (instance, assignment) =
            prepare_circuit_assignment_in_memory(prepare_run_circuit, &prepare_pk)
                .map_err(debug)?;
        let assignment_ms = elapsed_ms(started);
        let started = Instant::now();
        serialize_to_sink(&instance)?;
        serialize_to_sink(&assignment)?;
        let prepared_state_serialization_ms = elapsed_ms(started);
        let started = Instant::now();
        let randomness: Vec<Scalar> = (0..instance.num_shared_rows())
            .map(|_| Scalar::random(&mut OsRng))
            .collect();
        let link_randomness_ms = elapsed_ms(started);
        let instance_bytes = serialized_size(&instance)?;
        let assignment_bytes = serialized_size(&assignment)?;
        let started = Instant::now();
        let (proof, _, _) =
            reblind_in_memory(&prepare_pk, instance, assignment, &randomness).map_err(debug)?;
        let final_proof_ms = elapsed_ms(started);
        let prepare_commitment =
            bincode::serialize(proof.comm_W_shared()).map_err(|e| e.to_string())?;
        if index == 0 {
            linkage_randomness = Some(randomness.clone());
            linked_prepare_commitment = Some(prepare_commitment.clone());
        }
        let started = Instant::now();
        let proof_bytes = bincode::serialize(&proof).map_err(|e| e.to_string())?;
        let proof_serialization_ms = elapsed_ms(started);
        drop(proof);
        let started = Instant::now();
        let reconstructed_proof: R1CSSNARK<E> =
            bincode::deserialize(&proof_bytes).map_err(|e| e.to_string())?;
        let proof_deserialization_ms = elapsed_ms(started);
        let started = Instant::now();
        let verified = reconstructed_proof
            .verify(&prepare_vk)
            .is_ok_and(|values| values == prepare_public);
        let verify_ms = elapsed_ms(started);
        if index == 0 {
            prepare_sizes.proving_key_bytes = prepare_pk_bytes;
            prepare_sizes.verifying_key_bytes = prepare_vk_bytes;
            prepare_sizes.proof_bytes = proof_bytes.len() as u64;
            prepare_sizes.pre_reblind_instance_bytes = instance_bytes;
            prepare_sizes.assignment_bytes = assignment_bytes;
        }
        let prepare_run = StageRun {
            witness_handoff_ms,
            setup_ms,
            key_serialization_ms,
            assignment_ms,
            prepared_state_serialization_ms,
            final_proof_ms,
            proof_serialization_ms,
            proof_deserialization_ms,
            verify_ms,
            verified,
        };
        drop(reconstructed_proof);
        drop(prepare_pk);
        drop(prepare_vk);

        eprintln!(
            "{} benchmark run {}/{}: Show",
            profile,
            index + 1,
            repetitions
        );
        let started = Instant::now();
        let show_run_witness = parse_witness(&read(&show_wtns)?)
            .map_err(|error| format!("parse Show witness: {error:?}"))?;
        let show_run_circuit = show_shape.with_witness(show_run_witness);
        let witness_handoff_ms = elapsed_ms(started);
        let started = Instant::now();
        let (show_pk, show_vk) = R1CSSNARK::<E>::setup(show_shape.clone()).map_err(debug)?;
        let setup_ms = elapsed_ms(started);
        let started = Instant::now();
        serialize_to_sink(&show_pk)?;
        serialize_to_sink(&show_vk)?;
        let key_serialization_ms = elapsed_ms(started);
        let show_pk_bytes = serialized_size(&show_pk)?;
        let show_vk_bytes = serialized_size(&show_vk)?;
        let started = Instant::now();
        let (instance, assignment) =
            prepare_circuit_assignment_in_memory(show_run_circuit, &show_pk).map_err(debug)?;
        let assignment_ms = elapsed_ms(started);
        let started = Instant::now();
        serialize_to_sink(&instance)?;
        serialize_to_sink(&assignment)?;
        let prepared_state_serialization_ms = elapsed_ms(started);
        let instance_bytes = serialized_size(&instance)?;
        let assignment_bytes = serialized_size(&assignment)?;
        let started = Instant::now();
        let (proof, _, _) =
            reblind_in_memory(&show_pk, instance, assignment, &randomness).map_err(debug)?;
        let final_proof_ms = elapsed_ms(started);
        let show_commitment =
            bincode::serialize(proof.comm_W_shared()).map_err(|e| e.to_string())?;
        let started = Instant::now();
        let proof_bytes = bincode::serialize(&proof).map_err(|e| e.to_string())?;
        let proof_serialization_ms = elapsed_ms(started);
        drop(proof);
        let started = Instant::now();
        let reconstructed_proof: R1CSSNARK<E> =
            bincode::deserialize(&proof_bytes).map_err(|e| e.to_string())?;
        let proof_deserialization_ms = elapsed_ms(started);
        let started = Instant::now();
        let verified = reconstructed_proof
            .verify(&show_vk)
            .is_ok_and(|values| values == show_public);
        let verify_ms = elapsed_ms(started);
        if index == 0 {
            show_sizes.proving_key_bytes = show_pk_bytes;
            show_sizes.verifying_key_bytes = show_vk_bytes;
            show_sizes.proof_bytes = proof_bytes.len() as u64;
            show_sizes.pre_reblind_instance_bytes = instance_bytes;
            show_sizes.assignment_bytes = assignment_bytes;
        }
        let show_run = StageRun {
            witness_handoff_ms,
            setup_ms,
            key_serialization_ms,
            assignment_ms,
            prepared_state_serialization_ms,
            final_proof_ms,
            proof_serialization_ms,
            proof_deserialization_ms,
            verify_ms,
            verified,
        };
        raw_runs.push(RawRun {
            run: index + 1,
            prepare: prepare_run,
            show: show_run,
            link_randomness_ms,
            linked_commitments_equal: prepare_commitment == show_commitment,
        });
        drop(reconstructed_proof);
        drop(show_pk);
        drop(show_vk);
        index += 1;
        if index == 2 && requested_repetitions.is_none() {
            repetitions = if stages_unstable(&raw_runs[0], &raw_runs[1]) {
                7
            } else {
                3
            };
        }
    }

    if raw_runs
        .iter()
        .any(|run| !run.prepare.verified || !run.show.verified || !run.linked_commitments_equal)
    {
        return Err("a proof failed verification or linkage".into());
    }
    let production_peak_rss_bytes = peak_rss_bytes();
    let (negative_pk, negative_vk) = R1CSSNARK::<E>::setup(show_shape.clone()).map_err(debug)?;
    let (negative_instance, negative_assignment) =
        prepare_circuit_assignment_in_memory(unlinked_show_circuit, &negative_pk).map_err(debug)?;
    let (negative_proof, _, _) = reblind_in_memory(
        &negative_pk,
        negative_instance,
        negative_assignment,
        linkage_randomness
            .as_deref()
            .ok_or("missing linkage randomness")?,
    )
    .map_err(debug)?;
    let unlinked_show_verified_independently = negative_proof.verify(&negative_vk).is_ok();
    let unlinked_commitment =
        bincode::serialize(negative_proof.comm_W_shared()).map_err(|e| e.to_string())?;
    let unlinked_shared_commitment_rejected =
        unlinked_commitment != linked_prepare_commitment.ok_or("missing Prepare commitment")?;
    if !unlinked_show_verified_independently || !unlinked_shared_commitment_rejected {
        return Err("negative Show proof did not verify independently and fail linkage".into());
    }
    let report = Report {
        profile,
        prepare_circuit: prepare_name,
        show_circuit: show_name,
        business_statement,
        accepted_vct,
        repetitions,
        expanded_after_first_two: requested_repetitions.is_none() && repetitions == 7,
        prepare_summary: summarize_stage(raw_runs.iter().map(|run| &run.prepare)),
        show_summary: summarize_stage(raw_runs.iter().map(|run| &run.show)),
        witness_generation,
        raw_runs,
        exact_sizes: ExactSizeReport {
            prepare: prepare_sizes,
            show: show_sizes,
        },
        negative_linkage: NegativeLinkage {
            unlinked_show_verified_independently,
            unlinked_shared_commitment_rejected,
        },
        production_peak_rss_bytes,
        peak_rss_after_negative_control_bytes: peak_rss_bytes(),
    };
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

fn stages_unstable(first: &RawRun, second: &RawRun) -> bool {
    let pairs = [
        (
            first.prepare.witness_handoff_ms,
            second.prepare.witness_handoff_ms,
        ),
        (first.prepare.setup_ms, second.prepare.setup_ms),
        (
            first.prepare.key_serialization_ms,
            second.prepare.key_serialization_ms,
        ),
        (first.prepare.assignment_ms, second.prepare.assignment_ms),
        (
            first.prepare.prepared_state_serialization_ms,
            second.prepare.prepared_state_serialization_ms,
        ),
        (first.prepare.final_proof_ms, second.prepare.final_proof_ms),
        (
            first.prepare.proof_serialization_ms,
            second.prepare.proof_serialization_ms,
        ),
        (
            first.prepare.proof_deserialization_ms,
            second.prepare.proof_deserialization_ms,
        ),
        (first.prepare.verify_ms, second.prepare.verify_ms),
        (
            first.show.witness_handoff_ms,
            second.show.witness_handoff_ms,
        ),
        (first.show.setup_ms, second.show.setup_ms),
        (
            first.show.key_serialization_ms,
            second.show.key_serialization_ms,
        ),
        (first.show.assignment_ms, second.show.assignment_ms),
        (
            first.show.prepared_state_serialization_ms,
            second.show.prepared_state_serialization_ms,
        ),
        (first.show.final_proof_ms, second.show.final_proof_ms),
        (
            first.show.proof_serialization_ms,
            second.show.proof_serialization_ms,
        ),
        (
            first.show.proof_deserialization_ms,
            second.show.proof_deserialization_ms,
        ),
        (first.show.verify_ms, second.show.verify_ms),
        (first.link_randomness_ms, second.link_randomness_ms),
    ];
    pairs.into_iter().any(|(a, b)| {
        let mean = (a + b) / 2.0;
        mean > 0.0 && ((a - b).abs() / mean) > 0.15
    })
}

fn exact_relation_sizes(
    circuit: &Circuit,
    witness: &PathBuf,
    wasm: PathBuf,
    public_inputs: usize,
) -> Result<ExactSizes, String> {
    let stats = read_r1cs_compiler_stats(&circuit.r1cs)?;
    Ok(ExactSizes {
        constraints: stats.constraints,
        wires: stats.wires,
        r1cs_bytes: size(&circuit.r1cs)?,
        wasm_bytes: size(&wasm)?,
        witness_bytes: size(witness)?,
        public_input_count: public_inputs,
        hidden_shared_value_count: circuit.shared_outputs,
        ..ExactSizes::default()
    })
}

fn summarize_stage<'a>(runs: impl Iterator<Item = &'a StageRun>) -> StageSummary {
    let runs: Vec<&StageRun> = runs.collect();
    StageSummary {
        witness_handoff: metric(runs.iter().map(|run| run.witness_handoff_ms)),
        setup: metric(runs.iter().map(|run| run.setup_ms)),
        key_serialization: metric(runs.iter().map(|run| run.key_serialization_ms)),
        assignment: metric(runs.iter().map(|run| run.assignment_ms)),
        prepared_state_serialization: metric(
            runs.iter().map(|run| run.prepared_state_serialization_ms),
        ),
        final_proof: metric(runs.iter().map(|run| run.final_proof_ms)),
        proof_serialization: metric(runs.iter().map(|run| run.proof_serialization_ms)),
        proof_deserialization: metric(runs.iter().map(|run| run.proof_deserialization_ms)),
        verify: metric(runs.iter().map(|run| run.verify_ms)),
    }
}

fn metric(values: impl Iterator<Item = f64>) -> MetricSummary {
    let mut values: Vec<f64> = values.collect();
    values.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = if values.len() > 1 {
        values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64
    } else {
        0.0
    };
    let median = if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    };
    MetricSummary {
        min_ms: values[0],
        median_ms: median,
        max_ms: values[values.len() - 1],
        mean_ms: mean,
        sample_variance_ms2: variance,
        sample_standard_deviation_ms: variance.sqrt(),
        coefficient_of_variation: if mean == 0.0 {
            0.0
        } else {
            variance.sqrt() / mean
        },
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn serialized_size<T: Serialize>(value: &T) -> Result<u64, String> {
    bincode::serialized_size(value).map_err(|e| e.to_string())
}
fn serialize_to_sink<T: Serialize>(value: &T) -> Result<(), String> {
    bincode::serialize_into(std::io::sink(), value).map_err(|e| e.to_string())
}
fn read(path: &PathBuf) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}
fn size(path: &PathBuf) -> Result<u64, String> {
    fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| format!("stat {}: {e}", path.display()))
}
fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| format!("{name} must be an unsigned integer: {error}"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
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
