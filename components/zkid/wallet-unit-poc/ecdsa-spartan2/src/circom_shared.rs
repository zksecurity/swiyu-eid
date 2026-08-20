//! Circom synthesis where leading output wires are hidden Spartan shared rows.
//!
//! `circom_scotia::synthesize` allocates every Circom output as public IO. For
//! Prepare/Show composition we instead reuse the `AllocatedNum`s returned by
//! `SpartanCircuit::shared` for those exact wire positions. This is the missing
//! constraint link in the inherited zkID wrapper: the shared commitment now
//! commits variables that the imported Circom R1CS actually constrains.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use circom_scotia::r1cs::R1CS;
use ff::PrimeField;

pub fn synthesize_with_shared_outputs<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    r1cs: R1CS<F>,
    witness: Option<&[F]>,
    shared_outputs: &[AllocatedNum<F>],
) -> Result<(), SynthesisError> {
    if shared_outputs.len() != r1cs.num_pub_out {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut vars: Vec<AllocatedNum<F>> = Vec::with_capacity(r1cs.num_variables - 1);

    // Circom orders public outputs immediately after wire zero. Reuse the
    // already-allocated Spartan shared rows at those exact wire indices.
    vars.extend(shared_outputs.iter().cloned());

    // Remaining Circom public signals are genuine proof public inputs.
    for wire in (1 + r1cs.num_pub_out)..r1cs.num_inputs {
        let value = witness
            .as_ref()
            .map(|values| values[wire])
            .unwrap_or(F::ONE);
        vars.push(AllocatedNum::alloc_input(
            cs.namespace(|| format!("public_{wire}")),
            || Ok(value),
        )?);
    }

    // Private witness wires follow all Circom public outputs and inputs.
    for aux in 0..r1cs.num_aux {
        let wire = aux + r1cs.num_inputs;
        let value = witness
            .as_ref()
            .map(|values| values[wire])
            .unwrap_or(F::ONE);
        vars.push(AllocatedNum::alloc(
            cs.namespace(|| format!("aux_{aux}")),
            || Ok(value),
        )?);
    }

    let make_lc = |terms: Vec<(usize, F)>| {
        terms
            .into_iter()
            .fold(LinearCombination::<F>::zero(), |lc, (wire, coefficient)| {
                lc + if wire == 0 {
                    (coefficient, CS::one())
                } else {
                    (coefficient, vars[wire - 1].get_variable())
                }
            })
    };

    for (index, (a, b, c)) in r1cs.constraints.into_iter().enumerate() {
        cs.enforce(
            || format!("constraint {index}"),
            |_| make_lc(a),
            |_| make_lc(b),
            |_| make_lc(c),
        );
    }
    Ok(())
}
