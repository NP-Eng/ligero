use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ff::Field;
use ark_poly_commit::test_sponge;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ligero::arithmetic_circuit::ArithmeticCircuit;
use ligero::ligero::{types::LigeroMTTestParams, LigeroCircuit};
use ligero::DEFAULT_SECURITY_LEVEL;

fn generate_fibonacci_circuit(steps: usize) -> ArithmeticCircuit<Fr> {
    let mut circuit = ArithmeticCircuit::new();

    let one = circuit.constant(Fr::ONE);

    let f_0 = circuit.new_variable_with_label("f_0");
    let f_1 = circuit.new_variable_with_label("f_1");

    let mut first_operand = f_0;
    let mut second_operand = f_1;

    for _ in 2..steps {
        let next = circuit.add(first_operand, second_operand);
        first_operand = second_operand;
        second_operand = next;
    }

    circuit.add_nodes([second_operand, one]);
    circuit
}

pub fn prover_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover");
    for size in [10, 12, 14].iter() {
        group.bench_with_input(
            BenchmarkId::new("prove_fibonacci", format!("1 << {}", size)),
            size,
            |b, &size| {
                let steps = 1 << size;
                let circuit = generate_fibonacci_circuit(steps);
                let output_node = circuit.last();
                let ligero_circuit =
                    LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL);
                let sponge: PoseidonSponge<Fr> = test_sponge();
                let mt_params = LigeroMTTestParams::new();

                b.iter(|| {
                    ligero_circuit.prove_with_labels(
                        vec![("f_0", Fr::from(1)), ("f_1", Fr::from(1))],
                        &mt_params,
                        &mut sponge.clone(),
                    )
                })
            },
        );
    }
    group.finish();
}

pub fn verifier_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    for size in [10, 12, 14].iter() {
        group.bench_with_input(
            BenchmarkId::new("verify_fibonacci", format!("1 << {}", size)),
            size,
            |b, &size| {
                let steps = 1 << size;
                let circuit = generate_fibonacci_circuit(steps);
                let output_node = circuit.last();
                let ligero_circuit =
                    LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL);
                let sponge: PoseidonSponge<Fr> = test_sponge();
                let mt_params = LigeroMTTestParams::new();
                let proof = ligero_circuit.prove_with_labels(
                    vec![("f_0", Fr::from(1)), ("f_1", Fr::from(1))],
                    &mt_params,
                    &mut sponge.clone(),
                );

                b.iter(|| ligero_circuit.verify(&proof, &mt_params, &mut sponge.clone()))
            },
        );
    }
    group.finish();
}

criterion_group!(benches, prover_benchmark, verifier_benchmark);
criterion_main!(benches);
