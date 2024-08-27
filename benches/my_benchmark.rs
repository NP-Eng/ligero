use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crate::{
    arithmetic_circuit::tests::generate_bls12_377_circuit,
    ligero::{LigeroCircuit, types::LigeroMTTestParams},
    
    DEFAULT_SECURITY_LEVEL,
};
use ark_bls12_377::Fq;
use ark_poly_commit::{test_sponge};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_std::test_rng;

pub fn prover_benchmark(c: &mut Criterion) {

    let circuit = generate_bls12_377_circuit();
    let output_node = circuit.last();
    let ligero_circuit = LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL);

    let sponge: PoseidonSponge<Fq> = test_sponge();

    let mt_params = LigeroMTTestParams::new();

    c.bench_function("Bls12_377_3-4", |b| b.iter(|| ligero_circuit.prove(vec![("x", Fq::from(3)), ("y", Fq::from(4))], &mt_params, &mut sponge.clone())));
}

criterion_group!(benches, prover_benchmark);
criterion_main!(benches);