use crate::{
    arithmetic_circuit::tests::{
        generate_3_by_3_determinant_circuit, generate_bls12_377_circuit,
        generate_lemniscate_circuit,
    },
    ligero::LigeroCircuit,
    matrices::SparseMatrix,
    DEFAULT_SECURITY_LEVEL,
};
use ark_bls12_377::{Fq, G1Affine};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ec::short_weierstrass::Affine;
use ark_ff::{Field, UniformRand};
use ark_poly_commit::test_sponge;
use ark_std::test_rng;

#[test]
fn test_construction_bls12_377() {
    // Circuit with only one constant: the initial 1
    //     0: Constant(1)
    //     1: Variable
    //     2: Variable
    //     3: node(2) * node(2)
    //     4: -1 * node(3)
    //     5: node(1) * node(1)
    //     6: node(5) * node(1)
    //     7: node(6) + 1
    //     8: node(7) + node(4)
    //     9: node(8) + 1

    // Induced matrices:
    //       Row index      P_x         P_y         P_z        P_add
    //       0              []          []          []         []
    //       1              []          []          []         []
    //       2              []          []          []         []
    //       3              [(1, 2)]    [(1, 2)]    [(1, 3)]   []
    //       4              [(-1, 0)]   [(1, 3)]    [(1, 4)]   []
    //       5              [(1, 1)]    [(1, 1)]    [(1, 5)]   []
    //       6              [(1, 5)]    [(1, 1)]    [(1, 6)]   []
    //       7              []          []          []         [(1, 6), (1, 0), (-1, 7)]
    //       8              []          []          []         [(1, 7), (1, 4), (-1, 8)]
    //       9              []          []          []         [(1, 8), (1, 0), (-1, 9)]
    //       10             []          []          []         [(1, 8), (1, 0), (-1, 0)]
    //       11             []          []          []         []
    //       12             []          []          []         []
    //       13             []          []          []         []
    //       14             []          []          []         []
    //       15             []          []          []         []
    let circuit = generate_bls12_377_circuit();

    let output_node = circuit.last();

    let (m, k) = (4, 4);

    let p_x = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![
                vec![(Fq::ONE, 2)],
                vec![(-Fq::ONE, 0)],
                vec![(Fq::ONE, 1)],
                vec![(Fq::ONE, 5)],
            ],
            vec![vec![]; 9],
        ]
        .concat(),
        m * k,
    );

    let p_y = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![
                vec![(Fq::ONE, 2)],
                vec![(Fq::ONE, 3)],
                vec![(Fq::ONE, 1)],
                vec![(Fq::ONE, 1)],
            ],
            vec![vec![]; 9],
        ]
        .concat(),
        m * k,
    );

    let p_z = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![
                vec![(Fq::ONE, 3)],
                vec![(Fq::ONE, 4)],
                vec![(Fq::ONE, 5)],
                vec![(Fq::ONE, 6)],
            ],
            vec![vec![]; 9],
        ]
        .concat(),
        m * k,
    );

    let p_add = SparseMatrix::from_rows(
        [
            vec![vec![]; 7],
            vec![
                vec![(Fq::ONE, 6), (Fq::ONE, 0), (-Fq::ONE, 7)],
                vec![(Fq::ONE, 7), (Fq::ONE, 4), (-Fq::ONE, 8)],
                vec![(Fq::ONE, 8), (Fq::ONE, 0), (-Fq::ONE, 9)],
            ],
            vec![vec![(Fq::ONE, 8), (Fq::ONE, 0), (-Fq::ONE, 0)]],
            vec![vec![]; 5],
        ]
        .concat(),
        m * k,
    );

    let p_column = -p_x.v_stack(p_y.v_stack(p_z));
    let a_upper = SparseMatrix::identity(3 * m * k).h_stack(&p_column);
    let a_lower = SparseMatrix::zero(m * k, 3 * m * k).h_stack(&p_add);
    let expected_a = a_upper.v_stack(a_lower);

    assert_eq!(
        LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL).a,
        expected_a
    );
}

#[test]
fn test_prove_and_verify_bls12_377() {
    let Affine { x, y, .. } = G1Affine::rand(&mut test_rng());

    let circuit = generate_bls12_377_circuit();
    let output_node = circuit.last();
    let ligero_circuit = LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL);

    let sponge: PoseidonSponge<Fq> = test_sponge();

    let proof = ligero_circuit.prove(vec![(1, x), (2, y)], &mut sponge.clone());

    assert!(ligero_circuit.verify(proof, &mut sponge.clone()));
}

#[test]
fn test_prove_and_verify_lemniscate() {
    let circuit = generate_lemniscate_circuit();
    let output_node = circuit.last();
    let ligero_circuit = LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL);

    let sponge: PoseidonSponge<Fr> = test_sponge();

    let proof = ligero_circuit.prove(
        vec![(1, Fr::from(8u8)), (2, Fr::from(4u8))],
        &mut sponge.clone(),
    );

    assert!(ligero_circuit.verify(proof, &mut sponge.clone()));
}

#[test]
fn test_prove_and_verify_3_by_3_determinant() {
    let circuit = generate_3_by_3_determinant_circuit();
    let output_node = circuit.last();
    let ligero_circuit = LigeroCircuit::new(circuit, vec![output_node], DEFAULT_SECURITY_LEVEL);

    let sponge: PoseidonSponge<Fr> = test_sponge();

    let vars = vec![
        (1, Fr::from(2)),
        (2, Fr::from(0)),
        (3, Fr::from(-1)),
        (4, Fr::from(3)),
        (5, Fr::from(5)),
        (6, Fr::from(2)),
        (7, Fr::from(-4)),
        (8, Fr::from(1)),
        (9, Fr::from(4)),
    ];
    let det = Fr::from(13);
    let valid_assignment = [vars, vec![(10, det)]].concat();

    let proof = ligero_circuit.prove(valid_assignment.clone(), &mut sponge.clone());

    assert!(ligero_circuit.verify(proof, &mut sponge.clone()));
}
