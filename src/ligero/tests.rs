use crate::{
    arithmetic_circuit::{
        tests::{
            generate_3_by_3_determinant_circuit, generate_bls12_377_circuit,
            generate_lemniscate_circuit,
        },
        ArithmeticCircuit,
    },
    expression::{
        tests::{
            generate_3_by_3_determinant_expression, generate_bls12_377_expression,
            generate_lemniscate_expression,
        },
        Expression,
    },
    ligero::LigeroCircuit,
    matrices::SparseMatrix,
    DEFAULT_SECURITY_LEVEL,
};
use ark_bls12_377::{Fq, G1Affine};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_poly_commit::test_sponge;
use ark_std::test_rng;
use itertools::Itertools;

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
    //       0              []          []          []         [(1, 8), (1, 0), (-1, 0)]
    //       1              []          []          []         []
    //       2              []          []          []         []
    //       3              [(1, 2)]    [(1, 2)]    [(1, 3)]   []
    //       4              [(-1, 0)]   [(1, 3)]    [(1, 4)]   []
    //       5              [(1, 1)]    [(1, 1)]    [(1, 5)]   []
    //       6              [(1, 5)]    [(1, 1)]    [(1, 6)]   []
    //       7              []          []          []         [(1, 6), (1, 0), (-1, 7)]
    //       8              []          []          []         [(1, 7), (1, 4), (-1, 8)]
    //       9              []          []          []         [(1, 8), (1, 0), (-1, 9)]
    //       10             []          []          []         []
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
            vec![vec![(Fq::ONE, 8), (Fq::ONE, 0), (-Fq::ONE, 0)]],
            vec![vec![]; 6],
            vec![
                vec![(Fq::ONE, 6), (Fq::ONE, 0), (-Fq::ONE, 7)],
                vec![(Fq::ONE, 7), (Fq::ONE, 4), (-Fq::ONE, 8)],
                vec![(Fq::ONE, 8), (Fq::ONE, 0), (-Fq::ONE, 9)],
            ],
            vec![vec![]; 6],
        ]
        .concat(),
        m * k,
    );

    let p_column = -p_x.v_stack(p_y.v_stack(p_z));
    let a_upper = SparseMatrix::identity(3 * m * k).h_stack(&p_column);
    let a_lower = SparseMatrix::zero(m * k, 3 * m * k).h_stack(&p_add);
    let expected_a = a_upper.v_stack(a_lower);

    assert_eq!(
        LigeroCircuit::new(circuit, output_node, DEFAULT_SECURITY_LEVEL).a,
        expected_a
    );
}

fn proof_and_verify<F: PrimeField + Absorb>(
    circuit: ArithmeticCircuit<F>,
    vars: Vec<(usize, F)>,
) -> bool {
    let output_node = circuit.last();
    let ligero_circuit = LigeroCircuit::new(circuit, output_node, DEFAULT_SECURITY_LEVEL);

    let sponge: PoseidonSponge<F> = test_sponge();

    let proof = ligero_circuit.prove(vars.clone(), &mut sponge.clone());

    ligero_circuit.verify(proof, &mut sponge.clone())
}

fn test_proof_and_verify<F: PrimeField + Absorb>(
    circuit: ArithmeticCircuit<F>,
    vars: Vec<(usize, F)>,
) {
    let mut invalid_assignment = vars.clone();
    invalid_assignment[0].1 += F::ONE;

    assert!(proof_and_verify(circuit.clone(), vars));

    assert!(!proof_and_verify(circuit, invalid_assignment));
}

fn test_proof_and_verify_expression<F: PrimeField + Absorb>(
    expression: Expression<F>,
    vars: Vec<(&str, F)>,
) {
    let circuit = LigeroCircuit::format_circuit(expression.to_arithmetic_circuit());

    let indexed_vars = vars
        .into_iter()
        .map(|(s, f)| (circuit.get_variable(s), f))
        .collect::<Vec<_>>();

    test_proof_and_verify(circuit, indexed_vars);
}

#[test]
fn test_prove_and_verify_bls12_377() {
    let Affine { x, y, .. } = G1Affine::rand(&mut test_rng());

    test_proof_and_verify(generate_bls12_377_circuit(), vec![(1, x), (2, y)]);

    test_proof_and_verify_expression(generate_bls12_377_expression(), vec![("x", x), ("y", y)]);
}

#[test]
fn test_prove_and_verify_lemniscate() {
    test_proof_and_verify(
        generate_lemniscate_circuit(),
        vec![(1, Fr::from(8)), (2, Fr::from(4))],
    );

    test_proof_and_verify_expression(
        generate_lemniscate_expression(),
        vec![("x", Fr::from(8)), ("y", Fr::from(4))],
    );
}

#[test]
fn test_prove_and_verify_3_by_3_determinant() {
    let values = vec![
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

    test_proof_and_verify(
        generate_3_by_3_determinant_circuit(),
        [values.clone(), vec![(10, det)]].concat(),
    );

    let labeled_values = (0..3)
        .cartesian_product(0..3)
        .map(|(i, j)| (format!("x_{i}_{j}"), values[i * 3 + j].1))
        .map(|(s, f)| (s, f))
        .collect::<Vec<_>>();

    let labeled_vars = labeled_values
        .iter()
        .map(|(s, f)| (s.as_str(), *f))
        .collect::<Vec<_>>();

    test_proof_and_verify_expression(
        generate_3_by_3_determinant_expression(),
        [labeled_vars, vec![("det", det)]].concat(),
    );
}
