use crate::{
    arithmetic_circuit::{
        tests::{
            generate_3_by_3_determinant_circuit, generate_bls12_377_circuit,
            generate_lemniscate_circuit,
        },
        ArithmeticCircuit,
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

#[test]
pub fn test_multioutput_1() {
    let mut circuit = ArithmeticCircuit::new();

    // The first node must be the constant 1
    circuit.constant(Fr::ONE);

    // x^2 = 9
    // y^2 = 64
    // x + y = 7
    let x = circuit.new_variable_with_label("x");
    let y = circuit.new_variable_with_label("y");

    let c_1 = circuit.constant(Fr::from(-9 + 1));
    let c_2 = circuit.constant(Fr::from(-64 + 1));
    let c_3 = circuit.constant(Fr::from(-7 + 1));

    let x2 = circuit.mul(x, x);
    let y2 = circuit.pow(y, 3);
    let sum = circuit.add(x, y);

    let output_1 = circuit.add(x2, c_1);
    let output_2 = circuit.add(y2, c_2);
    let output_3 = circuit.add(sum, c_3);

    let ligero = LigeroCircuit::new(
        circuit,
        vec![output_1, output_2, output_3],
        DEFAULT_SECURITY_LEVEL,
    );

    let (m, k) = (ligero.m, ligero.k);

    //      sol         P_x         P_y         P_z        P_add
    // 0    1           []          []          []         []
    // 1    x           []          []          []         []
    // 2    y           []          []          []         []
    // 3    x2          [(1, 1)]    [(1, 1)]    [(1, 3)]   []
    // 4    y * y       [(1, 2)]    [(1, 2)]    [(1, 4)]   []
    // 5    y3          [(1, 4)]    [(1, 2)]    [(1, 5)]   []
    // 6    x + y       []          []          []         [(1, 1), (1, 2), (-1, 6)]
    // 7    x2 - 8      []          []          []         [(1, 3), (-8, 0), (-1, 7)]
    // 8    y3 - 63     []          []          []         [(1, 5), (-63, 0), (-1, 8)]
    // 9    x + y - 6   []          []          []         [(1, 6), (-6, 0), (-1, 9)]
    // 10   out. ct. 1  []          []          []         [(1, 3), (-8, 0), (-1, 0)]
    // 11   out. ct. 2  []          []          []         [(1, 5), (-63, 0), (-1, 0)]
    // 12   out. ct. 3  []          []          []         [(1, 6), (-6, 0), (-1, 0)]

    let p_x = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![vec![(Fr::ONE, 1)], vec![(Fr::ONE, 2)], vec![(Fr::ONE, 4)]],
            vec![vec![]; 4],
            vec![vec![]; 6], // Padding
        ]
        .concat(),
        10 + 6,
    );

    let p_y = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![vec![(Fr::ONE, 1)], vec![(Fr::ONE, 2)], vec![(Fr::ONE, 2)]],
            vec![vec![]; 4],
            vec![vec![]; 6], // Padding
        ]
        .concat(),
        10 + 6,
    );

    let p_z = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![vec![(Fr::ONE, 3)], vec![(Fr::ONE, 4)], vec![(Fr::ONE, 5)]],
            vec![vec![]; 4],
            vec![vec![]; 6], // Padding
        ]
        .concat(),
        10 + 6,
    );

    let p_add = SparseMatrix::from_rows(
        [
            vec![vec![]; 6],
            vec![
                vec![(Fr::ONE, 1), (Fr::ONE, 2), (-Fr::ONE, 6)],
                vec![(Fr::ONE, 3), (-Fr::from(8), 0), (-Fr::ONE, 7)],
                vec![(Fr::ONE, 5), (-Fr::from(63), 0), (-Fr::ONE, 8)],
                vec![(Fr::ONE, 6), (-Fr::from(6), 0), (-Fr::ONE, 9)],
                vec![(Fr::ONE, 3), (-Fr::from(8), 0), (-Fr::ONE, 0)],
                vec![(Fr::ONE, 5), (-Fr::from(63), 0), (-Fr::ONE, 0)],
                vec![(Fr::ONE, 6), (-Fr::from(6), 0), (-Fr::ONE, 0)],
            ],
            vec![vec![]; 3],
        ]
        .concat(),
        10 + 6,
    );

    let p_column = -p_x.v_stack(p_y.v_stack(p_z));
    let a_upper = SparseMatrix::identity(3 * m * k).h_stack(&p_column);
    let a_lower = SparseMatrix::zero(m * k, 3 * m * k).h_stack(&p_add);
    let expected_a = a_upper.v_stack(a_lower);

    assert_eq!(ligero.a, expected_a);

    let sponge: PoseidonSponge<Fr> = test_sponge();

    let mut prover_sponge = sponge.clone();
    let mut verifier_sponge = sponge;

    let proof = ligero.prove_with_labels(
        vec![("x", Fr::from(3)), ("y", Fr::from(4))],
        &mut prover_sponge,
    );

    assert!(ligero.verify(proof, &mut verifier_sponge));
}
