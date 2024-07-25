use std::collections::HashMap;

use crate::{
    arithmetic_circuit::ArithmeticCircuit,
    ligero::LigeroCircuit,
    matrices::{DenseMatrix, SparseMatrix},
    DEFAULT_SECURITY_LEVEL,
};
use ark_bls12_377::Fq;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_poly_commit::test_sponge;
use ark_std::test_rng;

// TODO remove
fn print_first_discrepancy(a: &SparseMatrix<Fq>, b: &SparseMatrix<Fq>) {
    if a.num_cols() != b.num_cols() {
        println!(
            "Different number of rows: {} vs {}",
            a.num_rows(),
            b.num_rows()
        );
        return;
    }

    a.rows
        .iter()
        .zip(b.rows.iter())
        .enumerate()
        .for_each(|(i, (a_row, b_row))| {
            if a_row != b_row {
                println!("Discrepancy in row {i}:\n\t{a_row:?}\n\tVS\n\t{b_row:?}");
            }
        });
}

// Defining equation of BLS12-377: y^2 = x^3 + 1 (over Fq)
fn generate_bls12_377_circuit() -> ArithmeticCircuit<Fq> {
    let mut circuit = ArithmeticCircuit::new();

    // Ligero circuits must start with a constant 1
    let one = circuit.constant(Fq::ONE);

    let x = circuit.variable();
    let y = circuit.variable();

    let y_squared = circuit.pow(y, 2);
    let minus_y_squared = circuit.minus(y_squared);
    let x_cubed = circuit.pow(x, 3);

    // Ligero will prove x^3 + 1 - y^2 + 1 = 1 Note that one could compute the
    // left-hand side as x^3 + 2 - y^2 in order to save one addition gate
    circuit.add_nodes([x_cubed, one, minus_y_squared, one]);
    circuit

    // n_i = 2, s = 8

    // Original circuit
    //     0: Constant(1)
    //     1: Variable
    //     2: Variable
    //     3: node(2) * node(2)
    //     4: Constant(21888242871839275222246405745257275088696311157297823662689037894645226208582)
    //     5: node(4) * node(3)
    //     6: node(1) * node(1)
    //     7: node(6) * node(1)
    //     8: node(7) + node(0)
    //     9: node(8) + node(5)
    //     10: node(9) + node(0)

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
}

#[test]
fn test_construction_for_bls12_377() {
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

    // Useful during testing: unfiltered- to filtered-index map
    // let index_map = HashMap::from_iter([
    //     (0, 0),
    //     (1, 1),
    //     (2, 2),
    //     (3, 3),
    //     (5, 4),
    //     (6, 5),
    //     (7, 6),
    //     (8, 7),
    // ]);

    //      [   |   -P_x    ]
    //      [ I |   -P_y    ]
    // A =  [   |   -P_z    ]
    //      [---------------]
    //      [ 0 |   P_add   ]
    let p_column = -p_x.v_stack(p_y.v_stack(p_z));
    let a_upper = SparseMatrix::identity(3 * m * k).h_stack(&p_column);
    let a_lower = SparseMatrix::zero(m * k, 3 * m * k).h_stack(&p_add);
    let expected_a = a_upper.v_stack(a_lower);

    assert_eq!(
        LigeroCircuit::new(circuit, output_node, DEFAULT_SECURITY_LEVEL).a,
        expected_a
    );
}
