use crate::{
    arithmetic_circuit::ArithmeticCircuit, ligero::LigeroCircuit, matrices::SparseMatrix,
    DEFAULT_SECURITY_LEVEL,
};
use ark_bn254::Fq;
use ark_ff::Field;

// Defining equation of Bn254: y^2 = x^3 + 3 in Fq
fn generate_bn254_circuit() -> ArithmeticCircuit<Fq> {
    let mut circuit = ArithmeticCircuit::new();

    // Ligero circuits must start with a constant 1
    let one = circuit.constant(Fq::ONE);
    let three = circuit.constant(Fq::from(3u8));

    let x = circuit.variable();
    let y = circuit.variable();

    let y_squared = circuit.pow(y, 2);
    let minus_y_squared = circuit.minus(y_squared);
    let x_cubed = circuit.pow(x, 3);

    // Ligero will prove x^3 + 3 - y^2 + 1 = 1 Note that one could compute the
    // left-hand side as x^3 + 4 - y^2 in order to save one addition gate
    circuit.add_nodes([x_cubed, three, minus_y_squared, one]);
    circuit

    // n_i = 2, s = 8

    // Original circuit
    //     0: Constant(1)
    //     1: Constant(3)
    //     2: Variable
    //     3: Variable
    //     4: node(3) * node(3)
    //     5: Constant(21888242871839275222246405745257275088696311157297823662689037894645226208582)
    //     6: node(5) * node(4)
    //     7: node(2) * node(2)
    //     8: node(7) * node(2)
    //     9: node(8) + node(1)
    //     10: node(9) + node(6)
    //     11: node(10) + node(0)

    // Circuit with only one constant: the initial 1
    //     0: Constant(1)
    //     1: Variable
    //     2: Variable
    //     3: node(2) * node(2)
    //     4: node(3) * -1
    //     5: node(1) * node(1)
    //     6: node(5) * node(1)
    //     7: node(6) + 3
    //     8: node(7) + node(4)
    //     9: node(8) + 1

    // Induced matrices:
    //       Row index      P_x         P_y         P_z        P_add
    //       0              []          []          []         []
    //       1              []          []          []         []
    //       2              []          []          []         []
    //       3              [(1, 2)]    [(1, 2)]    [(1, 3)]   []
    //       4              [(1, 3)]    [(-1, 0)]   [(1, 4)]   []
    //       5              [(1, 1)]    [(1, 1)]    [(1, 5)]   []
    //       6              [(1, 5)]    [(1, 1)]    [(1, 6)]   []
    //       7              []          []          []         [(1, 6), (3, 0), (-1, 7)]
    //       8              []          []          []         [(1, 7), (1, 4), (-1, 8)]
    //       9              []          []          []         [(1, 8), (1, 0), (-1, 9)]
    //       10             []          []          []         []
    //       11             []          []          []         []
    //       12             []          []          []         []
    //       13             []          []          []         []
    //       14             []          []          []         []
    //       15             []          []          []         []}
}

#[test]
fn test_construction_for_bn254() {
    let circuit = generate_bn254_circuit();

    let output_node = circuit.last();
    let (m, k) = (4, 4);

    let p_x = SparseMatrix::from_rows(
        [
            vec![vec![]; 3],
            vec![
                vec![(Fq::ONE, 2)],
                vec![(Fq::ONE, 3)],
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
                vec![(-Fq::ONE, 0)],
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
            vec![vec![]; 3],
            vec![
                vec![(Fq::ONE, 6), (Fq::from(3u8), 0), (-Fq::ONE, 7)],
                vec![(Fq::ONE, 7), (Fq::ONE, 4), (-Fq::ONE, 8)],
                vec![(Fq::ONE, 8), (Fq::ONE, 0), (-Fq::ONE, 9)],
            ],
            vec![vec![]; 10],
        ]
        .concat(),
        m * k,
    );

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
