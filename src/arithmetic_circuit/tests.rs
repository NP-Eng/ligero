use ark_ec::short_weierstrass::Affine;
use ark_ff::{Field, UniformRand};
use ark_std::test_rng;

use crate::{
    arithmetic_circuit::{filter_constants, ArithmeticCircuit},
    reader::read_constraint_system,
    TEST_DATA_PATH,
};

use ark_bls12_377::{Fq as FqBLS, G1Affine};
use ark_bn254::Fr as FrBN;

use super::Node;

// Defining equation of BLS12-377: y^2 = x^3 + 1 (over Fq)
pub fn generate_bls12_377_circuit() -> ArithmeticCircuit<FqBLS> {
    let mut circuit = ArithmeticCircuit::new();

    // Ligero circuits must start with a constant 1
    let one = circuit.constant(FqBLS::ONE);

    let x = circuit.new_variable_with_label("x");
    let y = circuit.new_variable_with_label("y");

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
}

/// (x^2 + y^2)^2 - 120x^2 + 80y^2 + 1 = 1
pub(crate) fn generate_lemniscate_circuit() -> ArithmeticCircuit<FrBN> {
    let mut circuit = ArithmeticCircuit::new();

    // Ligero circuits must start with a constant 1
    let one = circuit.constant(FrBN::ONE);

    let x = circuit.new_variable();
    let y = circuit.new_variable();

    let a = circuit.constant(FrBN::from(120));
    let b = circuit.constant(FrBN::from(80));

    let x_2 = circuit.mul(x, x);
    let y_2 = circuit.mul(y, y);

    let a_x_2 = circuit.mul(a, x_2);
    let b_y_2 = circuit.mul(b, y_2);
    let minus_a_x_2 = circuit.minus(a_x_2);

    let x_2_plus_y_2 = circuit.add(x_2, y_2);
    let b_y_2_minus_a_x_2 = circuit.add(b_y_2, minus_a_x_2);

    let x_2_plus_y_2_2 = circuit.mul(x_2_plus_y_2, x_2_plus_y_2);

    circuit.add_nodes([x_2_plus_y_2_2, b_y_2_minus_a_x_2, one]);
    circuit
}

pub(crate) fn generate_3_by_3_determinant_circuit() -> ArithmeticCircuit<FrBN> {
    let mut circuit = ArithmeticCircuit::new();

    // Ligero circuits must start with a constant 1
    let one = circuit.constant(FrBN::ONE);

    let vars = circuit.new_variables(9);
    let det = circuit.new_variable();

    let aei = circuit.mul_nodes([vars[0], vars[4], vars[8]]);
    let bfg = circuit.mul_nodes([vars[1], vars[5], vars[6]]);
    let cdh = circuit.mul_nodes([vars[2], vars[3], vars[7]]);

    let ceg = circuit.mul_nodes([vars[2], vars[4], vars[6]]);
    let bdi = circuit.mul_nodes([vars[1], vars[3], vars[8]]);
    let afh = circuit.mul_nodes([vars[0], vars[5], vars[7]]);

    let sum1 = circuit.add_nodes([aei, bfg, cdh]);
    let sum2 = circuit.add_nodes([ceg, bdi, afh]);

    let minus_sum2 = circuit.minus(sum2);
    let minus_det = circuit.minus(det);

    circuit.add_nodes([sum1, minus_sum2, minus_det, one]);
    circuit
}

#[test]
fn test_add_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let one = circuit.constant(FrBN::ONE);
    let two = circuit.constant(FrBN::from(2));
    circuit.add(one, two);
    assert_eq!(circuit.evaluate(vec![]), FrBN::from(3));
}

#[test]
fn test_mul_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.constant(FrBN::from(6));
    let b = circuit.constant(FrBN::from(2));
    circuit.mul(a, b);
    assert_eq!(circuit.evaluate(vec![]), FrBN::from(12));
}

#[test]
fn test_pow_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let two = circuit.constant(FrBN::from(2));
    circuit.pow(two, 5);
    assert_eq!(circuit.evaluate(vec![]), FrBN::from(32));
}

#[test]
fn test_add_variables() {
    let mut circuit = ArithmeticCircuit::new();
    let input = circuit.new_variables(2);
    circuit.add(input[0], input[1]);
    assert_eq!(
        circuit.evaluate(vec![(input[0], FrBN::from(2)), (input[1], FrBN::from(3))]),
        FrBN::from(5)
    );
}

#[test]
fn test_mul_variables() {
    let mut circuit = ArithmeticCircuit::new();
    let input = circuit.new_variables(2);
    circuit.mul(input[0], input[1]);
    assert_eq!(
        circuit.evaluate(vec![(input[0], FrBN::from(2)), (input[1], FrBN::from(3))]),
        FrBN::from(6)
    );
}

#[test]
fn test_pow_variable() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.new_variable();
    circuit.pow(a, 4);
    assert_eq!(circuit.evaluate(vec![(a, FrBN::from(2))]), FrBN::from(16));
}

#[test]
fn test_indicator() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.new_variable();
    circuit.indicator(a);
    assert_eq!(
        circuit.evaluate(vec![(a, FrBN::rand(&mut test_rng()))]),
        FrBN::from(1)
    );
}

#[tokio::test]
async fn test_multiplication() {
    let cs = read_constraint_system::<FrBN>(
        &format!(TEST_DATA_PATH!(), "multiplication.r1cs"),
        &format!(TEST_DATA_PATH!(), "multiplication.wasm"),
    );

    let (circuit, _) = ArithmeticCircuit::<FrBN>::from_constraint_system(&cs);

    let (a, b, c) = (FrBN::from(6), FrBN::from(3), FrBN::from(2));
    let valid_assignment = vec![(1, a), (2, b), (3, c)];

    assert_eq!(circuit.evaluate(valid_assignment), FrBN::ONE);
}

#[tokio::test]
async fn test_cube_multioutput() {
    let r1cs = read_constraint_system::<FrBN>(
        &format!(TEST_DATA_PATH!(), "cube.r1cs"),
        &format!(TEST_DATA_PATH!(), "cube.wasm"),
    );

    let (circuit, outputs) = ArithmeticCircuit::from_constraint_system(&r1cs);

    let mut clever_circuit = ArithmeticCircuit::new();
    let x = clever_circuit.new_variable();
    let x_cubed = clever_circuit.pow(x, 3);
    let c = clever_circuit.constant(-FrBN::from(26));
    clever_circuit.add(x_cubed, c);

    let mut another_clever_circuit = ArithmeticCircuit::new();
    let a_x = another_clever_circuit.new_variable();
    let a_x_2 = another_clever_circuit.mul(a_x, a_x);
    let a_x_cubed = another_clever_circuit.mul(a_x_2, a_x);
    let a_c = another_clever_circuit.constant(-FrBN::from(26));
    another_clever_circuit.add(a_x_cubed, a_c);

    let mut yet_another_clever_circuit = ArithmeticCircuit::new();
    let y_a_x = yet_another_clever_circuit.new_variable();
    let y_a_x_cubed = yet_another_clever_circuit.mul_nodes([y_a_x, y_a_x, y_a_x]);
    let y_a_c = yet_another_clever_circuit.constant(-FrBN::from(26));
    yet_another_clever_circuit.add(y_a_x_cubed, y_a_c);

    let evaluation_trace = circuit
        .evaluation_trace_multioutput(vec![(1, FrBN::from(3)), (2, FrBN::from(9))], &outputs);
    assert_eq!(
        outputs
            .into_iter()
            .map(|output| evaluation_trace[output].unwrap())
            .collect::<Vec<_>>(),
        vec![FrBN::ONE, FrBN::ONE],
    );

    [
        &clever_circuit,
        &another_clever_circuit,
        &yet_another_clever_circuit,
    ]
    .iter()
    .for_each(|circuit| assert_eq!(circuit.evaluate(vec![(0, FrBN::from(3))]), FrBN::ONE));

    assert_eq!(clever_circuit, another_clever_circuit);
    assert_eq!(clever_circuit, yet_another_clever_circuit);

    // With the indicator-based compiler, this would result in 719 gates
    assert_eq!(circuit.num_nodes(), 15);
    assert_eq!(clever_circuit.num_gates(), 3);
}

#[test]
fn test_fibonacci() {
    let mut circ = ArithmeticCircuit::<FrBN>::new();

    let f_0 = circ.new_variable();
    let f_1 = circ.new_variable();

    let mut first_operand = f_0;
    let mut second_operand = f_1;

    for _ in 3..50 {
        let next = circ.add(first_operand, second_operand);
        first_operand = second_operand;
        second_operand = next;
    }

    let f_42 = FrBN::from(267914296);

    // Checking F_42
    assert_eq!(
        circ.evaluate_node(vec![(f_0, FrBN::ONE), (f_1, FrBN::ONE)], 42 - 1),
        f_42,
    );

    // Checking F_42 after shifting the entire sequence by 4 positions
    assert_eq!(
        circ.evaluate_node(vec![(f_0, FrBN::from(5)), (f_1, FrBN::from(8))], 42 - 5),
        f_42,
    );
}

#[test]
fn test_fibonacci_with_const() {
    let mut circ = ArithmeticCircuit::<FrBN>::new();

    let f_0 = circ.constant(FrBN::ONE);
    let f_1 = circ.new_variable();

    let mut first_operand = f_0;
    let mut second_operand = f_1;

    for _ in 3..50 {
        let next = circ.add(first_operand, second_operand);
        first_operand = second_operand;
        second_operand = next;
    }

    let f_42 = FrBN::from(267914296);

    // Checking F_42
    assert_eq!(circ.evaluate_node(vec![(f_1, FrBN::ONE)], 42 - 1), f_42);
}

#[test]
fn test_bls12_377_circuit() {
    let circuit = generate_bls12_377_circuit();

    let Affine { x, y, .. } = G1Affine::rand(&mut test_rng());

    assert_eq!(y.pow([2]), x.pow([3]) + FqBLS::ONE);

    let valid_assignment = vec![(1, x), (2, y)];
    assert_eq!(circuit.evaluate(valid_assignment.clone()), FqBLS::ONE);
}

#[test]
fn test_lemniscate_circuit() {
    let circuit = generate_lemniscate_circuit();

    let x = FrBN::from(8);
    let y = FrBN::from(4);

    let valid_assignment = vec![(1, x), (2, y)];
    assert_eq!(circuit.evaluate(valid_assignment), FrBN::ONE);
}

#[test]
fn test_generate_3_by_3_determinant_circuit() {
    let circuit = generate_3_by_3_determinant_circuit();

    let vars = (1..=9)
        .map(|i| (i, FrBN::from(i as u64)))
        .collect::<Vec<_>>();
    let det = FrBN::from(0);
    let valid_assignment = [vars, vec![(10, det)]].concat();

    assert_eq!(circuit.evaluate(valid_assignment), FrBN::ONE);

    let circuit = generate_3_by_3_determinant_circuit();

    let vars = vec![
        (1, FrBN::from(2)),
        (2, FrBN::from(0)),
        (3, FrBN::from(-1)),
        (4, FrBN::from(3)),
        (5, FrBN::from(5)),
        (6, FrBN::from(2)),
        (7, FrBN::from(-4)),
        (8, FrBN::from(1)),
        (9, FrBN::from(4)),
    ];
    let det = FrBN::from(13);
    let valid_assignment = [vars, vec![(10, det)]].concat();

    assert_eq!(circuit.evaluate(valid_assignment), FrBN::ONE);
}

#[test]
pub fn test_constant_filtering() {
    let nodes: Vec<Node<FqBLS>> = vec![
        Node::Variable("x".to_string()), // 0  -> 0
        Node::Constant(FqBLS::from(3)),  // 1  -> 1
        Node::Constant(FqBLS::from(3)),  // 2  ----
        Node::Variable("y".to_string()), // 3  -> 2
        Node::Mul(18, 2),                // 4  -> 3
        Node::Constant(-FqBLS::from(1)), // 5  -> 4
        Node::Mul(4, 1),                 // 6  -> 5
        Node::Mul(2, 2),                 // 7  -> 6
        Node::Constant(FqBLS::from(4)),  // 8  -> 7
        Node::Mul(7, 7),                 // 9  -> 8
        Node::Constant(-FqBLS::from(1)), // 10 ----
        Node::Add(8, 5),                 // 11 -> 9
        Node::Add(8, 14),                // 12 -> 10
        Node::Mul(17, 10),               // 13 -> 11
        Node::Constant(FqBLS::from(3)),  // 14 -----
        Node::Constant(-FqBLS::from(2)), // 15 -> 12
        Node::Variable("z".to_string()), // 16 -> 13
        Node::Constant(-FqBLS::from(1)), // 17 -----
        Node::Add(12, 5),                // 18 -> 14
    ];

    let filtered_nodes: Vec<Node<FqBLS>> = vec![
        Node::Variable("x".to_string()), // 0  -> 0
        Node::Constant(FqBLS::from(3)),  // 1  -> 1
        Node::Variable("y".to_string()), // 3  -> 2
        Node::Mul(14, 1),                // 4  -> 3
        Node::Constant(-FqBLS::from(1)), // 5  -> 4
        Node::Mul(3, 1),                 // 6  -> 5
        Node::Mul(1, 1),                 // 7  -> 6
        Node::Constant(FqBLS::from(4)),  // 8  -> 7
        Node::Mul(6, 6),                 // 9  -> 8
        Node::Add(7, 4),                 // 11 -> 9
        Node::Add(7, 1),                 // 12 -> 10
        Node::Mul(4, 4),                 // 13 -> 11
        Node::Constant(-FqBLS::from(2)), // 15 -> 12
        Node::Variable("z".to_string()), // 16 -> 13
        Node::Add(10, 4),                // 18 -> 14
    ];

    assert_eq!(filter_constants(&nodes).0, filtered_nodes);
}
