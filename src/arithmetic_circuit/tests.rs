use ark_ff::{Field, UniformRand};
use ark_std::test_rng;

use crate::{
    arithmetic_circuit::ArithmeticCircuit, reader::read_constraint_system, TEST_DATA_PATH,
};

use ark_bn254::Fr;

#[test]
fn test_add_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let one = circuit.constant(Fr::ONE);
    let two = circuit.constant(Fr::from(2));
    let three = circuit.add(one, two);
    assert_eq!(circuit.evaluate(vec![], three), Fr::from(3));
}

#[test]
fn test_mul_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.constant(Fr::from(6));
    let b = circuit.constant(Fr::from(2));
    let c = circuit.mul(a, b);
    assert_eq!(circuit.evaluate(vec![], c), Fr::from(12));
}

#[test]
fn test_pow_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let two = circuit.constant(Fr::from(2));
    let four = circuit.pow(two, Fr::from(5).into());
    assert_eq!(circuit.evaluate(vec![], four), Fr::from(32));
}

#[test]
fn test_add_variables() {
    let mut circuit = ArithmeticCircuit::new();
    let input = circuit.variables(2);
    let c = circuit.add(input[0], input[1]);
    assert_eq!(
        circuit.evaluate(vec![(input[0], Fr::from(2)), (input[1], Fr::from(3))], c),
        Fr::from(5)
    );
}

#[test]
fn test_mul_variables() {
    let mut circuit = ArithmeticCircuit::new();
    let input = circuit.variables(2);
    let c = circuit.mul(input[0], input[1]);
    assert_eq!(
        circuit.evaluate(vec![(input[0], Fr::from(2)), (input[1], Fr::from(3))], c),
        Fr::from(6)
    );
}

#[test]
fn test_pow_variable() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.variable();
    let b = circuit.pow(a, Fr::from(4).into());
    assert_eq!(circuit.evaluate(vec![(a, Fr::from(2))], b), Fr::from(16));
}

#[test]
fn test_indicator() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.variable();
    let b = circuit.indicator(a);

    // TODO remove
    circuit.print_evaluation(vec![(a, Fr::rand(&mut test_rng()))], circuit.last());

    assert_eq!(
        circuit.evaluate(vec![(a, Fr::rand(&mut test_rng()))], b),
        Fr::from(1)
    );
}

#[test]
fn test_multiplication() {
    let cs = read_constraint_system::<Fr>(
        &format!(TEST_DATA_PATH!(), "multiplication.r1cs"),
        &format!(TEST_DATA_PATH!(), "multiplication.wasm"),
    );

    let circuit = ArithmeticCircuit::<Fr>::from_constraint_system(&cs);

    let (a, b, c) = (Fr::from(6), Fr::from(3), Fr::from(2));
    let valid_assignment = vec![(1, a), (2, b), (3, c)];

    // TODO remove
    // circuit.print_evaluation(valid_assignment.clone(), circuit.last());
    println!("{circuit}");

    assert_eq!(circuit.evaluate(valid_assignment, circuit.last()), Fr::ONE);
}

#[test]
fn test_cube() {
    let r1cs = read_constraint_system::<Fr>(
        &format!(TEST_DATA_PATH!(), "cube.r1cs"),
        &format!(TEST_DATA_PATH!(), "cube.wasm"),
    );

    let naive_circuit = ArithmeticCircuit::from_constraint_system(&r1cs);

    let mut clever_circuit = ArithmeticCircuit::new();
    let x = clever_circuit.variable();
    let x_cubed = clever_circuit.pow(x, Fr::from(3).into());
    let c = clever_circuit.constant(-Fr::from(26));
    clever_circuit.add(x_cubed, c);

    let mut another_clever_circuit = ArithmeticCircuit::new();
    let a_x = another_clever_circuit.variable();
    let a_x_2 = another_clever_circuit.mul(a_x, a_x);
    let a_x_cubed = another_clever_circuit.mul(a_x_2, a_x);
    let a_c = another_clever_circuit.constant(-Fr::from(26));
    another_clever_circuit.add(a_x_cubed, a_c);

    let mut yet_another_clever_circuit = ArithmeticCircuit::new();
    let y_a_x = yet_another_clever_circuit.variable();
    let y_a_x_cubed = yet_another_clever_circuit.mul_nodes([y_a_x, y_a_x, y_a_x]);
    let y_a_c = yet_another_clever_circuit.constant(-Fr::from(26));
    yet_another_clever_circuit.add(y_a_x_cubed, y_a_c);

    assert_eq!(
        naive_circuit.evaluate(
            vec![(1, Fr::from(3)), (2, Fr::from(9))],
            naive_circuit.last()
        ),
        Fr::ONE
    );

    [
        &clever_circuit,
        &another_clever_circuit,
        &yet_another_clever_circuit,
    ]
    .iter()
    .for_each(|circuit| {
        assert_eq!(
            circuit.evaluate(vec![(0, Fr::from(3))], circuit.last()),
            Fr::ONE
        )
    });

    assert_eq!(clever_circuit, another_clever_circuit);
    assert_eq!(clever_circuit, yet_another_clever_circuit);

    // The R1CS compiler uses an indicator for each constraint, leading to a massively blown-up circuit
    assert_eq!(naive_circuit.num_nodes(), 719);
    assert_eq!(clever_circuit.num_gates(), 3);
}

#[test]
fn test_fibonacci() {
    let mut circ = ArithmeticCircuit::<Fr>::new();

    let f_0 = circ.variable();
    let f_1 = circ.variable();

    let mut first_operand = f_0;
    let mut second_operand = f_1;

    for _ in 3..50 {
        let next = circ.add(first_operand, second_operand);
        first_operand = second_operand;
        second_operand = next;
    }

    let f_42 = Fr::from(267914296);

    // Checking F_42
    assert_eq!(
        circ.evaluate(vec![(f_0, Fr::ONE), (f_1, Fr::ONE)], 42 - 1),
        f_42,
    );

    // Checking F_42 after shifting the entire sequence by 4 positions
    assert_eq!(
        circ.evaluate(vec![(f_0, Fr::from(5)), (f_1, Fr::from(8))], 42 - 5),
        f_42,
    );
}
/*
#[test]
fn test_fibonacci_with_const() {

    let mut circ = ArithmeticCircuit::<Fr>::new();

    let f_0 = circ.constant(1);
    let f_1 = circ.variable();

    let mut first_operand = f_0;
    let mut second_operand = f_1;

    for _ in 3..50 {
        let next = circ.add(first_operand, second_operand);
        first_operand = second_operand;
        second_operand = next;
    }

    let f_42 = Fr::from(267914296);

    // Checking F_42
    assert_eq!(
        circ.evaluate(vec![(f_0, Fr::ONE), (f_1, Fr::ONE)], 42 - 1),
        f_42,
    );

    // Checking F_42 after shifting the entire sequence by 5 positions
    assert_eq!(
        circ.evaluate(vec![(f_0, Fr::from(5)), (f_1, Fr::from(8))], 41 - 5),
        f_42,
    );
}
 */
