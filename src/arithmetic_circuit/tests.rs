use ark_ff::{Field, UniformRand};
use ark_std::test_rng;

use crate::{
    arithmetic_circuit::ArithmeticCircuit, reader::read_constraint_system, TEST_DATA_PATH,
};

use ark_bn254::Fr;

#[test]
fn test_add_constants() {
    let mut circuit = ArithmeticCircuit::new();
    let one = circuit.one();
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
    let full_eval = circuit.evaluate_full(vec![(a, Fr::rand(&mut test_rng()))], circuit.last());

    full_eval.iter().enumerate().for_each(|(index, val)| {
        println!("\t{}: {:?}", index, val);
    });

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
    circuit.print_evaluation(valid_assignment.clone(), circuit.last());

    assert_eq!(circuit.evaluate(valid_assignment, circuit.last()), Fr::ONE);
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

// TODO tests:
// - Cannot set non-variable to a value
// - When setting a variable twice, the last value is used
// - Initialisation?
// - Minimal computation graph, including variable handling
// - Wrap-around arithmetic
// - Fibonacci with 1 constant
