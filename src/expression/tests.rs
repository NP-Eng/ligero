use std::ops::{Add, Deref};

use ark_bn254::Fr;
use ark_ff::Field;

use super::{Expression, ExpressionInner};

#[test]
fn test_same_reference() {
    let mut f1 = Expression::<Fr>::variable(0);
    let mut f2 = Expression::<Fr>::variable(1);

    let original_f1 = f1.clone();

    for _ in 0..10 {
        let next = f1.clone() + f2.clone();
        f1 = f2;
        f2 = next;
    }

    let curious_result = f2 * original_f1.clone();

    match curious_result.0.deref() {
        ExpressionInner::Mul(_, right) => {
            assert_eq!(right.pointer(), original_f1.pointer())
        }
        _ => panic!("Expected a multiplication expression"),
    }
}

#[test]
fn test_some_operations() {
    let x_f = Fr::from(5);
    let y_f = Fr::from(3);

    let output = (y_f - Fr::ONE).pow([8]);
    // let output = x_f.pow([3]) + (y_f - Fr::ONE).pow([8]) - Fr::from(13);

    let x_exp = Expression::<Fr>::constant(x_f);
    let y_exp = Expression::<Fr>::constant(y_f);

    // let output_exp = ((x_exp^3) + (y_exp - Fr::ONE)^8) - Fr::from(13);
    // let circ_output = output_exp.to_arithmetic_circuit().evaluate_last(vec![]);
    let output_exp = y_exp ^ 2;

    let circ = output_exp.to_arithmetic_circuit();
    println!("OUTPUT: {:?}", circ.evaluate_full(vec![], circ.last()))

    // assert_eq!(output, circ_output);
}

#[test]
fn test_to_arithmetic_circuit() {
    /*


                    Mul()
            /                   \
          Add()                 Add()
        /       \          /              \
        |        |      Variable(c)      Mul()
        |        |                     /       \
        -------------------------------        |
            |     |                            |
            |     ------------------------------
            |                   |
         Variable(a)         Variable(b)

    6: Mul(5, 2) -> 35
    5: Add(4, 3) -> 5
    4: Variable(a) -> 3
    3: Variable(b) -> 2
    2: Add(1, 0) -> 7
    1: Variable(c) -> 1
    0: Mul(4, 3) -> 6

    [6, 1, 7, 2, 3, 5, 35]
    */
    let a = Expression::<Fr>::variable(0);
    let b = Expression::<Fr>::variable(1);
    let c = Expression::<Fr>::variable(2);

    let result = (a.clone() + b.clone()) * (c + a * b);

    let circuit = result.to_arithmetic_circuit();

    println!(
        "{:?}",
        circuit.evaluate_full(
            vec![(1, Fr::from(1)), (3, Fr::from(2)), (4, Fr::from(3))],
            6
        )
    );
}
