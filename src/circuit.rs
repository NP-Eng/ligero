#[cfg(test)]
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};
use std::{
    borrow::BorrowMut,
    collections::HashSet,
    fmt::Display,
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
    rc::Rc,
};

use crate::reader::read_constraint_system;
use crate::TEST_DATA_PATH;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expression<F: PrimeField> {
    Variable(usize), // ID
    Constant(F),
    Add(Rc<Adder<F>>),
    Mul(Rc<Multiplier<F>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Adder<F: PrimeField> {
    left: Expression<F>,
    right: Expression<F>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Multiplier<F: PrimeField> {
    left: Expression<F>,
    right: Expression<F>,
}

impl<F: PrimeField> Expression<F> {
    fn exp(&self, exponent: F::BigInt) -> Self {
        let binary_decomposition = exponent
            .to_bits_be()
            .into_iter()
            .skip_while(|b| !b)
            .collect::<Vec<_>>();
        let mut result = Expression::Constant(F::one());
        let mut current = self.clone();

        for bit in binary_decomposition.into_iter().rev() {
            if bit == true {
                result = result * current.clone();
            }
            current = current.clone() * current;
        }
        result
    }

    // Computes self ^ (p - 1), where p is the characteristic of the field
    // When the field is prime, this is equivalent to computing the inverse of self
    // thus, the expression will be identical to zero iff self is zero
    fn indicator_function(&self) -> Self {
        self.exp((-F::one()).into())
    }

    // Count the number of gates in the expression
    fn num_gates(&self) -> usize {
        let mut seen_gates = HashSet::new();
        self.explore_gates(&mut seen_gates);
        seen_gates.len()
    }

    fn explore_gates<'a>(&'a self, explored_gates: &mut HashSet<usize>) {
        match &self {
            Expression::Add(a) => {
                if explored_gates.contains(&(a.as_ref() as *const _ as usize)) {
                    return;
                }
                explored_gates.insert(a.as_ref() as *const _ as usize);
                a.left.explore_gates(explored_gates);
                a.right.explore_gates(explored_gates);
            }
            Expression::Mul(m) => {
                if explored_gates.contains(&(m.as_ref() as *const _ as usize)) {
                    return;
                }
                explored_gates.insert(m.as_ref() as *const _ as usize);
                m.left.explore_gates(explored_gates);
                m.right.explore_gates(explored_gates);
            }
            _ => (),
        }
    }
}

impl<F: PrimeField> Add for Expression<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Expression::Add(Rc::new(Adder {
            left: self,
            right: rhs,
        }))
    }
}

impl<F: PrimeField> Add<F> for Expression<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        Expression::Add(Rc::new(Adder {
            left: self,
            right: Expression::Constant(rhs),
        }))
    }
}

impl<F: PrimeField> Mul for Expression<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Expression::Mul(Rc::new(Multiplier {
            left: self,
            right: rhs,
        }))
    }
}

impl<F: PrimeField> Mul<F> for Expression<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Expression::Mul(Rc::new(Multiplier {
            left: self,
            right: Expression::Constant(rhs),
        }))
    }
}

impl<F: PrimeField> Neg for Expression<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Expression::Mul(Rc::new(Multiplier {
            left: Expression::Constant(-F::one()),
            right: self,
        }))
    }
}

impl<F: PrimeField> Sub for Expression<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Expression::Add(Rc::new(Adder {
            left: self,
            right: -rhs,
        }))
    }
}

impl<F: PrimeField> Sub<F> for Expression<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        Expression::Add(Rc::new(Adder {
            left: self,
            right: Expression::Constant(-rhs),
        }))
    }
}

impl<F: PrimeField> Sum for Expression<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|a, b| a + b).unwrap()
    }
}

fn scalar_product<F: PrimeField>(a: Vec<Expression<F>>, b: Vec<Expression<F>>) -> Expression<F> {
    a.into_iter().zip(b.into_iter()).map(|(a, b)| a * b).sum()
}

fn sparse_scalar_product<F: PrimeField>(
    a: &Vec<(F, usize)>,
    b: &Vec<Expression<F>>,
) -> Expression<F> {
    a.into_iter()
        .map(|(a, i)| b[*i].clone() * *a)
        .collect::<Vec<_>>()
        .into_iter()
        .sum()
}

struct Circuit<F: PrimeField> {
    expression: Expression<F>,
}

impl<F: PrimeField> Circuit<F> {
    fn from_constraint_system(cs: &ConstraintSystem<F>) -> Self {
        let ConstraintMatrices { a, b, c, .. } = cs.to_matrices().unwrap();

        let solution_vector = [
            vec![Expression::Constant(F::one())],
            (0..cs.num_instance_variables + cs.num_witness_variables)
                .map(|i| Expression::Variable(i))
                .collect::<Vec<_>>(),
        ]
        .concat();

        let row_expressions = |matrix: Vec<Vec<(F, usize)>>| {
            matrix
                .into_iter()
                .map(|row| sparse_scalar_product(&row, &solution_vector))
                .collect::<Vec<_>>()
        };

        // Az, Bz, Cz
        let a = row_expressions(a);
        let b = row_expressions(b);
        let c = row_expressions(c);

        // Az * Bz - Cz == 0
        let constraints = a
            .into_iter()
            .zip(b.into_iter().zip(c.into_iter()))
            .map(|(a, (b, c))| a * b - c)
            .collect::<Vec<_>>();

        let indicators = constraints
            .iter()
            .map(|constraint| constraint.indicator_function())
            .collect::<Vec<_>>();

        Circuit {
            expression: indicators.into_iter().sum::<Expression<F>>()
                + Expression::Constant(F::one()),
        }
    }

    fn num_gates(&self) -> usize {
        self.expression.num_gates()
    }
}

// To print the circuit, we need to implement the Display trait for Expression
impl<F: PrimeField> Display for Expression<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Variable(id) => write!(f, "x_{}", id),
            Expression::Constant(c) => write!(f, "{}", c),
            Expression::Add(adder) => write!(f, "({} + {})", adder.left, adder.right),
            Expression::Mul(multiplier) => {
                write!(f, "({} * {})", multiplier.left, multiplier.right)
            }
        }
    }
}
