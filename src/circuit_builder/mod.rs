#[cfg(test)]
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};
use std::{
    borrow::BorrowMut,
    collections::{HashMap, HashSet},
    fmt::Display,
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
    rc::Rc,
    vec,
};

use crate::TEST_DATA_PATH;
use crate::{arithmetic_circuit::Node, reader::read_constraint_system};

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

    fn to_arithmetic_circuit(&self) -> Vec<Node<F>> {
        let mut nodes = Vec::<Node<F>>::new();
        self.update_nodes(&mut nodes);
        nodes
    }

    fn update_nodes(&self, nodes: &mut Vec<Node<F>>) {
        nodes.iter_mut().for_each(|node| match node {
            Node::Add(a, b) | Node::Mul(a, b) => {
                *a += 1;
                *b += 1;
            }
            _ => (),
        });
        match &self {
            Expression::Variable(v) => {
                nodes.push(Node::Variable);
            }
            Expression::Constant(c) => {
                nodes.push(Node::Constant(*c));
            }
            Expression::Add(a) => {
                nodes.push(Node::Add(0, 1));
                a.left.update_nodes(nodes);
                a.right.update_nodes(nodes);
            }
            Expression::Mul(m) => {
                nodes.push(Node::Mul(0, 1));
                m.left.update_nodes(nodes);
                m.right.update_nodes(nodes);
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

#[test]
fn test_to_arithmetic_circuit() {
    let a = Expression::<Fr>::Variable(0);
    let b = Expression::Variable(1);
    let c = Expression::Variable(2);
    let d = Expression::Variable(3);
    let e = Expression::Variable(4);

    let expr = a * b * c + d + e;

    let circuit = expr.to_arithmetic_circuit();
    println!("{:?}", circuit);
}
