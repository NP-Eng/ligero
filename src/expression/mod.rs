use ark_ff::PrimeField;
use itertools::Itertools;
use std::{
    collections::HashMap,
    fmt::Display,
    hash::Hash,
    iter::{Product, Sum},
    ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

use crate::arithmetic_circuit::ArithmeticCircuit;
use crate::arithmetic_circuit::Node;

#[cfg(test)]
pub mod tests;

/// Utilities that expose a user-friendly way to construct arithmetic circuits,
/// with syntax along the lines of:
/// let x = Expression::Variable(0);
/// let y = Expression::Variable(1);
/// let output = y^2 - (x^2 + x + 1) // 0 if (x, y) are in the corresponding elliptic curve!

/// Syntax summary:
/// - Expression::variable(id) creates a variable with the given ID.
///
/// - Expression::constant(value) creates a constant with the given F value.
///
/// - +, -, *, ^ are overloaded to mean addition, subtraction, multiplication, and exponentiation of expressions
///   Their assigning counterparts +=, -=, *=, ^= are also overloaded.
///
/// - Constants in the form of F can be used as operands on the right-hand side only.
///   This is due to the implementation for i32 from the next point.
///   E.g.: F::from(3) * exp, F::ONE * exp, and exp * F::from(3) are all valid
///   However, 3 * exp, -5 * exp, and exp * 3 are not.
///
/// - Constants in the form of i32 (where F: From<i32>) can be used as operands on the left-hand side only.
///   This is due to i32 and PrimeField both being foreign types.
///   E.g. 1 + exp and -5 * exp are both valid, equivalent to F::from(1) + exp and F::from(-5) * exp, respectively.
///   However, exp + 1, exp - 3 and exp * -5 are not.
enum ExpressionInner<F: PrimeField> {
    Variable(usize), // ID
    Constant(F),
    Add(Expression<F>, Expression<F>),
    Mul(Expression<F>, Expression<F>),
}

// New type pattern necessary so that we can implement operators such as +,
// which we can't directly do on the foreign type Rc<ExpressionInner<F>>
pub struct Expression<F: PrimeField>(Rc<ExpressionInner<F>>);

impl<F: PrimeField> Expression<F> {
    pub fn constant(value: F) -> Self {
        Expression(Rc::new(ExpressionInner::Constant(value)))
    }

    pub fn variable(id: usize) -> Self {
        Expression(Rc::new(ExpressionInner::Variable(id)))
    }

    pub fn to_arithmetic_circuit(&self) -> ArithmeticCircuit<F> {
        let mut nodes = HashMap::new();
        self.update_map(&mut nodes);

        let ptr_to_idx = nodes
            .iter()
            .map(|(ptr, (idx, _))| (*ptr, nodes.len() - idx - 1))
            .collect::<HashMap<_, _>>();

        let sorted_nodes = nodes
            .into_iter()
            .sorted_by(|(_, (i, _)), (_, (j, _))| j.cmp(i))
            .map(|(_, (_, node))| node)
            .collect::<Vec<_>>();

        let mut nodes = Vec::new();
        for node in sorted_nodes {
            match node {
                Node::Variable => {
                    nodes.push(Node::Variable);
                }
                Node::Constant(value) => {
                    nodes.push(Node::Constant(value));
                }
                Node::Add(a, b) => {
                    nodes.push(Node::Add(ptr_to_idx[&a], ptr_to_idx[&b]));
                }
                Node::Mul(a, b) => {
                    nodes.push(Node::Mul(ptr_to_idx[&a], ptr_to_idx[&b]));
                }
            }
        }

        ArithmeticCircuit {
            nodes,
            constants: HashMap::new(),
            unit_group_bits: None,
        }
        .filter_constants()
    }

    fn pointer(&self) -> usize {
        self.0.as_ref() as *const _ as usize
    }

    fn update_map(&self, nodes: &mut HashMap<usize, (usize, Node<F>)>) {
        if nodes.contains_key(&self.pointer()) {
            return;
        }
        match &*self.0 {
            ExpressionInner::Variable(id) => {
                nodes.insert(self.pointer(), (nodes.len(), Node::Variable));
            }
            ExpressionInner::Constant(value) => {
                nodes.insert(self.pointer(), (nodes.len(), Node::Constant(*value)));
            }
            ExpressionInner::Add(a, b) => {
                nodes.insert(
                    self.pointer(),
                    (nodes.len(), Node::Add(a.pointer(), b.pointer())),
                );
                a.update_map(nodes);
                b.update_map(nodes);
            }
            ExpressionInner::Mul(a, b) => {
                nodes.insert(
                    self.pointer(),
                    (nodes.len(), Node::Mul(a.pointer(), b.pointer())),
                );
                a.update_map(nodes);
                b.update_map(nodes);
            }
        }
    }

    pub fn scalar_product(a: Vec<Expression<F>>, b: Vec<Expression<F>>) -> Expression<F> {
        a.into_iter().zip(b.into_iter()).map(|(a, b)| a * b).sum()
    }

    pub fn sparse_scalar_product(a: &Vec<(F, usize)>, b: &Vec<Expression<F>>) -> Expression<F> {
        a.into_iter()
            .map(|(a, i)| b[*i].clone() * *a)
            .collect::<Vec<_>>()
            .into_iter()
            .sum()
    }

    pub fn pow(self, rhs: usize) -> Self {
        self ^ rhs
    }

    pub fn pow_assign(&mut self, rhs: usize) {
        *self ^= rhs;
    }
}

impl<F: PrimeField> Clone for Expression<F> {
    fn clone(&self) -> Self {
        Expression(Rc::clone(&self.0))
    }
}

impl<F: PrimeField> Add for Expression<F> {
    type Output = Expression<F>;

    fn add(self, rhs: Self) -> Self::Output {
        Expression(Rc::new(ExpressionInner::Add(self.clone(), rhs.clone())))
    }
}

impl<F: PrimeField + From<i32>> Add<Expression<F>> for i32 {
    type Output = Expression<F>;

    fn add(self, rhs: Expression<F>) -> Self::Output {
        Expression::constant(F::from(self)) + rhs
    }
}

impl<F: PrimeField> AddAssign for Expression<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<F: PrimeField> Add<F> for Expression<F> {
    type Output = Expression<F>;

    fn add(self, rhs: F) -> Self::Output {
        self + Expression::constant(rhs)
    }
}

impl<F: PrimeField> AddAssign<F> for Expression<F> {
    fn add_assign(&mut self, rhs: F) {
        *self = self.clone() + rhs;
    }
}

impl<F: PrimeField> Mul for Expression<F> {
    type Output = Expression<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        Expression(Rc::new(ExpressionInner::Mul(self.clone(), rhs.clone())))
    }
}

impl<F: PrimeField + From<i32>> Mul<Expression<F>> for i32 {
    type Output = Expression<F>;

    fn mul(self, rhs: Expression<F>) -> Self::Output {
        Expression::constant(F::from(self)) * rhs
    }
}

impl<F: PrimeField> MulAssign for Expression<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<F: PrimeField> Mul<F> for Expression<F> {
    type Output = Expression<F>;

    fn mul(self, rhs: F) -> Self::Output {
        self * Expression::constant(rhs)
    }
}

impl<F: PrimeField> MulAssign<F> for Expression<F> {
    fn mul_assign(&mut self, rhs: F) {
        *self = self.clone() * rhs;
    }
}

impl<F: PrimeField> Neg for Expression<F> {
    type Output = Expression<F>;

    fn neg(self) -> Self::Output {
        Expression::constant(-F::ONE) * self
    }
}

impl<F: PrimeField> Sub for Expression<F> {
    type Output = Expression<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl<F: PrimeField + From<i32>> Sub<Expression<F>> for i32 {
    type Output = Expression<F>;

    fn sub(self, rhs: Expression<F>) -> Self::Output {
        Expression::constant(F::from(self)) - rhs
    }
}

impl<F: PrimeField> SubAssign for Expression<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<F: PrimeField> Sub<F> for Expression<F> {
    type Output = Expression<F>;

    fn sub(self, rhs: F) -> Self::Output {
        self + (-rhs)
    }
}

impl<F: PrimeField> SubAssign<F> for Expression<F> {
    fn sub_assign(&mut self, rhs: F) {
        *self = self.clone() - rhs;
    }
}

impl<F: PrimeField> BitXor<usize> for Expression<F> {
    type Output = Expression<F>;

    fn bitxor(self, rhs: usize) -> Self::Output {
        if rhs == 0 {
            return self;
        }

        let mut bits = (0..usize::BITS).rev().map(|pos| (rhs >> pos) & 1);

        bits.position(|bit| bit == 1);

        let mut current = self.clone();

        for bit in bits.into_iter() {
            current = current.clone() * current;

            if bit == 1 {
                current = current.clone() * self.clone();
            }
        }

        current
    }
}

impl<F: PrimeField> BitXorAssign<usize> for Expression<F> {
    fn bitxor_assign(&mut self, rhs: usize) {
        *self = self.clone() ^ rhs;
    }
}

impl<F: PrimeField> Sum for Expression<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|a, b| a + b).unwrap()
    }
}

impl<F: PrimeField> Product for Expression<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|a, b| a * b).unwrap()
    }
}

impl<F: PrimeField> Display for Expression<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = self.pointer();
        match &*self.0 {
            ExpressionInner::Variable(id) => write!(f, "Variable({})<{}>", id, hash),
            ExpressionInner::Constant(value) => write!(f, "Constant({:?})<{}>", value, hash),
            ExpressionInner::Add(a, b) => {
                write!(f, "Add({}, {})<{}>", a.pointer(), b.pointer(), hash)
            }
            ExpressionInner::Mul(a, b) => {
                write!(f, "Mul({}, {})<{}>", a.pointer(), b.pointer(), hash)
            }
        }
    }
}
