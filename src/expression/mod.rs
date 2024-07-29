use ark_crypto_primitives::crh::sha256::digest::typenum::bit;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};
use itertools::Itertools;
use std::{
    collections::HashMap,
    fmt::Display,
    iter::Sum,
    ops::{Add, BitXor, Mul, Neg, Sub},
    rc::Rc,
};

use crate::arithmetic_circuit::ArithmeticCircuit;
use crate::arithmetic_circuit::Node;

#[cfg(test)]
pub mod tests;

// Utilities that expose a user-friendly way to construct arithmetic circuits,
// with syntax along the lines of:
// let x = Expression::Variable(0);
// let y = Expression::Variable(1);
// let output = y^2 - (x^2 + x + 1) // 0 if (x, y) are in the corresponding elliptic curve!

enum ExpressionInner<F> {
    Variable(usize), // ID
    Constant(F),
    Add(Expression<F>, Expression<F>),
    Mul(Expression<F>, Expression<F>),
}

// New type pattern necessary so that we can implement operators such as +,
// which we can't directly do on the foreign type Rc<ExpressionInner<F>>
struct Expression<F>(Rc<ExpressionInner<F>>);

impl<F: PrimeField> Expression<F> {
    fn constant(value: F) -> Self {
        Expression(Rc::new(ExpressionInner::Constant(value)))
    }

    fn variable(id: usize) -> Self {
        Expression(Rc::new(ExpressionInner::Variable(id)))
    }

    fn to_arithmetic_circuit(&self) -> ArithmeticCircuit<F> {
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

        let constants = nodes
            .iter()
            .enumerate()
            .filter_map(|(i, node)| match node {
                Node::Constant(value) => Some((*value, i)),
                _ => None,
            })
            .collect::<HashMap<_, _>>();

        ArithmeticCircuit {
            nodes,
            constants,
            unit_group_bits: Option::None,
        }
    }

    fn pointer(&self) -> usize {
        self.0.as_ref() as *const _ as usize
    }

    fn to_map(&self) -> HashMap<usize, (usize, Node<F>)> {
        let mut nodes = HashMap::new();
        self.update_map(&mut nodes);
        nodes
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

    fn scalar_product(a: Vec<Expression<F>>, b: Vec<Expression<F>>) -> Expression<F> {
        a.into_iter().zip(b.into_iter()).map(|(a, b)| a * b).sum()
    }

    fn sparse_scalar_product(a: &Vec<(F, usize)>, b: &Vec<Expression<F>>) -> Expression<F> {
        a.into_iter()
            .map(|(a, i)| b[*i].clone() * *a)
            .collect::<Vec<_>>()
            .into_iter()
            .sum()
    }
}

impl<F> Clone for Expression<F> {
    fn clone(&self) -> Self {
        Expression(Rc::clone(&self.0))
    }
}

impl<F> Add for Expression<F> {
    type Output = Expression<F>;

    fn add(self, rhs: Self) -> Self::Output {
        Expression(Rc::new(ExpressionInner::Add(self.clone(), rhs.clone())))
    }
}

impl<F: PrimeField> Add<F> for Expression<F> {
    type Output = Expression<F>;

    fn add(self, rhs: F) -> Self::Output {
        self + Expression::constant(rhs)
    }
}

// TODO unfortunately this cannot be done as such, but it would be pretty cool.
// Think of a workaround?
// impl<F: PrimeField + From<usize>> Add<usize> for Expression<F> {
//     type Output = Expression<F>;

//     fn add(self, rhs: usize) -> Self::Output {
//         self + Expression::constant(F::from(rhs))
//     }
// }

impl<F> Mul for Expression<F> {
    type Output = Expression<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        Expression(Rc::new(ExpressionInner::Mul(self.clone(), rhs.clone())))
    }
}

impl<F: PrimeField> Mul<F> for Expression<F> {
    type Output = Expression<F>;

    fn mul(self, rhs: F) -> Self::Output {
        self * Expression::constant(rhs)
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

impl<F: PrimeField> Sub<F> for Expression<F> {
    type Output = Expression<F>;

    fn sub(self, rhs: F) -> Self::Output {
        self + (-rhs)
    }
}

impl<F: PrimeField> BitXor<usize> for Expression<F> {
    type Output = Expression<F>;

    fn bitxor(self, rhs: usize) -> Self::Output {
        if rhs == 0 {
            return self;
        }

        let bits = (0..usize::BITS)
            .rev()
            .map(|pos| (rhs >> pos) & 1)
            .skip_while(|bit| *bit == 0);

        let mut result = Expression::constant(F::ONE);
        let mut current = self;

        for bit in bits.into_iter() {
            if bit == 1 {
                result = result * current.clone();
            }
            current = current.clone() * current;
        }
        result
    }
}

impl<F: PrimeField> Sum for Expression<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|a, b| a + b).unwrap()
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

// impl<F: PrimeField> Expression<F> {
//     fn exp(&self, exponent: F::BigInt) -> Self {
//         let binary_decomposition = exponent
//             .to_bits_be()
//             .into_iter()
//             .skip_while(|b| !b)
//             .collect::<Vec<_>>();
//         let mut result = Expression::Constant(F::one());
//         let mut current = self.clone();

//         for bit in binary_decomposition.into_iter().rev() {
//             if bit == true {
//                 result = result * current.clone();
//             }
//             current = current.clone() * current;
//         }
//         result
//     }

//     // Computes self ^ (p - 1), where p is the characteristic of the field When
//     // the field is prime, this is equivalent to computing the inverse of self
//     // thus, the expression will be identical to zero iff self is zero
//     fn indicator_function(&self) -> Self {
//         self.exp((-F::one()).into())
//     }

//     // Count the number of gates in the expression fn num_gates(&self) -> usize
//     // { let mut seen_gates = HashSet::new(); self.explore_gates(&mut
//     //     seen_gates); seen_gates.len() }

//     fn to_arithmetic_circuit(&self) -> ArithmeticCircuit<F> {
//         let mut nodes = BTreeMap::new();
//         self.explore_nodes(&mut nodes);
//         nodes
//     }

//     fn explore_nodes<'a>(&'a self, explored_nodes: &mut BTreeMap<usize, &Expression<F>>) {
//         match &self {
//             Expression::Add(a) => {
//                 if explored_nodes.contains_key(&(a.as_ref() as *const _ as usize)) {
//                     return;
//                 }
//                 explored_nodes.insert(a.as_ref() as *const _ as usize, &a);
//                 a.left.explore_nodes(explored_nodes);
//                 a.right.explore_nodes(explored_nodes);
//             }
//             Expression::Mul(m) => {
//                 if explored_nodes.contains(&(m.as_ref() as *const _ as usize)) {
//                     return;
//                 }
//                 explored_nodes.insert(m.as_ref() as *const _ as usize);
//                 m.left.explore_nodes(explored_nodes);
//                 m.right.explore_nodes(explored_nodes);
//             }
//             _ => {}
//         }
//     }
// }
