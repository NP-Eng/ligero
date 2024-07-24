use num_bigint::BigUint;
use std::{collections::HashMap, fmt::Display};

use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node<F: PrimeField> {
    /// Variable set individually for each execution
    Variable,
    /// Constant across all executions
    Constant(F),
    /// Addition gate with indices of its left and right input within a larger
    /// circuit
    Add(usize, usize),
    // Multiplication gate with indices of its left and right input within a
    // larger circuit
    Mul(usize, usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArithmeticCircuit<F: PrimeField> {
    // List of nodes of the circuit
    pub(crate) nodes: Vec<Node<F>>,
    // Hash map of constants defined in the circuit in order to avoid duplication
    constants: HashMap<F, usize>,
    // Big-endian bit decomposition of F::MODULUS - 1, without initial zeros
    unit_group_bits: Option<Vec<bool>>,
}

impl<F: PrimeField> ArithmeticCircuit<F> {
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn num_constants(&self) -> usize {
        self.constants.len()
    }

    pub fn num_variables(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| **node == Node::Variable)
            .count()
    }

    pub fn last(&self) -> usize {
        self.nodes.len() - 1
    }

    pub fn num_gates(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| match node {
                Node::Add(_, _) | Node::Mul(_, _) => true,
                _ => false,
            })
            .count()
    }

    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            constants: HashMap::new(),
            unit_group_bits: Option::None,
        }
    }

    pub fn constant(&mut self, value: F) -> usize {
        if let Some(index) = self.constants.get(&value) {
            *index
        } else {
            let index = self.push_node(Node::Constant(value));
            self.constants.insert(value, index);
            index
        }
    }

    pub fn variable(&mut self) -> usize {
        self.push_node(Node::Variable)
    }

    pub fn variables(&mut self, num: usize) -> Vec<usize> {
        (0..num).map(|_| self.variable()).collect()
    }

    fn add_unchecked(&mut self, left: usize, right: usize) -> usize {
        self.push_node(Node::Add(left, right))
    }

    pub fn add(&mut self, left: usize, right: usize) -> usize {
        let length = self.nodes.len();
        assert!(left < length, "Left operand to Add not in circuit:");
        assert!(right < length, "Right operand to Add not in circuit:");

        self.push_node(Node::Add(left, right))
    }

    pub fn mul_unchecked(&mut self, left: usize, right: usize) -> usize {
        self.push_node(Node::Mul(left, right))
    }

    pub fn mul(&mut self, left: usize, right: usize) -> usize {
        let length = self.nodes.len();
        assert!(left < length, "Left operand to Mul not in circuit:");
        assert!(right < length, "Right operand to Mul not in circuit:");

        self.push_node(Node::Mul(left, right))
    }

    pub fn add_nodes(&mut self, indices: impl IntoIterator<Item = usize>) -> usize {
        indices
            .into_iter()
            .reduce(|acc, index| self.add(acc, index))
            .unwrap()
    }

    pub fn mul_nodes(&mut self, indices: impl IntoIterator<Item = usize>) -> usize {
        indices
            .into_iter()
            .reduce(|acc, index| self.mul(acc, index))
            .unwrap()
    }

    pub fn pow_bigint(&mut self, node: usize, exponent: BigUint) -> usize {
        assert!(
            node < self.num_nodes(),
            "Base node ({node}) not in the circuit (which contains {} nodes)",
            self.num_nodes()
        );

        let binary_decomposition = exponent
            .to_radix_be(2)
            .into_iter()
            .map(|b| b == 1)
            .skip_while(|b| !b)
            .collect::<Vec<_>>();

        self.pow_binary(node, &binary_decomposition)
    }

    pub fn pow(&mut self, node: usize, exponent: usize) -> usize {
        self.pow_bigint(node, exponent.into())
    }

    // Standard square-and-multiply. The first bit is always one, so we can
    // skip it and initialise the accumulator to node instead of 1
    fn pow_binary(&mut self, node: usize, binary_decomposition: &Vec<bool>) -> usize {
        let mut current = node;

        for bit in binary_decomposition.iter().skip(1) {
            current = self.mul_unchecked(current, current);

            if *bit {
                current = self.mul_unchecked(current, node);
            }
        }

        current
    }

    // Computes the node x^(F::MODULUS - 1), which is 0 if x = 0 and 1 otherwise
    pub fn indicator(&mut self, node: usize) -> usize {
        let unit_group_bits = self
            .unit_group_bits
            .get_or_insert_with(|| {
                let mod_minus_one: F::BigInt = (-F::ONE).into();
                mod_minus_one
                    .to_bits_be()
                    .into_iter()
                    .skip_while(|b| !b)
                    .collect()
            })
            .clone();

        self.pow_binary(node, &unit_group_bits)
    }

    pub fn minus(&mut self, node: usize) -> usize {
        let minus_one = self.constant(-F::ONE);
        self.mul(minus_one, node)
    }

    // Compute the scalar product of two vectors of nodes. Does NOT perform
    // optimisations by, for instance, skipping multiplication of the form 1 * x
    // or 0 * x, or omitting addition of zero terms.
    pub fn scalar_product(
        &mut self,
        left: impl IntoIterator<Item = usize>,
        right: impl IntoIterator<Item = usize>,
    ) -> usize {
        let products = left
            .into_iter()
            .zip(right.into_iter())
            .map(|(l, r)| self.mul_unchecked(l, r))
            .collect::<Vec<_>>();
        self.add_nodes(products)
    }

    fn push_node(&mut self, node: Node<F>) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    // Evaluate all nodes required to compute the output node, returning the
    // full vector of intermediate node values. Nodes not involved in the
    // computation (and not passed as part of the variable assignment) are left
    // as None
    pub fn evaluate_full(&self, vars: Vec<(usize, F)>, node: usize) -> Vec<Option<F>> {
        let mut node_assignments = self
            .nodes
            .iter()
            .map(|node| {
                if let Node::Constant(c) = node {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect::<Vec<Option<F>>>();

        // This does not check (for efficiency reasons) that each variable was
        // supplied with only one value: in the case of duplicates, the latest
        // one in the list is used
        for (index, value) in vars {
            if self.nodes[index] == Node::Variable {
                node_assignments[index] = Some(value);
            } else {
                panic!("Value supplied for non-variable node");
            }
        }

        self.inner_evaluate(node, &mut node_assignments);

        node_assignments
    }

    fn inner_evaluate(&self, node_index: usize, node_assignments: &mut Vec<Option<F>>) {
        if let Some(_) = node_assignments[node_index] {
            return;
        }

        let node = &self.nodes[node_index];

        match node {
            Node::Variable => panic!("Uninitialised variable"),
            Node::Constant(_) => panic!("Uninitialised constant"),
            Node::Add(left, right) | Node::Mul(left, right) => {
                self.inner_evaluate(*left, node_assignments);
                self.inner_evaluate(*right, node_assignments);

                let left_value = node_assignments[*left].unwrap();
                let right_value = node_assignments[*right].unwrap();

                node_assignments[node_index] = Some(match node {
                    Node::Add(_, _) => left_value + right_value,
                    Node::Mul(_, _) => left_value * right_value,
                    _ => unreachable!(),
                });
            }
        }
    }

    pub fn evaluate(&self, vars: Vec<(usize, F)>, node: usize) -> F {
        self.evaluate_full(vars, node)[node].unwrap()
    }

    fn print_evaluation(&self, vars: Vec<(usize, F)>, node: usize) {
        println!("Arithmetic circuit with {} nodes:", self.num_nodes());

        let evaluations = self.evaluate_full(vars, node);

        for (index, (node, value)) in self.nodes.iter().zip(evaluations.iter()).enumerate() {
            if let Node::Constant(c) = node {
                println!("\t{index}: Constant = {c:?}");
            } else {
                let value = if let Some(v) = value {
                    format!("{v:?}")
                } else {
                    "not set".to_string()
                };

                println!("\t{index}: {node} = {value}");
            }
        }
    }

    pub fn from_constraint_system(cs: &ConstraintSystem<F>) -> Self {
        // TODO include assertion (likely irrelevant in practice) that the
        // *effective* number of constraints is less than F::MODULUS
        // minus...one? two? In any case, getting the effective number of
        // constraints is a difficult task in itself, to be addressed in v2 of
        // this compiler

        let ConstraintMatrices { a, b, c, .. } = cs.to_matrices().unwrap();

        let mut circuit = ArithmeticCircuit::new();
        let one = circuit.constant(F::ONE);
        circuit.variables(cs.num_instance_variables + cs.num_witness_variables - 1);

        let mut row_expressions = |matrix: Vec<Vec<(F, usize)>>| {
            matrix
                .into_iter()
                .map(|row| circuit.compile_sparse_scalar_product(row))
                .collect::<Vec<_>>()
        };

        // Az, Bz, Cz
        let a = row_expressions(a);
        let b = row_expressions(b);
        let c = row_expressions(c);

        // Az (hadamard) Bz
        let pairwise_mul_a_b = a
            .into_iter()
            .zip(b.into_iter())
            .map(|(a, b)| circuit.mul(a, b))
            .collect::<Vec<_>>();

        let minus_one = circuit.constant(-F::ONE);
        let minus_c = c
            .into_iter()
            .map(|c| circuit.mul(c, minus_one))
            .collect::<Vec<_>>();

        // Az * Bz - Cz == 0
        let constraints = pairwise_mul_a_b
            .into_iter()
            .zip(minus_c.into_iter())
            .map(|(ab, c)| circuit.add(ab, c))
            .collect::<Vec<_>>();

        let indicators = constraints
            .into_iter()
            .map(|constraint| circuit.indicator(constraint))
            .collect::<Vec<_>>();

        let node_sum = circuit.add_nodes(indicators);
        circuit.add(node_sum, one);
        circuit
    }

    // Compile a sparse scalar product into nodes. Relies on some assumptions
    // guaranteed by `from_constraint_systems`, which should be the only caller.
    // Performs certain optimisations, most notably: terms of the form C * 1 and
    // 1 * V are simplified to C and V respectively.
    fn compile_sparse_scalar_product(&mut self, sparse_row: Vec<(F, usize)>) -> usize {
        let constants = sparse_row
            .into_iter()
            .map(|(c, var_index)| (self.constant(c), var_index))
            .collect::<Vec<_>>();

        let products = constants
            .into_iter()
            .map(|(c_index, var_index)| {
                // If either the constant or the variable is ONE, we can just return the other
                if c_index == 0 || var_index == 0 {
                    c_index + var_index
                } else {
                    self.mul(c_index, var_index)
                }
            })
            .collect::<Vec<_>>();

        self.add_nodes(products)
    }
}

impl<F: PrimeField> Display for Node<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Variable => write!(f, "Variable"),
            Node::Constant(c) => write!(f, "Constant({})", c),
            Node::Add(left, right) => write!(f, "node({}) + node({})", left, right),
            Node::Mul(left, right) => write!(f, "node({}) * node({})", left, right),
        }
    }
}

impl<F: PrimeField> Display for ArithmeticCircuit<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Arithmetic circuit with {} nodes:", self.num_nodes())?;

        for (index, node) in self.nodes.iter().enumerate() {
            writeln!(f, "\t{}: {}", index, node)?;
        }
        Ok(())
    }
}
