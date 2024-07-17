use std::fmt::Display;

use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq)]
enum Node<F: PrimeField> {
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

// TODO remove
// let node1 = circuit.variable()
// let node2 = circuit.variable()
// let node3 = circuit.add(node1, node2)
// let node4 = circuit.mul(node2, node3)
// let node4 = circuit.m(node4) // ^p-1
//
// Circuit = {id1: gate_1, id2: gate_2}

// let gate3 = circuit.add(gate_1, gate_2)
// let gate4 = circuit.constant(F::from(25));

// gate_3 = gate_1 + gate_2
// circuit.update(gate_3)

// Circuit = {id1: gate_1, id2: gate_2, id3: Add(id1, id2)}

// TODO Think of the correct relation between R1CS and circuit in terms of
// instance/witness, public/private inputs and constants
//
// R1CS: instance, witness
// Circuit: (alpha_1, ... alpha_n)
//
// Maybe    instance <-> circuit constants
//          witness <-> (alpha_1, ... alpha_n) (= circuit variables)

// TODO think about optimising this sort of duplication introduced by circom/R1CS
// one = circuit.one();
// fortyseven = circuit.constant(47);
// circuit.mul(fortyseven, one);
//
// as opposed to
// circuit.constant(47);

// TODO save zero-trimmed bit decomposition of p - 1

// TODO better use of unchecked methods

// TODO call one() when reading
// TODO add constraints -1, 0 to the constraint system

#[derive(Clone)]
pub struct ArithmeticCircuit<F: PrimeField> {
    // List of nodes of the circuit
    nodes: Vec<Node<F>>,
    one: Option<usize>,
}

impl<F: PrimeField> ArithmeticCircuit<F> {
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
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
            one: None,
        }
    }

    pub fn one(&mut self) -> usize {
        match self.one {
            Some(index) => index,
            None => self.constant(F::ONE),
        }
    }

    pub fn constant(&mut self, value: F) -> usize {
        self.push_node(Node::Constant(value))
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

    pub fn pow(&mut self, node: usize, exponent: F::BigInt) -> usize {
        assert!(
            node < self.num_nodes(),
            "Base node ({node}) not in the circuit (which contains {} nodes)",
            self.num_nodes()
        );

        let binary_decomposition = exponent
            .to_bits_be()
            .into_iter()
            .skip_while(|b| !b)
            .collect::<Vec<_>>();
        println!("Binary decomposition: {:?}", binary_decomposition);

        // Standard square-and-multiply. The first bit is always one, so we can
        // skip it and initialise the accumulator to node instead of 1

        let mut current = node;

        for bit in binary_decomposition.into_iter().skip(1) {
            current = self.mul_unchecked(current, current);

            if bit {
                current = self.mul_unchecked(current, node);
            }
        }

        current
    }

    pub fn indicator(&mut self, node: usize) -> usize {
        self.pow(node, (-F::one()).into())
    }

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

    pub fn sparse_scalar_product(&mut self, sparse_row: Vec<(F, usize)>) -> usize {
        let constants = sparse_row
            .into_iter()
            .map(|(c, var_index)| (self.constant(c), var_index))
            .collect::<Vec<_>>();

        let products = constants
            .into_iter()
            .map(|(c_index, var_index)| self.mul(c_index, var_index))
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
                    "None".to_string()
                };

                println!("\t{index}: {node:?} = {value}");
            }
        }
    }

    pub fn from_constraint_system(cs: &ConstraintSystem<F>) -> Self {
        let ConstraintMatrices { a, b, c, .. } = cs.to_matrices().unwrap();

        let mut circuit = ArithmeticCircuit::new();
        let one = circuit.one();
        circuit.variables(cs.num_instance_variables + cs.num_witness_variables - 1);

        let mut row_expressions = |matrix: Vec<Vec<(F, usize)>>| {
            matrix
                .into_iter()
                .map(|row| circuit.sparse_scalar_product(row))
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

        let minus_one = circuit.constant(-F::one());
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
}

impl<F: PrimeField> Display for Node<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Variable => write!(f, "Variable"),
            Node::Constant(c) => write!(f, "Constant({})", c),
            Node::Add(left, right) => write!(f, "{} + {})", left, right),
            Node::Mul(left, right) => write!(f, "{} * {}", left, right),
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
