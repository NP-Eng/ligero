use num_bigint::BigUint;
use std::{collections::HashMap, fmt::Display};

use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};

#[cfg(test)]
pub mod tests;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node<F> {
    /// Variable set individually for each execution
    // Since no two variables have the same label, no memory cost is incurred
    // due to owning the string as opposed to a &'a str
    Variable(String),
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
    pub(crate) constants: HashMap<F, usize>,
    // Map from variable labels to node indices
    pub(crate) variables: HashMap<String, usize>,
    // Big-endian bit decomposition of F::MODULUS - 1, without initial zeros
    pub(crate) unit_group_bits: Option<Vec<bool>>,
}

impl<F: PrimeField> ArithmeticCircuit<F> {
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn num_constants(&self) -> usize {
        self.constants.len()
    }

    pub fn num_variables(&self) -> usize {
        self.variables.len()
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
            variables: HashMap::new(),
            unit_group_bits: Option::None,
        }
    }

    /// Returns existing constant with value `value` if it exists, or creates a
    /// new one and returns its index if it does not
    pub fn constant(&mut self, value: F) -> usize {
        if let Some(index) = self.constants.get(&value) {
            *index
        } else {
            let index = self.push_node(Node::Constant(value));
            self.constants.insert(value, index);
            index
        }
    }

    /// Creates a variable with the given label
    ///
    /// # Panics
    /// Panics if the circuit already contains a variable with name `var_N`
    //
    // Receiving &str to ease caller syntax
    pub fn new_variable_with_label(&mut self, label: &str) -> usize {
        let index = self.push_node(Node::Variable(label.to_string()));

        if self.variables.insert(label.to_string(), index).is_some() {
            panic!("Variable label already in use: {label}");
        }

        index
    }

    /// Creates a variable with the label `var_N`, where `N` is the number of
    /// variables in the circuit
    ///
    /// # Panics
    /// Panics if the circuit already contains a variable with name `var_N`
    pub fn new_variable(&mut self) -> usize {
        self.new_variable_with_label(&format!("var_{}", self.num_variables()))
    }

    pub fn new_variables(&mut self, num: usize) -> Vec<usize> {
        (0..num).map(|_| self.new_variable()).collect()
    }

    pub fn get_variable(&self, label: &str) -> usize {
        *self.variables.get(label).expect("Variable not in circuit")
    }

    /// Adds the two nodes without checking that they are in the circuit
    fn add_unchecked(&mut self, left: usize, right: usize) -> usize {
        self.push_node(Node::Add(left, right))
    }

    /// Adds the two nodes, checking that they are in the circuit
    pub fn add(&mut self, left: usize, right: usize) -> usize {
        let length = self.nodes.len();
        assert!(left < length, "Left operand to Add not in circuit:");
        assert!(right < length, "Right operand to Add not in circuit:");

        self.push_node(Node::Add(left, right))
    }

    /// Multiplies the two nodes without checking that they are in the circuit
    pub fn mul_unchecked(&mut self, left: usize, right: usize) -> usize {
        self.push_node(Node::Mul(left, right))
    }

    /// Multiplies the two nodes, checking that they are in the circuit
    pub fn mul(&mut self, left: usize, right: usize) -> usize {
        let length = self.nodes.len();
        assert!(left < length, "Left operand to Mul not in circuit:");
        assert!(right < length, "Right operand to Mul not in circuit:");

        self.push_node(Node::Mul(left, right))
    }

    /// Adds all nodes in the given iterator
    pub fn add_nodes(&mut self, indices: impl IntoIterator<Item = usize>) -> usize {
        indices
            .into_iter()
            .reduce(|acc, index| self.add(acc, index))
            .unwrap()
    }

    /// Multiplies all nodes in the given list
    pub fn mul_nodes(&mut self, indices: impl IntoIterator<Item = usize>) -> usize {
        indices
            .into_iter()
            .reduce(|acc, index| self.mul(acc, index))
            .unwrap()
    }

    /// Computes node^exponent, where exponent is a BigUint
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

    /// Computes node^exponent, where exponent is a usize
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

    /// Computes the node x^(F::MODULUS - 1), which is 0 if x = 0 and 1 otherwise
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

    /// Computes the negation of the given node
    pub fn minus(&mut self, node: usize) -> usize {
        let minus_one = self.constant(-F::ONE);
        self.mul(minus_one, node)
    }

    /// Computes the scalar product of two vectors of nodes. Does NOT perform
    /// optimisations by, for instance, skipping multiplication of the form 1 * x
    /// or 0 * x, or omitting addition of zero terms.
    pub fn scalar_product(
        &mut self,
        left: impl IntoIterator<Item = usize>,
        right: impl IntoIterator<Item = usize>,
    ) -> usize {
        let products = left
            .into_iter()
            .zip(right)
            .map(|(l, r)| self.mul_unchecked(l, r))
            .collect::<Vec<_>>();
        self.add_nodes(products)
    }

    fn push_node(&mut self, node: Node<F>) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    // Auxiliary recursive function which evaluation_trace wraps around
    fn inner_evaluate(&self, node_index: usize, node_assignments: &mut Vec<Option<F>>) {
        if node_assignments[node_index].is_some() {
            return;
        }

        let node = &self.nodes[node_index];

        match node {
            Node::Variable(_) => panic!("Uninitialised variable"),
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

    // ************************ Evaluation functions ***************************

    // Evaluate all nodes required to compute the output node, returning the
    // full vector of intermediate node values. Nodes not involved in the
    // computation (and not passed as part of the variable assignment) are left
    // as None
    pub fn evaluation_trace(&self, vars: Vec<(usize, F)>, node: usize) -> Vec<Option<F>> {
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
            if let Node::Variable(_) = self.nodes[index] {
                node_assignments[index] = Some(value);
            } else {
                panic!("Value supplied for non-variable node");
            }
        }

        self.inner_evaluate(node, &mut node_assignments);

        node_assignments
    }

    pub fn evaluation_trace_with_labels(
        &self,
        vars: Vec<(&str, F)>,
        node: usize,
    ) -> Vec<Option<F>> {
        let vars = vars
            .into_iter()
            .map(|(label, value)| (self.get_variable(label), value))
            .collect::<Vec<_>>();

        self.evaluation_trace(vars, node)
    }

    // Evaluate all nodes required to compute all output nodes, returning the
    // full vector of intermediate node values. Nodes not involved in the
    // computation (and not passed as part of the variable assignment) are left
    // as None
    pub fn evaluation_trace_multioutput(
        &self,
        vars: Vec<(usize, F)>,
        outputs: &Vec<usize>,
    ) -> Vec<Option<F>> {
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
            if let Node::Variable(_) = self.nodes[index] {
                node_assignments[index] = Some(value);
            } else {
                panic!("Value supplied for non-variable node");
            }
        }

        outputs
            .iter()
            .for_each(|node| self.inner_evaluate(*node, &mut node_assignments));

        node_assignments
    }

    pub fn evaluation_trace_multioutput_with_labels(
        &self,
        vars: Vec<(&str, F)>,
        outputs: &Vec<usize>,
    ) -> Vec<Option<F>> {
        let vars = vars
            .into_iter()
            .map(|(label, value)| (self.get_variable(label), value))
            .collect::<Vec<_>>();

        self.evaluation_trace_multioutput(vars, outputs)
    }

    pub fn evaluate_node(&self, vars: Vec<(usize, F)>, node: usize) -> F {
        self.evaluation_trace(vars, node)[node].unwrap()
    }

    pub fn evaluate_node_with_labels(&self, vars: Vec<(&str, F)>, node: usize) -> F {
        self.evaluation_trace_with_labels(vars, node)[node].unwrap()
    }

    pub fn evaluate_multioutput(&self, vars: Vec<(usize, F)>, outputs: &Vec<usize>) -> Vec<F> {
        self.evaluation_trace_multioutput(vars, outputs)
            .into_iter()
            .enumerate()
            .filter_map(|(i, v)| if outputs.contains(&i) { v } else { None })
            .collect()
    }

    pub fn evaluate_multioutput_with_labels(
        &self,
        vars: Vec<(&str, F)>,
        outputs: &Vec<usize>,
    ) -> Vec<F> {
        self.evaluation_trace_multioutput_with_labels(vars, outputs)
            .into_iter()
            .enumerate()
            .filter_map(|(i, v)| if outputs.contains(&i) { v } else { None })
            .collect()
    }

    pub fn evaluate(&self, vars: Vec<(usize, F)>) -> F {
        self.evaluate_node(vars, self.last())
    }

    pub fn evaluate_with_labels(&self, vars: Vec<(&str, F)>) -> F {
        self.evaluate_node_with_labels(vars, self.last())
    }

    fn print_evaluation_trace(&self, var_assignment: Vec<(usize, F)>, node: usize) {
        println!("Arithmetic circuit with {} nodes:", self.num_nodes());

        let evaluations = self.evaluation_trace(var_assignment, node);

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

    fn print_evaluation_trace_multioutput(
        &self,
        var_assignment: Vec<(usize, F)>,
        outputs: &Vec<usize>,
    ) {
        println!("Arithmetic circuit with {} nodes:", self.num_nodes());

        let evaluations = self.evaluation_trace_multioutput(var_assignment, outputs);

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

    // ************************ Compilation functions **************************

    pub fn from_constraint_system(cs: &ConstraintSystem<F>) -> (Self, Vec<usize>) {
        let ConstraintMatrices { a, b, c, .. } = cs.to_matrices().unwrap();

        let mut circuit = ArithmeticCircuit::new();
        let one = circuit.constant(F::ONE);
        circuit.new_variables(cs.num_instance_variables + cs.num_witness_variables - 1);

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
            .zip(b)
            .map(|(a, b)| circuit.mul(a, b))
            .collect::<Vec<_>>();

        let minus_one = circuit.constant(-F::ONE);
        let minus_c = c
            .into_iter()
            .map(|c| circuit.mul(c, minus_one))
            .collect::<Vec<_>>();

        // Az * Bz - Cz + 1
        let outputs = pairwise_mul_a_b
            .into_iter()
            .zip(minus_c)
            .map(|(ab, m_c)| circuit.add_nodes([ab, m_c, one]))
            .collect::<Vec<_>>();

        (circuit, outputs)
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
            Node::Variable(label) => write!(f, "{}", label),
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

// Discards duplicated constants and updates all gate relations accordingly
pub(crate) fn filter_constants<F: PrimeField>(
    nodes: &Vec<Node<F>>,
) -> (Vec<Node<F>>, HashMap<F, usize>) {
    // Map of unique constants mapping sending value to final position
    let mut constants = HashMap::new();

    // Mapping from original indices to post-constant-removal indices
    let mut filtered_indices = HashMap::new();

    let mut removed_constants = 0;

    nodes.iter().enumerate().for_each(|(i, node)| match node {
        Node::Constant(v) => {
            if constants.contains_key(v) {
                removed_constants += 1;
            } else {
                constants.insert(*v, i - removed_constants);
                filtered_indices.insert(i, i - removed_constants);
            }
        }
        _ => {
            filtered_indices.insert(i, i - removed_constants);
        }
    });

    // TODO possibly change to into_iter and avoid node cloning if the
    // borrow checker can find it in its heart to accept that
    let new_nodes = nodes
        .iter()
        .enumerate()
        .filter_map(|(i, node)| {
            match node {
                Node::Constant(_) => {
                    // Checking if this is the first appearance of the constant
                    if filtered_indices.contains_key(&i) {
                        Some(node.clone())
                    } else {
                        None
                    }
                }
                Node::Variable(_) => Some(node.clone()),
                Node::Add(left, right) | Node::Mul(left, right) => {
                    let updated_left = match nodes[*left] {
                        Node::Constant(c) => *constants.get(&c).unwrap(),
                        _ => *filtered_indices.get(left).unwrap(),
                    };
                    let updated_right = match nodes[*right] {
                        Node::Constant(c) => *constants.get(&c).unwrap(),
                        _ => *filtered_indices.get(right).unwrap(),
                    };
                    match node {
                        Node::Add(_, _) => Some(Node::Add(updated_left, updated_right)),
                        Node::Mul(_, _) => Some(Node::Mul(updated_left, updated_right)),
                        _ => unreachable!(),
                    }
                }
            }
        })
        .collect();

    (new_nodes, constants)
}
