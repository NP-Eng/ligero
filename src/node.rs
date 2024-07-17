use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem};

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

#[derive(Clone)]
pub struct ArithmeticCircuit<F: PrimeField> {
    output_node: usize,
    nodes: Vec<Node<F>>,
}

impl<F: PrimeField> ArithmeticCircuit<F> {
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn num_gates() {}

    pub fn evaluate_in_full(&self, vars: Vec<(usize, F)>) -> Vec<Option<F>> {
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

        // This does check that all variables were supplied: that will result in
        // an uninitialisation error later on. It also does not check (for
        // efficiency) that each variable was supplied with only one value: in
        // the case of duplicates, the latest one in the list is used
        for (index, value) in vars {
            if self.nodes[index] == Node::Variable {
                node_assignments[index] = Some(value);
            } else {
                panic!("Value supplied for non-variable node");
            }
        }

        self.inner_evaluate(self.output_node, &mut node_assignments);

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

    pub fn evaluate(&self, vars: Vec<(usize, F)>) -> F {
        self.evaluate_in_full(vars)[self.output_node].unwrap()
    }

    pub fn from_constraint_system(cs: &ConstraintSystem<F>) {
        let ConstraintMatrices { a, b, c, .. } = cs.to_matrices().unwrap();
    }
}
