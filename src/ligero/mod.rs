use ark_ff::PrimeField;

use crate::{
    arithmetic_circuit::{ArithmeticCircuit, Node},
    matrices::SparseMatrix,
};

pub struct LigeroCircuit<F: PrimeField> {
    circuit: ArithmeticCircuit<F>,
    matrices: LigeroMatrices<F>,
}

struct LigeroMatrices<F: PrimeField> {
    p_x: SparseMatrix<F>,
    p_y: SparseMatrix<F>,
    p_z: SparseMatrix<F>,
    p_add: SparseMatrix<F>,
}
impl<F: PrimeField> LigeroCircuit<F> {
    pub fn new(circuit: ArithmeticCircuit<F>) -> Self {
        // TODO handle this case gracefully: add constant 1 at the beginning of the the circuit
        if circuit.nodes[0] != Node::Constant(F::ONE) {
            panic!("First node in the circuit must be the constant 1");
        }

        // TODO check validity, including
        //  - the fact that each gate depends only on previous gates
        //  - disallow add(const, const) or mul(const, const)

        let matrices = Self::generate_matrices(&circuit);

        Self { circuit, matrices }
    }

    fn generate_matrices(circuit: &ArithmeticCircuit<F>) -> LigeroMatrices<F> {
        let nodes = &circuit.nodes;

        // TODO if interested, make this work:
        // let [mut p_x, mut p_y, mut p_z, mut p_add] = (0..4).map(|_| Vec::new()).to_slice();

        let mut p_x = Vec::new();
        let mut p_y = Vec::new();
        let mut p_z = Vec::new();
        let mut p_add = Vec::new();

        let mut seen_constants = 0;

        nodes.iter().enumerate().skip(1).for_each(|(i, node)| {
            match node {
                Node::Variable => {
                    p_x.push(vec![]);
                    p_y.push(vec![]);
                    p_z.push(vec![]);
                    p_add.push(vec![]);
                }
                Node::Constant(_) => {
                    seen_constants += 1;
                }
                Node::Add(l_node, r_node) => {
                    p_x.push(vec![]);
                    p_y.push(vec![]);
                    p_z.push(vec![]);

                    if let Node::Constant(c) = nodes[*l_node] {
                        p_add.push(vec![
                            (c, 0),
                            (F::ONE, *r_node - seen_constants),
                            (-F::ONE, i - seen_constants),
                        ]);
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        p_add.push(vec![
                            (c, 0),
                            (F::ONE, *l_node - seen_constants),
                            (-F::ONE, i - seen_constants),
                        ]);
                    } else {
                        // Add(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Add(non-constant, non-constant)
                        p_add.push(vec![
                            (F::ONE, *l_node - seen_constants),
                            (F::ONE, *r_node - seen_constants),
                            (-F::ONE, i - seen_constants),
                        ]);
                    }
                }
                Node::Mul(l_node, r_node) => {
                    p_add.push(vec![]);

                    if let Node::Constant(c) = nodes[*l_node] {
                        p_x.push(vec![(c, 0)]);
                        p_y.push(vec![(F::ONE, *r_node - seen_constants)]);
                        // TODO important question: is the coefficient -1 or 1? The paper is not clear
                        p_z.push(vec![(-F::ONE, i - seen_constants)]);
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        p_x.push(vec![(F::ONE, *l_node - seen_constants)]);
                        p_y.push(vec![(c, 0)]);
                        // TODO important question: is the coefficient -1 or 1? The paper is not clear
                        p_z.push(vec![(-F::ONE, i - seen_constants)]);
                    } else {
                        // Mul(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Mul(non-constant, non-constant)
                        p_x.push(vec![(F::ONE, *l_node - seen_constants)]);
                        p_y.push(vec![(F::ONE, *r_node - seen_constants)]);
                        // TODO important question: is the coefficient -1 or 1? The paper is not clear
                        p_z.push(vec![(-F::ONE, i - seen_constants)]);
                    }
                }
            }
        });

        // TODO add row with the constraint output = 0

        LigeroMatrices {
            p_x,
            p_y,
            p_z,
            p_add,
        }
    }
}
