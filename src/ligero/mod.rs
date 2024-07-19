use ark_ff::PrimeField;

use crate::{
    arithmetic_circuit::{ArithmeticCircuit, Node},
    matrices::SparseMatrix,
};

pub struct LigeroCircuit<F: PrimeField> {
    /// Arithmetic circuit to be proved
    circuit: ArithmeticCircuit<F>,

    /// Index of the output node in the circuit
    output_node: usize,

    /// Matrix encoding the relation between x, y, z, and the w, as well as the
    /// additive gates of the circuit
    //      [   |   -P_x    ]
    //      [ I |   -P_y    ]
    // A =  [   |   -P_z    ]
    //      [---------------]
    //      [ 0 |   P_add   ]
    a: SparseMatrix<F>,

    /// Number of rows of the P matrices prior to encoding
    m: usize,

    /// Number of columns of the P matrices prior to encoding
    l: usize,

    /// Block length of the Reed Solomon code
    n: usize,

    /// Dimension of the Reed Solomon code >= l
    k: usize,

    /// Number of column openings
    t: usize,
}

impl<F: PrimeField> LigeroCircuit<F> {
    pub fn new(circuit: ArithmeticCircuit<F>, output_node: usize) -> Self {
        // TODO handle this case gracefully: add constant 1 at the beginning of the the circuit
        if circuit.nodes[0] != Node::Constant(F::ONE) {
            panic!("First node in the circuit must be the constant 1");
        }

        // TODO check validity, including
        //  - the fact that each gate depends only on previous gates
        //  - disallow add(const, const) or mul(const, const)

        // More efficient way to compute:
        //  1 + circuit.num_variables() - circuit.num_gates()
        // or, in the notation of the paper,
        //  1 - n_i - s.
        // The first 1 comes from the constant 1, which is does not appear in
        // the less-general version in the article.
        let sol_vec_length = 1 + circuit.num_nodes() - circuit.num_constants();

        let (m, l) = Self::compute_dimensions(sol_vec_length);
        let (n, k, t) = Self::reed_solomon_parameters(m, l);

        let a = Self::generate_matrices(&circuit, m * l);

        Self {
            circuit,
            output_node,
            a,
            m,
            l,
            n,
            k,
            t,
        }
    }

    // TODO: THIS MUST BE REDONE, REQUIRES AN IN DEPTH ANALYSIS OF m AND l
    fn compute_dimensions(sol_vec_length: usize) -> (usize, usize) {
        let x = (sol_vec_length as f64).sqrt();
        let m = x.ceil() as usize;
        (m, m)
    }

    fn reed_solomon_parameters(m: usize, l: usize) -> (usize, usize, usize) {
        todo!();
    }

    fn generate_matrices(circuit: &ArithmeticCircuit<F>, num_cols: usize) -> SparseMatrix<F> {
        let nodes = &circuit.nodes;

        let mut p_x = SparseMatrix::new(num_cols);
        let mut p_y = SparseMatrix::new(num_cols);
        let mut p_z = SparseMatrix::new(num_cols);
        let mut p_add = SparseMatrix::new(num_cols);

        let mut seen_constants = 0;

        nodes.iter().enumerate().skip(1).for_each(|(i, node)| {
            match node {
                Node::Variable => {
                    p_x.push_empty_row();
                    p_y.push_empty_row();
                    p_z.push_empty_row();
                    p_add.push_empty_row();
                }
                Node::Constant(_) => {
                    seen_constants += 1;
                }
                Node::Add(l_node, r_node) => {
                    p_x.push_empty_row();
                    p_y.push_empty_row();
                    p_z.push_empty_row();

                    let mut row = vec![];

                    if let Node::Constant(c) = nodes[*l_node] {
                        row.extend(vec![(c, 0), (F::ONE, *r_node - seen_constants)]);
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        row.extend(vec![(c, 0), (F::ONE, *l_node - seen_constants)]);
                    } else {
                        // Add(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Add(non-constant, non-constant)
                        row.extend(vec![
                            (F::ONE, *l_node - seen_constants),
                            (F::ONE, *r_node - seen_constants),
                        ]);
                    }
                    row.push((-F::ONE, i - seen_constants));
                    p_add.push_row(row);
                }
                Node::Mul(l_node, r_node) => {
                    p_add.push_empty_row();

                    if let Node::Constant(c) = nodes[*l_node] {
                        p_x.push_row(vec![(c, 0)]);
                        p_y.push_row(vec![(F::ONE, *r_node - seen_constants)]);
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        p_x.push_row(vec![(F::ONE, *l_node - seen_constants)]);
                        p_y.push_row(vec![(c, 0)]);
                    } else {
                        // Mul(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Mul(non-constant, non-constant)
                        p_x.push_row(vec![(F::ONE, *l_node - seen_constants)]);
                        p_y.push_row(vec![(F::ONE, *r_node - seen_constants)]);
                    }
                    // TODO important question: is the coefficient -1 or 1? The paper is not clear
                    p_z.push_row(vec![(-F::ONE, i - seen_constants)]);
                }
            }
        });

        // TODO add row with the constraint output = 0

        // Constructing
        //      [   |   -P_x    ]
        //      [ I |   -P_y    ]
        // A =  [   |   -P_z    ]
        //      [---------------]
        //      [ 0 |   P_add   ]
        let upper_right = -p_x.h_stack(&p_y).h_stack(&p_z);
        let upper = SparseMatrix::identity(3 * num_cols).h_stack(&upper_right);
        let lower = SparseMatrix::zero(num_cols, num_cols).h_stack(&p_add);
        upper.v_stack(lower)
    }

    pub fn prove(&self, vars: Vec<(usize, F)>) {
        // Solution vector, w in the notation of the paper. The first element is
        // an extra 1 used to handle constants in this more general version
        let w: Vec<F> = self
            .circuit
            .evaluate_full(vars, self.output_node)
            .into_iter()
            .zip(
                self
                .circuit
                .nodes
                .iter()
            )
            .enumerate()
            .filter(|(i, (_, node))| !matches!(node, Node::Constant(_)) || *i == 0)
            .map(|(_, (val, _))| val.expect(
                "Uninitialised variable. Make sure the circuit only contains nodes on which the final output truly depends"
            ))
            .collect();
    }
}
