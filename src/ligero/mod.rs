use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_poly_commit::linear_codes::calculate_t;
use itertools::izip;
use std::{
    collections::{HashMap, HashSet},
    vec,
};

use crate::{
    arithmetic_circuit::{ArithmeticCircuit, Node},
    matrices::{DenseMatrix, SparseMatrix},
    utils::get_distinct_indices_from_prng,
};

#[cfg(test)]
mod tests;

// TODO: optimise: when can one evaluate the interpolating polynomial at the
// queried points instead of computing the whole RS encoding in the three
// individual tests?

pub struct LigeroCircuit<F: PrimeField> {
    /// Arithmetic circuit to be proved
    circuit: ArithmeticCircuit<F>,

    /// Index of the output node in the circuit
    output_node: usize,

    /// Matrix encoding the relation between `x`, `y`, `z`, and the `w`, as well as the
    /// additive gates of the circuit
    //      [   |   -P_x    ]
    //      [ I |   -P_y    ]
    // A =  [   |   -P_z    ]
    //      [---------------]
    //      [ 0 |   P_add   ]
    a: SparseMatrix<F>,

    /// Number of rows of the `P`` matrices prior to encoding
    m: usize,

    /// `l` and `k`` from the paper, which are made to coincide. This Number of
    /// columns of the P matrices prior to encoding, as well as the size of the
    /// small FFT domain
    k: usize,

    /// Block length of the Reed Solomon code
    n: usize,

    /// Number of column openings
    t: usize,

    /// Large FFT domain for the Reed-Solomon code, size: `n`
    large_domain: GeneralEvaluationDomain<F>,

    /// Small FFT domain for the Reed-Solomon code, size: `k`. Equal to `large_domain^(n/k)`
    small_domain: GeneralEvaluationDomain<F>,

    /// Intermediate FFT domain for the quadratic-constraints test, size: `2 * k`
    intermediate_domain: GeneralEvaluationDomain<F>,
}

pub struct LigeroProof<F: PrimeField> {
    // Matrix U = [U_x
    //             U_y
    //             U_z
    //             U_w]
    // purportedly encoding x || y || z || w as defined in the reference
    u: DenseMatrix<F>,

    // Proof for Test-Interleaved
    interleaved_proof: Vec<F>,

    // Proof for Test-Linear-Constraints
    linear_constraints_proof: DensePolynomial<F>,

    // Proof for Test-Quadratic-Constraints
    quadratic_constraints_proof: DensePolynomial<F>,
}

impl<F: PrimeField + Absorb> LigeroCircuit<F> {
    pub fn new(circuit: ArithmeticCircuit<F>, output_node: usize, lambda: usize) -> Self {
        // TODO handle this case gracefully: add constant 1 at the beginning of the the circuit
        if circuit.nodes[0] != Node::Constant(F::ONE) {
            panic!("First node in the circuit must be the constant 1");
        }

        // TODO check validity, including
        //  - the fact that each gate depends only on previous gates
        //  - disallow add(const, const) or mul(const, const)

        // More efficient way to compute:
        //  1 + circuit.num_variables() + circuit.num_gates()
        // or, in the notation of the paper,
        //  1 + n_i + s = m * k
        // The first 1 comes from the constant 1, which is does not appear in
        // the less-general version in the article.
        let sol_vec_length = 1 + circuit.num_nodes() - circuit.num_constants();

        // In this implementation, k = l by convention
        let (m, k) = Self::compute_dimensions(sol_vec_length);
        let (n, t) = Self::reed_solomon_parameters(m, k, lambda);

        // Map sending the original index of a node to its filtered index (the
        // position where it lands after removing all constants but the initial 1)
        let mut index_map = HashMap::new();
        let mut seen_constants = 0;

        // The constant 1 remains at position 0
        index_map.insert(0, 0);

        for (i, node) in circuit.nodes.iter().enumerate().skip(1) {
            match node {
                Node::Constant(_) => {
                    seen_constants += 1;
                }
                _ => {
                    index_map.insert(i, i - seen_constants);
                }
            }
        }

        // Constructing the main matrix A
        let a = Self::generate_matrices(&circuit, m * k, &index_map);

        let large_domain = GeneralEvaluationDomain::<F>::new(n).unwrap_or_else(|| {
            panic!(
                "The field F cannot accomodate FFT for msg.len() * RHO_INV = {} elements (too many)",
                n
            )
        });

        let small_domain = GeneralEvaluationDomain::<F>::new(k).unwrap();
        let intermediate_domain = GeneralEvaluationDomain::<F>::new(2 * k).unwrap();

        Self {
            circuit,
            output_node,
            a,
            m,
            n,
            k,
            t,
            large_domain,
            small_domain,
            intermediate_domain,
        }
    }

    pub fn format_circuit(mut circuit: ArithmeticCircuit<F>) -> ArithmeticCircuit<F> {
        // Get the index of the constant 1 in the circuit, if it exists
        let one_index = circuit
            .constants
            .get(&F::ONE)
            .unwrap_or(&usize::MAX)
            .to_owned();

        // Move the constant 1 to the beginning of the circuit
        if one_index != usize::MAX {
            circuit.nodes.remove(one_index);
        }

        circuit.nodes.insert(0, Node::Constant(F::ONE));

        let shift_index = |node_index: usize| {
            if node_index < one_index {
                node_index + 1
            } else if node_index == one_index {
                0
            } else {
                node_index
            }
        };

        // Shift the indices of the nodes, variables and constants accordingly
        circuit.nodes.iter_mut().for_each(|node| {
            if let Node::Add(a, b) | Node::Mul(a, b) = node {
                *a = shift_index(*a);
                *b = shift_index(*b);
            }
        });

        circuit.constants.iter_mut().for_each(|(_, i)| {
            *i = shift_index(*i);
        });

        circuit
            .variables
            .iter_mut()
            .for_each(|(_, i)| *i = shift_index(*i));

        circuit
    }

    // Computes the dimensions m and l
    // TODO THIS MUST BE REDONE, REQUIRES AN IN DEPTH ANALYSIS OF m AND l
    fn compute_dimensions(sol_vec_length: usize) -> (usize, usize) {
        let x = (sol_vec_length as f64).sqrt();
        let m = x.ceil() as usize;
        (m, m.next_power_of_two())
    }

    // Computes the code parameters n (block lengh) and t (number of column openings)
    // TODO MUST BE IMPLEMENTED
    fn reed_solomon_parameters(m: usize, k: usize, lambda: usize) -> (usize, usize) {
        let codeword_length = 8 * k;
        (
            codeword_length,
            calculate_t::<F>(
                lambda,
                (codeword_length - k + 1, codeword_length),
                codeword_length,
            )
            .unwrap(),
        )
    }

    fn generate_matrices(
        circuit: &ArithmeticCircuit<F>,
        num_cols: usize,
        index_map: &HashMap<usize, usize>,
    ) -> SparseMatrix<F> {
        let nodes = &circuit.nodes;

        let mut p_x = SparseMatrix::new(num_cols);
        let mut p_y = SparseMatrix::new(num_cols);
        let mut p_z = SparseMatrix::new(num_cols);
        let mut p_add = SparseMatrix::new(num_cols);

        // Adding the constraint output = 1
        let output = circuit.last();

        match &nodes[output] {
            Node::Add(l_node, r_node) => {
                p_x.push_empty_row();
                p_y.push_empty_row();
                p_z.push_empty_row();

                let mut row = vec![];

                if let Node::Constant(c) = nodes[*l_node] {
                    row.extend(vec![(c, 0), (F::ONE, *index_map.get(r_node).unwrap())]);
                } else if let Node::Constant(c) = nodes[*r_node] {
                    row.extend(vec![(F::ONE, *index_map.get(l_node).unwrap()), (c, 0)]);
                } else {
                    // Add(constant, constant) is prevented by the validity
                    // check, so the only remaining possibility is the case
                    // Add(non-constant, non-constant)
                    row.extend(vec![
                        (F::ONE, *index_map.get(l_node).unwrap()),
                        (F::ONE, *index_map.get(r_node).unwrap()),
                    ]);
                }
                row.push((-F::ONE, 0));
                p_add.push_row(row);
            }
            Node::Mul(l_node, r_node) => {
                p_add.push_empty_row();

                if let Node::Constant(c) = nodes[*l_node] {
                    p_x.push_row(vec![(c, 0)]);
                    p_y.push_row(vec![(F::ONE, *index_map.get(r_node).unwrap())]);
                } else if let Node::Constant(c) = nodes[*r_node] {
                    p_x.push_row(vec![(F::ONE, *index_map.get(l_node).unwrap())]);
                    p_y.push_row(vec![(c, 0)]);
                } else {
                    // Mul(constant, constant) is prevented by the validity
                    // check, so the only remaining possibility is the case
                    // Mul(non-constant, non-constant)
                    p_x.push_row(vec![(F::ONE, *index_map.get(l_node).unwrap())]);
                    p_y.push_row(vec![(F::ONE, *index_map.get(r_node).unwrap())]);
                }
                p_z.push_row(vec![(F::ONE, 0)]);
            }
            _ => panic!("The output node must be an addition or multiplication gate"),
        }

        nodes.iter().enumerate().skip(1).for_each(|(i, node)| {
            match node {
                Node::Variable(_) => {
                    p_x.push_empty_row();
                    p_y.push_empty_row();
                    p_z.push_empty_row();
                    p_add.push_empty_row();
                }
                Node::Add(l_node, r_node) => {
                    p_x.push_empty_row();
                    p_y.push_empty_row();
                    p_z.push_empty_row();

                    let mut row = vec![];

                    if let Node::Constant(c) = nodes[*l_node] {
                        row.extend(vec![(c, 0), (F::ONE, *index_map.get(r_node).unwrap())]);
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        row.extend(vec![(F::ONE, *index_map.get(l_node).unwrap()), (c, 0)]);
                    } else {
                        // Add(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Add(non-constant, non-constant)
                        row.extend(vec![
                            (F::ONE, *index_map.get(l_node).unwrap()),
                            (F::ONE, *index_map.get(r_node).unwrap()),
                        ]);
                    }
                    row.push((-F::ONE, *index_map.get(&i).unwrap()));
                    p_add.push_row(row);
                }
                Node::Mul(l_node, r_node) => {
                    p_add.push_empty_row();

                    if let Node::Constant(c) = nodes[*l_node] {
                        p_x.push_row(vec![(c, 0)]);
                        p_y.push_row(vec![(F::ONE, *index_map.get(r_node).unwrap())]);
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        p_x.push_row(vec![(F::ONE, *index_map.get(l_node).unwrap())]);
                        p_y.push_row(vec![(c, 0)]);
                    } else {
                        // Mul(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Mul(non-constant, non-constant)
                        p_x.push_row(vec![(F::ONE, *index_map.get(l_node).unwrap())]);
                        p_y.push_row(vec![(F::ONE, *index_map.get(r_node).unwrap())]);
                    }
                    p_z.push_row(vec![(F::ONE, *index_map.get(&i).unwrap())]);
                }
                _ => {}
            }
        });

        // Padding matrices from 1 + n_i + s rows to m * k
        let padding = num_cols - p_x.num_rows();
        p_x.push_empty_rows(padding);
        p_y.push_empty_rows(padding);
        p_z.push_empty_rows(padding);
        p_add.push_empty_rows(padding);

        // Constructing
        //      [   |   -P_x    ]
        //      [ I |   -P_y    ]
        // A =  [   |   -P_z    ]
        //      [---------------]
        //      [ 0 |   P_add   ]
        let upper_right = -p_x.v_stack(p_y).v_stack(p_z);
        let upper = SparseMatrix::identity(3 * num_cols).h_stack(&upper_right);
        let lower = SparseMatrix::zero(num_cols, 3 * num_cols).h_stack(&p_add);
        upper.v_stack(lower)
    }

    pub fn prove(
        &self,
        var_assignment: Vec<(usize, F)>,
        sponge: &mut impl CryptographicSponge,
    ) -> LigeroProof<F> {
        // TODO initialise sponge, absorb maybe x, y, z

        // TODO: FS more generally, especially absorptions

        // TODO: Feed u into the Sponge

        let sol: Vec<F> = self.circuit.evaluation_trace(var_assignment, self.output_node).into_iter().map(|n|
            n.expect("Uninitialised variable. Make sure the circuit only contains nodes upon which the final output truly depends")
        ).collect();

        // Solution and multiplication IO vectors (w, x, y and z in the notation
        // of the paper). The first element of w is an extra 1 used to handle
        // constants in this more general version
        let mut x = vec![];
        let mut y = vec![];
        let mut z = vec![];
        let mut w = vec![];

        sol.iter()
            .zip(self.circuit.nodes.iter())
            .enumerate()
            .filter(|(i, (_, node))| !matches!(node, Node::Constant(_)) || *i == 0)
            .for_each(|(_, (val, node))| {
                w.push(*val);

                if let Node::Mul(left, right) = node {
                    x.push(sol[*left]);
                    y.push(sol[*right]);
                    z.push(*val);
                } else {
                    x.push(F::ZERO);
                    y.push(F::ZERO);
                    z.push(F::ZERO);
                }
            });

        x.resize(self.m * self.k, F::ZERO);
        y.resize(self.m * self.k, F::ZERO);
        z.resize(self.m * self.k, F::ZERO);
        w.resize(self.m * self.k, F::ZERO);

        let preenc_x = self.as_matrix(x);
        let preenc_y = self.as_matrix(y);
        let preenc_z = self.as_matrix(z);
        let preenc_w = self.as_matrix(w);

        let preenc_u = DenseMatrix::new(vec![preenc_x, preenc_y, preenc_z, preenc_w].concat());

        // TODO check if the coefficient vector r needs to be distinct for each
        // sub-protocol

        let u_polynomial_coeffs: Vec<Vec<F>> = preenc_u
            .clone()
            .rows
            .into_iter()
            .map(|row| self.reed_solomon_interpolate(row))
            .collect();

        let u: DenseMatrix<F> = DenseMatrix::new(
            u_polynomial_coeffs
                .iter()
                .map(|row| self.reed_solomon_evaluate(row.clone()))
                .collect(),
        );

        let u_polys: Vec<DensePolynomial<F>> = u_polynomial_coeffs
            .into_iter()
            .map(|row| DensePolynomial::from_coefficients_vec(row))
            .collect();

        sponge.absorb(&u.rows.concat());

        let interleaved_proof = self.prove_interleaved(&preenc_u, sponge);

        let linear_constraints_proof = self.prove_linear_constraints(&u_polys, sponge);

        let mut u_xyz_polys = u_polys;
        u_xyz_polys.truncate(3 * self.m);

        let quadratic_constraints_proof = self.prove_quadratic_constraints(u_xyz_polys, sponge);

        LigeroProof {
            u,
            interleaved_proof,
            linear_constraints_proof,
            quadratic_constraints_proof,
        }
    }

    pub fn verify(&self, proof: LigeroProof<F>, sponge: &mut impl CryptographicSponge) -> bool {
        let LigeroProof {
            u,
            interleaved_proof,
            linear_constraints_proof,
            quadratic_constraints_proof,
        } = proof;

        sponge.absorb(&u.rows.concat());

        self.verify_interleaved(interleaved_proof, &u, sponge)
            && self.verify_linear(linear_constraints_proof, &u, sponge)
            && self.verify_quadratic_constraints(quadratic_constraints_proof, &u, sponge)
    }

    fn prove_interleaved(
        &self,
        u_preenc: &DenseMatrix<F>,
        sponge: &mut impl CryptographicSponge,
    ) -> Vec<F> {
        let r_interleaved: Vec<F> = sponge.squeeze_field_elements(4 * self.m);
        u_preenc.row_mul(&r_interleaved)
    }

    fn verify_interleaved(
        &self,
        interleaved_proof: Vec<F>,
        u: &DenseMatrix<F>,
        sponge: &mut impl CryptographicSponge,
    ) -> bool {
        let r_interleaved: Vec<F> = sponge.squeeze_field_elements(4 * self.m);
        let w = self.reed_solomon(interleaved_proof);

        let queried_columns = get_distinct_indices_from_prng(self.n, self.t);

        // Testing w = r^T * U at a few random positions
        queried_columns.into_iter().all(|col|
            // The right hand side is the scalar pdocut of r^T and the col-th column of U
            w[col] == r_interleaved.iter().enumerate().map(|(i, r)| *r * u.rows[i][col]).sum())
    }

    // Implements the proving part of Test-Linear-Constraints in the case b = 0,
    // which is the only relevant one for Ligero
    fn prove_linear_constraints(
        &self,
        u_polys: &Vec<DensePolynomial<F>>,
        sponge: &mut impl CryptographicSponge,
    ) -> DensePolynomial<F> {
        let r_linear: Vec<F> = sponge.squeeze_field_elements(4 * self.m * self.k);
        let r_a = self.a.row_mul(&r_linear);
        let r_a_rows = r_a.chunks_exact(self.k).map(|row| row.to_vec());

        // Constructing r_i of degree < k
        let r_polys: Vec<DensePolynomial<F>> = r_a_rows
            .map(|row| self.small_domain.ifft(&row))
            .map(DensePolynomial::from_coefficients_vec)
            .collect();

        r_polys
            .iter()
            .zip(u_polys.iter())
            .map(|(r, p)| r * p)
            .reduce(|acc, p| acc + p)
            .unwrap()
    }

    fn verify_linear(
        &self,
        linear_proof: DensePolynomial<F>,
        u: &DenseMatrix<F>,
        sponge: &mut impl CryptographicSponge,
    ) -> bool {
        let r_linear: Vec<F> = sponge.squeeze_field_elements(4 * self.m * self.k);
        let r_a = self.a.row_mul(&r_linear);
        let r_a_rows = r_a.chunks_exact(self.k).map(|row| row.to_vec());

        let r_polys: Vec<DensePolynomial<F>> = r_a_rows
            .map(|row| self.small_domain.ifft(&row))
            .map(DensePolynomial::from_coefficients_vec)
            .collect();

        if linear_proof.degree() >= 2 * self.k - 1 {
            return false;
        }

        let mut q_coeffs = linear_proof.coeffs.clone();
        q_coeffs.resize(2 * self.k, F::ZERO);
        let intermediate_evals = self.intermediate_domain.fft(&q_coeffs);

        // Cofactor of the intermediate domain inside the large domain,
        let cofactor = self.n / (2 * self.k);

        // Checking sum_{c = 0}^{l - 1} q(zeta_c) = sum_{i, j} r_ic * b_ic
        if intermediate_evals.iter().step_by(2).sum::<F>() != F::ZERO {
            return false;
        }

        let queried_columns: HashSet<usize> =
            HashSet::from_iter(get_distinct_indices_from_prng(self.n, self.t).into_iter());

        let mut q_evals = queried_columns.into_iter().map(|j| {
            let point = self.large_domain.element(j);
            let eval = if j % cofactor == 0 {
                intermediate_evals[j / cofactor]
            } else {
                linear_proof.evaluate(&point)
            };
            (j, point, eval)
        });

        // sum_i^m r_i(eta_j) * U_{i, j} = q(eta_j)
        q_evals.all(|(j, point, eval)| {
            r_polys
                .iter()
                .zip(u.rows.iter())
                .map(|(r, u_row)| r.evaluate(&point) * u_row[j])
                .sum::<F>()
                == eval
        })
    }

    fn prove_quadratic_constraints(
        &self,
        u_xyz_polys: Vec<DensePolynomial<F>>,
        sponge: &mut impl CryptographicSponge,
    ) -> DensePolynomial<F> {
        let r_quadratic: Vec<F> = sponge.squeeze_field_elements(self.m);

        let (p_x, u_yz) = u_xyz_polys.split_at(self.m);
        let (p_y, p_z) = u_yz.split_at(self.m);

        izip!(p_x.iter(), p_y.iter(), p_z.iter(), r_quadratic.iter())
            .map(|(p_x, p_y, p_z, r)| &(&(p_x * p_y) - p_z) * *r)
            .reduce(|acc, p| acc + p)
            .unwrap()
    }

    fn verify_quadratic_constraints(
        &self,
        quadratic_proof: DensePolynomial<F>,
        u: &DenseMatrix<F>,
        sponge: &mut impl CryptographicSponge,
    ) -> bool {
        let r_quadratic: Vec<F> = sponge.squeeze_field_elements(self.m);

        // q(v) = sum_{i = 1}^{3m} r_i * (p_i_x(v) * p_i_y(v) - p_i_z(v))
        if quadratic_proof.degree() >= 2 * self.k - 1 {
            return false;
        }

        let mut p_0_coeffs = quadratic_proof.coeffs.clone();
        p_0_coeffs.resize(2 * self.k, F::ZERO);
        let intermediate_evals = self.intermediate_domain.fft(&p_0_coeffs);

        // Checking p_0(zeta_c) for each 0 <= c < k
        // Note that zeta_c is the 2*c-th element of the intermediate domain
        if (0..self.k).any(|c| intermediate_evals[2 * c] != F::ZERO) {
            return false;
        }

        // Cofactor of the intermediate domain inside the large domain,
        let cofactor = self.n / (2 * self.k);

        let queried_columns = get_distinct_indices_from_prng(self.n, self.t);

        queried_columns.into_iter().all(|col| {
            // Computing the left-hand side p_0(large_domain[j])
            let lhs = if col % cofactor == 0 {
                // In this case, the evaluation point is in the intermediate
                // domain and hence we already have its value
                intermediate_evals[col / cofactor]
            } else {
                quadratic_proof.evaluate(&self.large_domain.element(col))
            };

            // Computing the right-hand side
            let rhs: F = r_quadratic
                .iter()
                .enumerate()
                .map(|(i, r_i)| {
                    //     U_{i, j}^x       U_{i, j}^x                U_{i, j}^x
                    *r_i * (u.rows[i][col] * u.rows[i + self.m][col] - u.rows[i + 2 * self.m][col])
                })
                .sum();

            lhs == rhs
        })
    }

    fn reed_solomon_interpolate(&self, msg: Vec<F>) -> Vec<F> {
        let mut msg = msg;
        msg.resize(self.k, F::ZERO);
        self.small_domain.ifft(&msg)
    }

    fn reed_solomon_evaluate(&self, msg: Vec<F>) -> Vec<F> {
        let mut msg = msg;
        msg.resize(self.n, F::ZERO);
        self.large_domain.fft(&msg)
    }

    fn reed_solomon(&self, msg: Vec<F>) -> Vec<F> {
        self.reed_solomon_evaluate(self.reed_solomon_interpolate(msg))
    }

    #[inline]
    fn as_matrix(&self, vec: Vec<F>) -> Vec<Vec<F>> {
        vec.chunks_exact(self.k).map(|row| row.to_vec()).collect()
    }
}
