use arithmetic_circuits::arithmetic_circuit::{ArithmeticCircuit, Node};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
    sponge::{Absorb, CryptographicSponge},
};
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_poly_commit::linear_codes::{calculate_t, create_merkle_tree};
use ark_std::cfg_into_iter;
use itertools::{izip, Itertools};
use std::{borrow::Borrow, collections::HashMap, vec};

use crate::{
    matrices::{DenseMatrix, SparseMatrix},
    utils::{get_distinct_indices_from_prng, get_field_elements_from_prng, scalar_product_checked},
    CHACHA_SEED_BYTES,
};

#[cfg(test)]
mod tests;
mod types;

// TODO: optimise: when can one evaluate the interpolating polynomial at the
// queried points instead of computing the whole RS encoding in the three
// individual tests?

pub trait LigeroMTParams<C, H>
where
    C: Config + 'static,
    H: CRHScheme + 'static,
    C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
    H::Output: Into<C::Leaf>,
{
    /// Get the hash parameters for obtaining leaf digest from leaf value.
    fn leaf_hash_param(&self) -> &<C::LeafHash as CRHScheme>::Parameters;

    /// Get the parameters for hashing nodes in the merkle tree.
    fn two_to_one_hash_param(&self) -> &<C::TwoToOneHash as TwoToOneCRHScheme>::Parameters;

    /// Get the parameters for hashing a vector of values,
    /// representing a column of the coefficient matrix, into a leaf value.
    fn col_hash_params(&self) -> &H::Parameters;
}

pub struct LigeroCircuit<F: PrimeField> {
    /// Arithmetic circuit to be proved (formatted)
    circuit: ArithmeticCircuit<F>,

    // Index of constant one in the original circuit
    one_index: usize,

    // True if the constant one is present in the original circuit
    one_found: bool,

    /// Indices of nodes that contain the output to the circuit. Ligero proves
    /// that each of them take the value 1.
    outputs: Vec<usize>,

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

    /// `l` and `k` from the paper, which are made to coincide. This is the
    /// number of columns of the P matrices prior to encoding, as well as the
    /// size of the small FFT domain
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

pub struct LigeroProof<F: PrimeField, C: Config> {
    // Merkle commitment to the matrix
    // U = [U_x
    //      U_y
    //      U_z
    //      U_w]
    // purportedly encoding x || y || z || w as defined in the reference
    u_root: C::InnerDigest,

    // Proof for Test-Interleaved
    interleaved_proof: InterleavedProof<F, C>,

    // Proof for Test-Linear-Constraints
    linear_constraints_proof: LinearConstraintsProof<F, C>,

    // Proof for Test-Quadratic-Constraints
    quadratic_constraints_proof: QuadraticConstraintsProof<F, C>,
}

/// Proof for the Test-Interleaved protocol
pub struct InterleavedProof<F, C>
where
    F: PrimeField,
    C: Config,
{
    preenc_u_lc: Vec<F>,
    columns: Vec<Vec<F>>,
    paths: Vec<Path<C>>,
}

pub struct LinearConstraintsProof<F, C>
where
    F: PrimeField,
    C: Config,
{
    polynomial: DensePolynomial<F>,
    columns: Vec<Vec<F>>,
    paths: Vec<Path<C>>,
}

pub struct QuadraticConstraintsProof<F, C>
where
    F: PrimeField,
    C: Config,
{
    polynomial: DensePolynomial<F>,
    columns: Vec<Vec<F>>,
    paths: Vec<Path<C>>,
}

impl<F: PrimeField + Absorb> LigeroCircuit<F> {
    pub fn new(circuit: ArithmeticCircuit<F>, outputs: Vec<usize>, lambda: usize) -> Self {
        // TODO check validity, including
        //  - the fact that each gate depends only on previous gates
        //  - disallow add(const, const) or mul(const, const)

        // More efficient way to compute:
        //  1 + circuit.num_variables() + circuit.num_gates()
        // or, in the notation of the paper,
        //  1 + n_i + s = m * k
        // The first 1 comes from the constant 1, which is does not appear in
        // the less-general version in the article.

        // Get the index of the constant 1 in the circuit, if it exists
        let (one_index, one_found) = if let Some(&i) = circuit.constants.get(&F::ONE) {
            (i, true)
        } else {
            (1, false)
        };

        let mut circuit = circuit;
        if one_index != 0 {
            Self::insert_one(&mut circuit, one_index, one_found)
        }

        let sol_vec_length = 1 + circuit.num_nodes() - circuit.num_constants() + outputs.len();

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
        let outputs = outputs
            .iter()
            .map(|&i| Self::bump_index(one_index, one_found, i))
            .collect::<Vec<usize>>();

        let a = Self::generate_matrices(&circuit, &outputs, m * k, &index_map);

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
            outputs,
            one_index,
            one_found,
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

    fn bump_index(one_index: usize, one_found: bool, index: usize) -> usize {
        if one_found {
            if index < one_index {
                index + 1
            } else if index == one_index {
                0
            } else {
                index
            }
        } else {
            index + 1
        }
    }

    fn insert_one(circuit: &mut ArithmeticCircuit<F>, one_index: usize, one_found: bool) {
        // Move the constant 1 to the beginning of the circuit
        if one_found {
            circuit.nodes.remove(one_index);
        }

        circuit.nodes.insert(0, Node::Constant(F::ONE));

        // Shift the indices of the nodes, variables and constants accordingly
        circuit.nodes.iter_mut().for_each(|node| {
            if let Node::Add(a, b) | Node::Mul(a, b) = node {
                *a = Self::bump_index(one_index, one_found, *a);
                *b = Self::bump_index(one_index, one_found, *b);
            }
        });

        circuit
            .constants
            .iter_mut()
            .for_each(|(_, i)| *i = Self::bump_index(one_index, one_found, *i));

        circuit.constants.insert(F::ONE, 0);

        circuit
            .variables
            .iter_mut()
            .for_each(|(_, i)| *i = Self::bump_index(one_index, one_found, *i));
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
        outputs: &Vec<usize>,
        num_cols: usize,
        index_map: &HashMap<usize, usize>,
    ) -> SparseMatrix<F> {
        let nodes = &circuit.nodes;

        let mut p_x = SparseMatrix::new(num_cols);
        let mut p_y = SparseMatrix::new(num_cols);
        let mut p_z = SparseMatrix::new(num_cols);
        let mut p_add = SparseMatrix::new(num_cols);

        nodes.iter().enumerate().for_each(|(i, node)| {
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
                _ => {
                    if i == 0 {
                        p_x.push_empty_row();
                        p_y.push_empty_row();
                        p_z.push_empty_row();
                        p_add.push_empty_row();
                    }
                }
            }
        });

        // Adding the constraint o = 1 for each output node o
        for output_node in outputs {
            match &nodes[*output_node] {
                Node::Add(l_node, r_node) => {
                    p_x.push_empty_row();
                    p_y.push_empty_row();
                    p_z.push_empty_row();

                    let mut row = if let Node::Constant(c) = nodes[*l_node] {
                        vec![(c, 0), (F::ONE, *index_map.get(r_node).unwrap())]
                    } else if let Node::Constant(c) = nodes[*r_node] {
                        vec![(F::ONE, *index_map.get(l_node).unwrap()), (c, 0)]
                    } else {
                        // Add(constant, constant) is prevented by the validity
                        // check, so the only remaining possibility is the case
                        // Add(non-constant, non-constant)
                        vec![
                            (F::ONE, *index_map.get(l_node).unwrap()),
                            (F::ONE, *index_map.get(r_node).unwrap()),
                        ]
                    };

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
        }

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

    pub fn prove<C, H, P>(
        &self,
        var_assignment: Vec<(usize, F)>,
        mt_params: &P,
        sponge: &mut impl CryptographicSponge,
    ) -> LigeroProof<F, C>
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        let var_assignment = var_assignment
            .into_iter()
            .map(|(i, f)| (Self::bump_index(self.one_index, self.one_found, i), f))
            .collect();

        self.prove_inner(mt_params, var_assignment, sponge)
    }

    fn prove_inner<C, H, P>(
        &self,
        mt_params: &P,
        var_assignment: Vec<(usize, F)>,
        sponge: &mut impl CryptographicSponge,
    ) -> LigeroProof<F, C>
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        // TODO initialise sponge, absorb maybe x, y, z

        // TODO: FS more generally, especially absorptions

        // TODO: Feed u into the Sponge
        let sol: Vec<F> = self.circuit.evaluation_trace_multioutput(var_assignment, &self.outputs).into_iter().map(|n|
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

        // Merkle-committing to the matrix U
        let mut leaves: Vec<C::Leaf> = cfg_into_iter!(u.columns())
            .map(|col| {
                H::evaluate(P::col_hash_params(mt_params), col)
                    .unwrap()
                    .into()
            })
            .collect();

        let u_tree = create_merkle_tree::<C>(
            &mut leaves,
            mt_params.leaf_hash_param(),
            mt_params.two_to_one_hash_param(),
        )
        .unwrap();

        let u_root = u_tree.root();

        // Constructing polynomials from the rows of U for the linera and
        // quadratic proofs
        let u_polys: Vec<DensePolynomial<F>> = u_polynomial_coeffs
            .into_iter()
            .map(DensePolynomial::from_coefficients_vec)
            .collect();

        sponge.absorb(&u_root);

        let interleaved_proof = self.prove_interleaved(&preenc_u, &u, &u_tree, sponge);

        let linear_constraints_proof = self.prove_linear_constraints(&u_polys, &u, &u_tree, sponge);

        let mut u_xyz_polys = u_polys;
        u_xyz_polys.truncate(3 * self.m);

        let quadratic_constraints_proof =
            self.prove_quadratic_constraints(u_xyz_polys, &u, &u_tree, sponge);

        LigeroProof {
            u_root,
            interleaved_proof,
            linear_constraints_proof,
            quadratic_constraints_proof,
        }
    }

    pub fn prove_with_labels<C, H, P>(
        &self,
        var_assignment: Vec<(&str, F)>,
        mt_params: &P,
        sponge: &mut impl CryptographicSponge,
    ) -> LigeroProof<F, C>
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        self.prove_inner(
            mt_params,
            var_assignment
                .into_iter()
                .map(|(label, value)| {
                    (
                        *self
                            .circuit
                            .variables
                            .get(label)
                            .expect(&format!("Variable not found: {}", label)),
                        value,
                    )
                })
                .collect(),
            sponge,
        )
    }

    pub fn verify<C, H, P>(
        &self,
        proof: LigeroProof<F, C>,
        mt_params: &P,
        sponge: &mut impl CryptographicSponge,
    ) -> bool
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        let LigeroProof {
            u_root,
            interleaved_proof,
            linear_constraints_proof,
            quadratic_constraints_proof,
        } = proof;

        sponge.absorb(&u_root);

        self.verify_interleaved(&interleaved_proof, mt_params, &u_root, sponge)
            && self.verify_linear(&linear_constraints_proof, mt_params, &u_root, sponge)
            && self.verify_quadratic_constraints(
                &quadratic_constraints_proof,
                mt_params,
                &u_root,
                sponge,
            )
    }

    fn prove_interleaved<C: Config>(
        &self,
        preenc_u: &DenseMatrix<F>,
        u: &DenseMatrix<F>,
        u_tree: &MerkleTree<C>,
        sponge: &mut impl CryptographicSponge,
    ) -> InterleavedProof<F, C> {
        let seed_r = sponge.squeeze_bytes(CHACHA_SEED_BYTES);

        let r_interleaved: Vec<F> =
            get_field_elements_from_prng(4 * self.m, seed_r.try_into().unwrap());

        let preenc_u_lc = preenc_u.row_mul(&r_interleaved);

        sponge.absorb(&preenc_u_lc);

        let (columns, paths) = self.open_columns(u, u_tree, sponge);

        InterleavedProof {
            preenc_u_lc,
            columns,
            paths,
        }
    }

    fn verify_interleaved<C, H, P>(
        &self,
        interleaved_proof: &InterleavedProof<F, C>,
        mt_params: &P,
        u_root: &C::InnerDigest,
        sponge: &mut impl CryptographicSponge,
    ) -> bool
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        let InterleavedProof {
            preenc_u_lc,
            columns,
            paths,
        } = interleaved_proof;

        let seed = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let r_interleaved: Vec<F> =
            get_field_elements_from_prng(4 * self.m, seed.try_into().unwrap());

        sponge.absorb(&preenc_u_lc);

        if !self.verify_column_openings(columns, &paths, mt_params, u_root, sponge) {
            return false;
        }

        let w = self.reed_solomon(preenc_u_lc.clone());

        // Testing w = r^T * U at a few random positions
        paths.iter().zip(columns.iter()).all(|(path, col)|
            // The right hand side is the scalar pdocut of r^T and the col-th column of U
            w[path.leaf_index] == scalar_product_checked(&r_interleaved, col))
    }

    // Implements the proving part of Test-Linear-Constraints in the case b = 0,
    // which is the only relevant one for Ligero
    fn prove_linear_constraints<C: Config>(
        &self,
        u_polys: &Vec<DensePolynomial<F>>,
        u: &DenseMatrix<F>,
        u_tree: &MerkleTree<C>,
        sponge: &mut impl CryptographicSponge,
    ) -> LinearConstraintsProof<F, C> {
        let seed = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let r_linear: Vec<F> =
            get_field_elements_from_prng(4 * self.m * self.k, seed.try_into().unwrap());
        let r_a = self.a.row_mul(&r_linear);
        let r_a_rows = r_a.chunks_exact(self.k).map(|row| row.to_vec());

        // Constructing r_i of degree < k
        let r_polys: Vec<DensePolynomial<F>> = r_a_rows
            .map(|row| self.small_domain.ifft(&row))
            .map(DensePolynomial::from_coefficients_vec)
            .collect();

        let linear_constraint_poly = u_polys
            .iter()
            .zip(r_polys.iter())
            .map(|(r, p)| r * p)
            .reduce(|acc, p| acc + p)
            .unwrap();

        sponge.absorb(&linear_constraint_poly.coeffs);

        let (columns, paths) = self.open_columns(u, u_tree, sponge);

        LinearConstraintsProof {
            polynomial: linear_constraint_poly,
            columns,
            paths,
        }
    }

    fn verify_linear<C, H, P>(
        &self,
        linear_proof: &LinearConstraintsProof<F, C>,
        mt_params: &P,
        u_root: &C::InnerDigest,
        sponge: &mut impl CryptographicSponge,
    ) -> bool
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        let LinearConstraintsProof {
            polynomial: linear_proof,
            columns,
            paths,
        } = linear_proof;

        let seed = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let r_linear: Vec<F> =
            get_field_elements_from_prng(4 * self.m * self.k, seed.try_into().unwrap());

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

        sponge.absorb(&linear_proof.coeffs);

        if !self.verify_column_openings(columns, &paths, mt_params, u_root, sponge) {
            return false;
        }

        let q_evals = paths.into_iter().map(|path| {
            let j = path.leaf_index;
            let point = self.large_domain.element(j);
            let eval = if j % cofactor == 0 {
                intermediate_evals[j / cofactor]
            } else {
                linear_proof.evaluate(&point)
            };
            (j, eval)
        });

        // TODO this can become slower than individual evaluation at single points if t << n
        let r_polys_evals: Vec<Vec<F>> = r_polys
            .iter()
            .map(|poly| self.reed_solomon_evaluate(poly.coeffs.clone()))
            .collect();

        // sum_i^m r_i(eta_j) * U_{i, j} = q(eta_j)
        q_evals.zip(columns.iter()).all(|((j, eval), column)| {
            r_polys_evals
                .iter()
                .enumerate()
                .map(|(i, r_i_evals)| r_i_evals[j] * column[i])
                .sum::<F>()
                == eval
        })
    }

    fn prove_quadratic_constraints<C: Config>(
        &self,
        u_xyz_polys: Vec<DensePolynomial<F>>,
        u: &DenseMatrix<F>,
        u_tree: &MerkleTree<C>,
        sponge: &mut impl CryptographicSponge,
    ) -> QuadraticConstraintsProof<F, C> {
        let seed = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let r_quadratic: Vec<F> = get_field_elements_from_prng(self.m, seed.try_into().unwrap());

        let (p_x, u_yz) = u_xyz_polys.split_at(self.m);
        let (p_y, p_z) = u_yz.split_at(self.m);

        let quad_constraint_poly = izip!(p_x.iter(), p_y.iter(), p_z.iter(), r_quadratic.iter())
            .map(|(p_x, p_y, p_z, r)| &(&(p_x * p_y) - p_z) * *r)
            .reduce(|acc, p| acc + p)
            .unwrap();

        sponge.absorb(&quad_constraint_poly.coeffs);

        let (columns, paths) = self.open_columns(&u, &u_tree, sponge);

        QuadraticConstraintsProof {
            polynomial: quad_constraint_poly,
            columns,
            paths,
        }
    }

    fn verify_quadratic_constraints<C, H, P>(
        &self,
        quadratic_proof: &QuadraticConstraintsProof<F, C>,
        mt_params: &P,
        u_root: &C::InnerDigest,
        sponge: &mut impl CryptographicSponge,
    ) -> bool
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        let QuadraticConstraintsProof {
            polynomial: quadratic_proof,
            columns,
            paths,
        } = quadratic_proof;

        let seed = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let r_quadratic: Vec<F> = get_field_elements_from_prng(self.m, seed.try_into().unwrap());

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

        sponge.absorb(&quadratic_proof.coeffs);

        if !self.verify_column_openings(&columns, &paths, mt_params, u_root, sponge) {
            return false;
        }

        paths.into_iter().zip(columns.iter()).all(|(path, column)| {
            let col = path.leaf_index;

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
                    *r_i * (column[i] * column[i + self.m] - column[i + 2 * self.m])
                })
                .sum();

            lhs == rhs
        })
    }

    fn open_columns<C: Config>(
        &self,
        u: &DenseMatrix<F>,
        u_tree: &MerkleTree<C>,
        sponge: &mut impl CryptographicSponge,
    ) -> (Vec<Vec<F>>, Vec<Path<C>>) {
        let seed_cols = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let indices = get_distinct_indices_from_prng(self.n, self.t, seed_cols.try_into().unwrap());

        let columns = indices
            .iter()
            .map(|i| u.column(*i).clone())
            .collect::<Vec<_>>();

        let paths = indices
            .iter()
            .map(|i| u_tree.generate_proof(*i).unwrap())
            .collect_vec();

        (columns, paths)
    }

    fn verify_column_openings<P, C, H>(
        &self,
        columns: &Vec<Vec<F>>,
        paths: &Vec<Path<C>>,
        mt_params: &P,
        u_root: &C::InnerDigest,
        sponge: &mut impl CryptographicSponge,
    ) -> bool
    where
        C: Config + 'static,
        H: CRHScheme + 'static,
        C::Leaf: Sized + Clone + Default + Send + AsRef<C::Leaf>,
        H::Output: Into<C::Leaf>,
        P: LigeroMTParams<C, H>,
        Vec<F>: Borrow<<H as CRHScheme>::Input>,
    {
        let seed_cols = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
        let indices = get_distinct_indices_from_prng(self.n, self.t, seed_cols.try_into().unwrap());

        let col_hashes = columns
            .iter()
            .map(|col| {
                H::evaluate(mt_params.col_hash_params(), col.clone())
                    .unwrap()
                    .into()
            })
            .collect::<Vec<_>>();

        izip!(col_hashes.into_iter(), indices.into_iter(), paths).all(|(col_hash, i, path)| {
            path.leaf_index == i
                && path
                    .verify(
                        mt_params.leaf_hash_param(),
                        mt_params.two_to_one_hash_param(),
                        u_root,
                        col_hash,
                    )
                    .is_ok()
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
