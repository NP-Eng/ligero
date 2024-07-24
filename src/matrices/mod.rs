use std::ops::Neg;

use ark_ff::PrimeField;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SparseMatrix<F> {
    num_cols: usize,
    rows: Vec<Vec<(F, usize)>>,
}

impl<F: PrimeField> SparseMatrix<F> {
    pub(crate) fn new(num_cols: usize) -> Self {
        Self {
            num_cols,
            rows: Vec::new(),
        }
    }

    pub(crate) fn from_rows(rows: Vec<Vec<(F, usize)>>, num_cols: usize) -> Self {
        Self { num_cols, rows }
    }

    pub(crate) fn from_vec_of_slices(rows: &Vec<&[(F, usize)]>, num_cols: usize) -> Self {
        Self {
            num_cols,
            rows: rows
                .iter()
                .map(|row| row.iter().copied().collect())
                .collect(),
        }
    }

    pub(crate) fn num_cols(&self) -> usize {
        self.num_cols
    }

    pub(crate) fn num_rows(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn push_row(&mut self, row: Vec<(F, usize)>) {
        self.rows.push(row);
    }

    pub(crate) fn push_empty_row(&mut self) {
        self.rows.push(Vec::new());
    }

    pub(crate) fn identity(size: usize) -> Self {
        Self {
            num_cols: size,
            rows: (0..size).map(|i| vec![(F::one(), i)]).collect(),
        }
    }

    pub(crate) fn zero(num_rows: usize, num_cols: usize) -> Self {
        Self {
            num_cols,
            rows: vec![vec![]; num_rows],
        }
    }

    pub(crate) fn h_stack(mut self, other: &Self) -> Self {
        assert_eq!(
            self.num_rows(),
            other.num_rows(),
            "Row number mismatch in when stacking matrices horizontally: {} != {}",
            self.num_rows(),
            other.num_rows()
        );

        let h_shift = self.num_cols();

        for (own_row, other_row) in self.rows.iter_mut().zip(other.rows.iter()) {
            own_row.extend(other_row.iter().map(|(v, j)| (*v, j + h_shift)));
        }

        self
    }

    pub(crate) fn v_stack(mut self, other: Self) -> Self {
        assert_eq!(
            self.num_cols(),
            other.num_cols(),
            "Column number mismatch in when stacking matrices vertically: {} != {}",
            self.num_cols(),
            other.num_cols()
        );

        self.rows.extend(other.rows);
        self
    }

    pub(crate) fn row_mul(&self, row: &Vec<F>) -> Vec<F> {
        let mut result = vec![F::ZERO; self.num_cols];

        for (c, own_row) in row.iter().zip(self.rows.iter()) {
            for (value, col) in own_row {
                result[*col] += *c * value;
            }
        }

        result
    }
}

impl<F: PrimeField> Neg for SparseMatrix<F> {
    type Output = Self;

    fn neg(self) -> Self {
        SparseMatrix {
            num_cols: self.num_cols,
            rows: self
                .rows
                .into_iter()
                .map(|row| row.into_iter().map(|(v, j)| (-v, j)).collect())
                .collect(),
        }
    }
}

pub(crate) struct DenseMatrix<F> {
    pub(crate) rows: Vec<Vec<F>>,
}

impl<F: PrimeField> DenseMatrix<F> {
    pub(crate) fn new(rows: Vec<Vec<F>>) -> Self {
        Self { rows }
    }

    pub(crate) fn row_mul(&self, row: &Vec<F>) -> Vec<F> {
        let mut result = vec![F::ZERO; self.rows[0].len()];

        for (c, own_row) in row.iter().zip(self.rows.iter()) {
            result
                .iter_mut()
                .zip(own_row.iter())
                .for_each(|(res, own)| *res += *own * *c);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;

    #[test]
    fn test_mat_mul_dense() {
        let m = DenseMatrix::new(vec![
            vec![Fr::from(1u32), Fr::from(2u32), Fr::from(8u32)],
            vec![Fr::from(3u32), Fr::from(4u32), Fr::from(5u32)],
        ]);

        let v = vec![-Fr::from(5u32), Fr::from(17u32)];

        assert_eq!(
            m.row_mul(&v),
            vec![Fr::from(46u32), Fr::from(58u32), Fr::from(45u32)]
        );
    }

    #[test]
    fn test_mat_mul_sparse() {
        let mut m = SparseMatrix::new(3);
        m.push_row(vec![(Fr::from(1u32), 0), (Fr::from(8u32), 2)]);
        m.push_row(vec![(Fr::from(4u32), 1), (Fr::from(5u32), 2)]);

        let v = vec![-Fr::from(5u32), Fr::from(17u32)];

        assert_eq!(
            m.row_mul(&v),
            vec![-Fr::from(5u32), Fr::from(68u32), Fr::from(45u32)]
        );
    }
}
