use std::ops::Neg;

use ark_ff::PrimeField;

#[derive(Debug, Clone)]
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
