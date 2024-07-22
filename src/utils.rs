use ark_ff::PrimeField;

#[inline]
pub(crate) fn scalar_product<F: PrimeField>(a: &Vec<F>, b: &Vec<F>) -> F {
    a.iter().zip(b.iter()).map(|(a, b)| *a * *b).sum()
}
