use ark_std::{
    cmp::min,
    collections::BTreeSet,
    rand::{Rng, SeedableRng},
};

use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::PrimeField;
use rand_chacha::ChaChaRng;

use crate::CHACHA_SEED_BYTES;

#[inline]
pub(crate) fn scalar_product<F: PrimeField>(a: &Vec<F>, b: &Vec<F>) -> F {
    a.iter().zip(b.iter()).map(|(a, b)| *a * *b).sum()
}

pub(crate) fn get_distinct_indices_from_sponge(
    n: usize,
    t: usize,
    sponge: &mut impl CryptographicSponge,
) -> Vec<usize> {
    let seed = sponge.squeeze_bytes(CHACHA_SEED_BYTES);
    let mut rng = ChaChaRng::from_seed(seed.try_into().unwrap());

    // Squeeze t elements, then removing duplicates. Crucially, this must be
    // done deterministically to ensure prover-verifier consistency.
    let mut selected = BTreeSet::new();

    // If we must select more than half the entries of n, it is instead more
    // efficient to randomly generate the complement set instead
    let to_select = min(t, n - t);

    while selected.len() < to_select {
        selected.insert(rng.gen_range(0..n));
    }

    if to_select == t {
        selected.into_iter().collect()
    } else {
        (0..n).filter(|i| !selected.contains(i)).collect()
    }
}
