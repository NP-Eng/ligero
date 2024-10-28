use ark_crypto_primitives::{
    crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{LeafParam, TwoToOneParam},
};
use ark_ff::PrimeField;
use ark_poly_commit::test_types::{
    FieldToBytesColHasher, LeafIdentityHasher, TestMerkleTreeParams,
};
use ark_std::rand::SeedableRng;
use blake2::Blake2s256;
use rand_chacha::ChaChaRng;

use super::LigeroMTParams;

pub struct LigeroMTTestParams<F: PrimeField> {
    leaf_hash_param: LeafParam<TestMerkleTreeParams>,
    two_to_one_hash_param: TwoToOneParam<TestMerkleTreeParams>,
    col_hash_params: <FieldToBytesColHasher<F, Blake2s256> as CRHScheme>::Parameters,
}

impl<F: PrimeField> LigeroMTTestParams<F> {
    pub fn new() -> Self {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        LigeroMTTestParams {
            leaf_hash_param: <LeafIdentityHasher as CRHScheme>::setup(&mut rng).unwrap(),
            two_to_one_hash_param: <Sha256 as TwoToOneCRHScheme>::setup(&mut rng).unwrap(),
            col_hash_params: <FieldToBytesColHasher<F, Blake2s256> as CRHScheme>::setup(&mut rng)
                .unwrap(),
        }
    }
}

impl<F: PrimeField> LigeroMTParams<TestMerkleTreeParams, FieldToBytesColHasher<F, Blake2s256>>
    for LigeroMTTestParams<F>
{
    fn leaf_hash_param(&self) -> &LeafParam<TestMerkleTreeParams> {
        &self.leaf_hash_param
    }
    fn two_to_one_hash_param(&self) -> &TwoToOneParam<TestMerkleTreeParams> {
        &self.two_to_one_hash_param
    }

    fn col_hash_params(&self) -> &<FieldToBytesColHasher<F, Blake2s256> as CRHScheme>::Parameters {
        &self.col_hash_params
    }
}
