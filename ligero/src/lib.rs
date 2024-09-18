pub mod ligero;
pub(crate) mod matrices;
pub(crate) mod utils;

pub const DEFAULT_SECURITY_LEVEL: usize = 128;
pub const CHACHA_SEED_BYTES: usize = 256 / 8;

#[macro_export]
macro_rules! TEST_DATA_PATH {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/circom/{}",)
    };
}
