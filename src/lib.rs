pub mod arithmetic_circuit;
pub mod expression;
pub mod ligero;
pub(crate) mod matrices;
pub mod reader;
pub(crate) mod utils;

pub const DEFAULT_SECURITY_LEVEL: usize = 128;

#[macro_export]
macro_rules! TEST_DATA_PATH {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/circom/{}",)
    };
}
