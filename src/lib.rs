pub mod circuit;
pub mod reader;

#[macro_export]
macro_rules! TEST_DATA_PATH {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/circom/{}",)
    };
}
