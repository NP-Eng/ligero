pub mod arithmetic_circuit;
pub mod ligero;
pub(crate) mod matrices;
pub mod reader;
pub(crate) mod utils;

// TODO Think of the correct relation between R1CS and circuit in terms of
// instance/witness, public/private inputs and constants
//
// R1CS: instance, witness
// Circuit: (alpha_1, ... alpha_n)
//
// Maybe    instance <-> circuit constants
//          witness <-> (alpha_1, ... alpha_n) (= circuit variables)

// TODO better use of unchecked methods

// TODO if only one constraint, no indicator is needed

// TODO (big) improve compiler to avoid massive blowup

// TODO code optimised version of scalar product

// TODO parallelisation

// TODO tests:
// - Various SparseMatrix tests
// - Cannot set non-variable to a value
// - When setting a variable twice, the last value is used
// - Initialisation?
// - Minimal computation graph, including variable handling
// - Wrap-around arithmetic
// - Fibonacci with 1 constant

#[macro_export]
macro_rules! TEST_DATA_PATH {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/circom/{}",)
    };
}
