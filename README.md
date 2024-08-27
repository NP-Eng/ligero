
# Ligero SNARK for arithmetic circuits

Protocol reference: section 4 of [Ligero: Lightweight Sublinear Arguments
Without a Trusted Setup](https://eprint.iacr.org/2022/1608.pdf). By Scott Ames, Carmit Hayzay Yuval Ishai and Muthuramakrishnan Venkitasubramaniam.

This is a Rust implementation of the (non-ZK) Ligero SNARK for arithmetic circuits.

This repo also includes an interface for arithmetic circuits, as well as tools to parse arithmetic expressions and R1CS files into arithmetic circuits.

 > *Disclaimer*: This codebase is for demonstration purposes only and not ready for production use - neither from a performance nor a security perspective. 

## Arithmetic circuits

Arithmetic circuits are a way to represent arithmetic expressions as a sequence of operations. The operations are represented as nodes in a directed acyclic graph (DAG), where the edges represent the flow of data between the nodes. We represent arithmetic circuits as an array of `Constants`, `Variables`, and gates (`Add` and `Mul`). A gate has a left and right input, which are indices for the respective nodes in the array. In order to construct an arithmetic circuit, the user must instantiate an `ArithmeticCircuit` and mutate it via the public struct methods (e.g. `new_variable`, `add`, `mul`...), each of which returns the index of the new node in the array. For example, the arithmetic circuit `2*x + y` can be constructed as follows:

```rust
    let mut circuit = ArithmeticCircuit::new();
    let two = circuit.new_constant(2);
    let x = circuit.new_variable_with_label("x");
    let y = circuit.new_variable_with_label("y");
    let two_x = circuit.mul(two, x);
    let result = circuit.add(two_x, y);
```


## Arithmetic expressions

Since arithmetic circuits might be cumbersome to write by hand, we include tooling to generate them from arithmetic expressions. Expressions allow the user to write mathematical formulas in a more human-readable way (e.g., `a + b * c`), which can be converted into arithmetic circuits. For comparison, the same arithmetic circuit `2*x + y` can be constructed as follows:

```rust
    let x = Expression::variable("x");
    let y = Expression::variable("y");
    let result = 2 * x + y;
    let circuit = result.to_arithmetic_circuit();
```

## R1CS to arithmetic circuits

Our implementation also includes a method `from_constraint_system` that allows the user to convert a R1CS into an arithmetic circuit. The method takes as input a `ConstraintSystem` struct, which contains the matrices `A`, `B`, and `C` of the R1CS. A `ConstraintSystem` can be obtained from the circom generated `.r1cs` and `.wasm` files,via the `read_constraint_system` method.

#### Generating R1CS files 
In order to generate an `.r1cs` file from a `.circom` one (with name, say, `NAME`), use
```
    circom NAME.circom --r1cs
```

In order to generate a `.wasm` file from a `.circom` one, use
```
    circom NAME.circom --wasm
```
and take the `.wasm` file from within the newly created folder.
