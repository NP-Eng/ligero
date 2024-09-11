
# Ligero SNARK for arithmetic circuits

Protocol reference: section 4 of [Ligero: Lightweight Sublinear Arguments
Without a Trusted Setup](https://eprint.iacr.org/2022/1608.pdf). By Scott Ames, Carmit Hayzay Yuval Ishai and Muthuramakrishnan Venkitasubramaniam.

This is a Rust implementation of (the non-interactive, non-ZK version of) the Ligero SNARK for arithmetic circuits.

This repository also includes an interface for arithmetic circuits, as well as tools to parse arithmetic expressions and R1CS files into arithmetic circuits.

 > *Disclaimer*: This codebase is for demonstration purposes only and not ready for production use - neither from a performance nor a security perspective. 

## Arithmetic circuits

Arithmetic circuits are a way to represent polynomial expressions as a sequence of addition and multiplication operations, which we conceptualise as gates. These operations take the form of nodes in a directed acyclic graph, where the edges represent the flow of data between the nodes. In this implementation, gates have a fan-in of two (i.e. two inputs) and arbitrary fan-out (i.e. their output can be the output of arbitrarily many other gates).  We represent arithmetic circuits as an array of `Constants`, `Variables`, `Add` gates and `Mul` gates. Gates have a left and right input, which are indices for the respective nodes in the array. In order to directly construct an arithmetic circuit, the user must instantiate an empty `ArithmeticCircuit` struct and mutate it via its public methods (e.g. `new_variable`, `add`, `mul`), each of which returns the index of the new node in the array. For example, an  arithmetic circuit expressing the computation `2 * x + y` can be constructed as follows:

```rust
    let mut circuit = ArithmeticCircuit::new();
    let two = circuit.constant(F::from(2));
    let x = circuit.new_variable();
    let y = circuit.new_variable();
    let two_x = circuit.mul(two, x);
    let result = circuit.add(two_x, y);
```

Variables can also be given labels for easier value assignment and tracking:

```rust
    let x = circuit.new_variable_with_label("x");
    let y = circuit.new_variable_with_label("y");
```

We note that there is only one `Constant` node for each field element `v` appearing in the computation: subsequent calls to `circuit.constant(v)` will point to the same node and therefore can be transparently made without incuring unnecessary spatial costs.


## Arithmetic expressions

We also provide tooling to generate arithmetic circuits from user-friendly `Expression`s. The latter allow the programmer to write mathematical formulas in a more human-readable way (e.g., `a + b * c`) and can subsequently be converted into an `ArithmeticCircuit`. For comparison, an arithmetic circuit for the same computation `2 * x + y` can be constructed as follows:

```rust
    let x = Expression::variable("x");
    let y = Expression::variable("y");
    let result = 2 * x + y;
    let circuit = result.to_arithmetic_circuit();
```

In the case of expressions, variable labels are indispensable anchors to each individual variable after the expression is compiled into a circuit.

Due to Rust's borrow-checker, an expression needs to be cloned if it is used more than once in the same line. For instance, the following
```rust
    let expression = x * x + y;
```
will not compile, the correct syntax being:
```rust
    let expression = x.clone() * x + y;
```
We note that cloning expressions is very cheap, since they are implemented using the `Rc` struct. This and other pain points of expression sysntax may be ironed out in the future.

## R1CS to arithmetic circuits

Our implementation also includes the method `from_constraint_system`, which allows the user to convert an Arkworks `ConstraintSystem` (i.e., an R1CS) into an `ArithmeticCircuit`. The method takes as input a `ConstraintSystem` struct, which contains the R1CS matrices `A`, `B`, and `C`. A `ConstraintSystem` can be obtained from the circom generated `.r1cs` and `.wasm` files,via the `read_constraint_system` method.

## Generating R1CS files 
In order to generate an `.r1cs` file from a `.circom` one (with name, say, `NAME`), use
```
    circom NAME.circom --r1cs
```

In order to generate a `.wasm` file from a `.circom` one, use
```
    circom NAME.circom --wasm
```
and take the `.wasm` file from within the newly created folder.

## Ligero circuits
The central structure of the repository is the `LigeroCircuit`, which allows for proving and verification of `ArithmeticCircuits` using the aforementioned Ligero proof system.

```rust
    // Reading an R1CS computing a Poseidon hash of rate 3.
    let cs: ConstraintSystem<F> = read_constraint_system(
        "circom/poseidon/poseidon.r1cs",
        "circom/poseidon/poseidon_js/poseidon.wasm",
    );

    // Compiling into an ArithmeticCircuit and then a LigeroCircuit
    let (circuit, outputs) = ArithmeticCircuit::from_constraint_system(&cs);
    let ligero = LigeroCircuit::new(circuit, outputs, DEFAULT_SECURITY_LEVEL);

    // Loading a valid witness produced by circom
    let cs_witness: Vec<F> = serde_json::from_str::<Vec<String>>(
        &std::fs::read_to_string("circom/poseidon/witness.json").unwrap(),
    ).unwrap().iter().map(|s| F::from_str(s).unwrap()).collect();

    // Skipping the initial 1 in the R1CS witness
    let var_assignment = cs_witness.into_iter().enumerate().skip(1).collect_vec();

    // Proof system setup
    let mut sponge: PoseidonSponge<Fr> = test_sponge();
    let mt_params = LigeroMTTestParams::new();

    // Proving and verifying
    let proof = ligero.prove(var_assignment, &mt_params, &mut sponge.clone());
    assert!(ligero.verify(proof, &mt_params, &mut sponge));
```

A few caveats are in order:
- A `LigeroCircuit` is constructed from an `ArithmeticCircuit` by designating some of its nodes as outputs. The proof system convinces the verifier that the value of each of those outputs with the witness provided by the prover is equal to one.
- The proof system described in the reference paper is slightly expanded to naturally handle constants, which were not part of the original description.
- Each `LigeroCircuit` starts with a constant node of value `1`, as necessitated by the proof system. This is handled transparently whenever an `ArithmeticCircuit` is compiled into a `LigeroCircuit`.

## Benchmarks

Currently, we construct a very simple `ArithmeticCircuit` over the scalar field of BN254 for computing n Fibonacci steps with only addition gates. Note that the parameters (e.g. matrix dimensions) have not been optimized.

To run the benchmarks, use:
```
cargo bench
```

Sample results on a c5a.4xlarge AWS instance are shown in [benches/results.txt](benches/results.txt).