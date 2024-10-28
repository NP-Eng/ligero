 # Ligero circuits
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