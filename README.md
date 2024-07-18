
# Ligero SNARK for arithmetic circuits

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
