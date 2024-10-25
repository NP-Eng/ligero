
# Ligero SNARK for arithmetic circuits

Protocol reference: section 4 of [Ligero: Lightweight Sublinear Arguments
Without a Trusted Setup](https://eprint.iacr.org/2022/1608.pdf). By Scott Ames, Carmit Hayzay Yuval Ishai and Muthuramakrishnan Venkitasubramaniam.

This is a Rust implementation of (the non-interactive, non-ZK version of) the Ligero SNARK for arithmetic circuits.

This repository is split into two crates: `arithmetic-circuits` and `ligero`. The former includes an interface for arithmetic circuits, as well as 
tools to parse arithmetic expressions and R1CS files into arithmetic circuits. The latter implements the Ligero proof system. For more details, see the 
respective README files in the subdirectories.

 > *Disclaimer*: This codebase is for demonstration purposes only and not ready for production use - neither from a performance nor a security perspective. 