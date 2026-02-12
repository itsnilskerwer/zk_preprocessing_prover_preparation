Work in progress: Not production-ready.

# Processing RDF for Noir ZK in Rust: Prepare Prover.toml (Noir inputs)

Load inputs: signature, verifying key, merkle root over dataset.
Note: Merkle root is currently hardcoded and has to be pasted into main().

Root is converted to bytes, to conduct a signature verification (sanity check - can be removed).

Output:

- root = "0x..." -> Noir pub Field
- pub_key_x = [0x.., 0x.., ...] -> Noir [u8; 32]
- pub_key_y = [0x.., 0x.., ...] -> Noir [u8; 32]
- signature = [0x.., 0x.., ...] -> Noir [u8; 64]
- leaves = ["0x...", "0x...", ...] -> Noir [Field; 4]
 Note: Leaves are hardcoded and currently have to be pasted into main() as well.

TODO: Refactor to make root private input

# How to run

```rust
cargo run
````
