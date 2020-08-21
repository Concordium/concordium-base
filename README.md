# crypto

Cryptographic infrastructure 

# How to Build Only Rust Part

move to rust-src dir, run

cargo build --release

This will build the following rust libraries

-VRF : libecvrf

-SHA-2: libsha_2

-Ed Signature: libeddsa_ed25519

# How to Build for Haskell

stack build

This should build both rust and haskell code. 

For runtime linking (Depending on your OS) 
you may need to add rust-src/target/release/ to your library path.