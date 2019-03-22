# crypto

Cryptographic infrastructure 

# How to Build Only Rust Part

move to rust-src dir, run

cargo build --release

This will build the following rust libraries

-VRF : libec_vrf_ed25519_sha256

-SHA-2: libsha_2

-Ed Signature: libeddsa_ed25519

# How to Build for Haskell

first build the Rust part as shown above. then run

stack build