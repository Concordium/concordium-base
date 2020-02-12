# Building the libraries for mobile wallets on Android and iOS

## Common requirements
The cryptographic library is written in Rust, and therefore the Rust compiler and Cargo is required. These are often packaged with the package manager of your choice, but can also be obtained through https://rustup.rs/

The cargo build tool depends on git to obtain dependencies from crates.io.

Certain crates in the crypto library are foreign code requiring a C compiler to be available. A compiler such as GCC works.

## Android
