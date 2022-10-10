# Use all kernel functions

This project exists purely to serve as an example of a contract which uses all
of the functions on our external contract API. This means we can build this
function and check it's wasm imports to get a description wasm API derived
mechanically from the Rust definition in `prims.rs`.

- Build the code, `cargo build --target wasm32-unknown-unknown`
- Covert the wasm to the textual representation, `wasm2wat somewhere/in/your/build/output/use-all-kernel-functions.wasm | less`
- Look at the list of imports towards the beginning of the printed wasm
