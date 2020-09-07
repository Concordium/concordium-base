use crypto_common::to_bytes;

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("global_bytes.bin");

    let global = id::types::GlobalContext::<id::constants::ArCurve>::generate();
    std::fs::write(&dest_path, &to_bytes(&global)).expect("Could not write table to file.");
}
