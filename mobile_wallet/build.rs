use concordium_base::common::to_bytes;

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("table_bytes.bin");

    let global = concordium_base::id::types::GlobalContext::<concordium_base::id::constants::ArCurve>::generate(String::from(
        "genesis_string",
    ));
    let m = 1 << 16;
    let table = concordium_base::elgamal::BabyStepGiantStep::new(
        global.encryption_in_exponent_generator(),
        m,
    );
    std::fs::write(dest_path, to_bytes(&table)).expect("Could not write table to file.");
}
