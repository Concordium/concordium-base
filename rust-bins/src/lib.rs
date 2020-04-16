use id::{ffi::*, types::*};
use pairing::bls12_381::Bls12;

use serde_json::{to_string_pretty, to_writer_pretty};

use curve_arithmetic::curve_arithmetic::*;

use serde::{de::DeserializeOwned, Serialize as SerdeSerialize};

use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    str::FromStr,
};

pub type ExampleCurve = <Bls12 as Pairing>::G1;

pub type ExampleAttribute = AttributeKind;

pub type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

pub static GLOBAL_CONTEXT: &str = "database/global.json";
pub static IDENTITY_PROVIDERS: &str = "database/identity_providers.json";

pub fn read_global_context(filename: &str) -> Option<GlobalContext<ExampleCurve>> {
    read_json_from_file(filename).ok()
}

pub fn read_identity_providers() -> Option<Vec<IpInfo<Bls12, <Bls12 as Pairing>::G1>>> {
    read_json_from_file(IDENTITY_PROVIDERS).ok()
}

/// Parse YYYYMM as YearMonth
pub fn parse_yearmonth(input: &str) -> Option<YearMonth> {
    match YearMonth::from_str(input) {
        Ok(ym) => Some(ym),
        Err(_) => None,
    }
}

pub fn write_json_to_file<T: SerdeSerialize>(filepath: &str, v: &T) -> io::Result<()> {
    let path = Path::new(filepath);
    let file = File::create(&path)?;
    Ok(to_writer_pretty(file, v)?)
}

/// Output json to standard output.
pub fn output_json<T: SerdeSerialize>(v: &T) {
    println!("{}", to_string_pretty(v).unwrap());
}

pub fn read_json_from_file<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> io::Result<T>
where
    P: std::fmt::Debug, {
    let file = File::open(path)?;

    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}
