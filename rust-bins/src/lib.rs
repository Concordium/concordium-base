use crypto_common::*;
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
    read_exact_versioned_json_from_file(VERSION_GLOBAL_PARAMETERS, filename).ok()
}

pub fn read_identity_providers() -> Option<Vec<IpInfo<Bls12, <Bls12 as Pairing>::G1>>> {
    read_exact_versioned_vec_json_from_file(VERSION_IP_INFO_PUBLIC, IDENTITY_PROVIDERS).ok()
}

/// Parse YYYYMM as YearMonth
pub fn parse_yearmonth(input: &str) -> Option<YearMonth> { YearMonth::from_str(input).ok() }

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

/// Reads JSON from a file and check the stored version is equal the argument.
pub fn read_exact_versioned_json_from_file<P: AsRef<Path>, T: DeserializeOwned>(
    version: Version,
    path: P,
) -> io::Result<T>
where
    P: std::fmt::Debug, {
    let versioned: Versioned<T> = read_json_from_file(path)?;
    if versioned.version() == version {
        Ok(versioned.value())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid version in file",
        ))
    }
}

/// Reads JSON from a file and check the stored version is equal the argument.
pub fn read_exact_versioned_vec_json_from_file<P: AsRef<Path>, T: DeserializeOwned>(
    version: Version,
    path: P,
) -> io::Result<Vec<T>>
where
    P: std::fmt::Debug,
    T: Clone, {
    let mut versioned: Vec<Versioned<T>> = read_json_from_file(path)?;
    if versioned.iter().any(|v| v.version() != version) {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid version in vectored file",
        ))
    } else {
        let mut result = Vec::new();
        while let Some(t) = versioned.pop() {
            result.push(t.value());
        }
        result.reverse();
        Ok(result)
    }
}
