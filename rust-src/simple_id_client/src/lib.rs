use id::{ffi::*, types::*};
use pairing::bls12_381::Bls12;

use chrono::NaiveDateTime;

use serde_json::{to_string_pretty, to_writer_pretty, Map, Value};

use curve_arithmetic::curve_arithmetic::*;

use serde::{de::DeserializeOwned, Serialize as SerdeSerialize};

use std::{
    fs::File,
    io::{self, BufReader, Error, ErrorKind},
    path::Path,
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

/// Show fields of the type of fields of the given attribute list.
pub fn show_attribute_format(variant: u16) -> &'static str {
    match variant {
        0 => "[ExpiryDate, MaxAccount, Age]",
        1 => "[ExpiryDate, MaxAccount, Age, Citizenship, Business]",
        _ => unimplemented!("Only two formats of attribute lists supported."),
    }
}

pub fn show_attribute(variant: u16, idx: AttributeIndex, att: &ExampleAttribute) -> String {
    let idx: usize = idx.into();
    format!("{}: {}", ATTRIBUTE_LISTS[variant as usize][idx], att)
}

pub fn parse_expiry_date(input: &str) -> io::Result<u64> {
    let mut input = input.to_owned();
    input.push_str(" 23:59:59");
    let dt = NaiveDateTime::parse_from_str(&input, "%d %B %Y %H:%M:%S")
        .map_err(|x| Error::new(ErrorKind::Other, x.to_string()))?;
    Ok(dt.timestamp() as u64)
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

static ALIST_BASIC_PERSON: &[&str] = &[
    "maxAccount",
    "creationTime",
    "birthYear",
    "residenceCountryCode",
];

static ALIST_ACCREDITED_INVESTOR: &[&str] = &[
    "maxAccount",
    "creationTime",
    "residenceCountryCode",
    "assetsOwnedLB",
];

static ALIST_DRIVER: &[&str] = &[
    "maxAccount",
    "creationTime",
    "birthYear",
    "residenceCountryCode",
    "drivingLicenseCountryCode",
    "drivingLicenseIssueDate",
    "drivingLicenseExpiry",
    "drivingLicenseCategories",
];

static ALIST_BASIC_COMPANY: &[&str] = &[
    "maxAccount",
    "creationTime",
    "registrationCountryCode",
    "isEUVAT",
    "VATNumber",
];

static ALIST_BASIC_VEHICLE: &[&str] = &[
    "maxAccount",
    "creationTime",
    "brandId",
    "registrationCountryCode",
    "vehicleClass",
    "numPassengerSeats",
    "modelYear",
    "productionYear",
    "modelId",
    "engineType",
    "engineSize",
    "VIN",
];

static ALIST_BASIC_IOT: &[&str] = &[
    "maxAccount",
    "creationTime",
    "deviceType",
    "deviceManufacturer",
    "deviceSerial",
    "deviceSpecific1",
    "deviceSpecific2",
    "deviceSpecific3",
];

pub static ATTRIBUTE_LISTS: &[&[&str]] = &[
    ALIST_BASIC_PERSON,
    ALIST_ACCREDITED_INVESTOR,
    ALIST_DRIVER,
    ALIST_BASIC_COMPANY,
    ALIST_BASIC_VEHICLE,
    ALIST_BASIC_IOT,
];

// index of the attribute in the list, if such a thing exists
pub fn attribute_index(variant: u16, s: &str) -> Option<u16> {
    let variant = variant as usize;
    if variant < ATTRIBUTE_LISTS.len() {
        let i = ATTRIBUTE_LISTS[variant].iter().position(|x| *x == s)?;
        Some(i as u16)
    } else {
        None
    }
}

pub fn alist_to_json(alist: &ExampleAttributeList) -> Value {
    let mut mp = Map::with_capacity(2);
    mp.insert("variant".to_owned(), Value::from(alist.variant.to_string()));
    mp.insert(
        "expiryDate".to_owned(),
        Value::from(alist.expiry.to_string()),
    );
    if (alist.variant as usize) < ATTRIBUTE_LISTS.len()
        && alist.alist.len() == ATTRIBUTE_LISTS[alist.variant as usize].len()
    {
        let keys = ATTRIBUTE_LISTS[alist.variant as usize];
        for (&i, v) in alist.alist.iter() {
            let i: usize = i.into();
            if i < keys.len() {
                mp.insert(keys[i].to_owned(), Value::from(v.to_string()));
            } else {
                return Value::Null;
            }
        }
        Value::Object(mp)
    } else {
        Value::Null
    }
}
