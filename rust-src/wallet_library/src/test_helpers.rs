use concordium_base::{
    common::Versioned,
    id::{
        constants::{self},
        types::{ArIdentity, ArInfo, GlobalContext, IpInfo},
    },
};
use std::{collections::BTreeMap, fs, path::PathBuf};

#[cfg(test)]
fn base_path() -> String {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    let base_path = &d
        .as_path()
        .as_os_str()
        .to_str()
        .expect("Should be able to get base path.");
    base_path.to_string()
}

#[cfg(test)]
pub fn read_ip_info() -> IpInfo<constants::IpPairing> {
    let base_path = base_path();
    let contents = fs::read_to_string(format!("{}/{}", &base_path, "ip_info.json"))
        .expect("Should have been able to read the file");
    let ip_info_versioned: Versioned<IpInfo<constants::IpPairing>> =
        serde_json::from_str(contents.as_str()).unwrap();
    ip_info_versioned.value
}

#[cfg(test)]
pub fn read_global() -> GlobalContext<constants::ArCurve> {
    let base_path = base_path();
    let global_contents = fs::read_to_string(format!("{}/{}", &base_path, "global.json"))
        .expect("Should have been able to read the file");
    let global_versioned: Versioned<GlobalContext<constants::ArCurve>> =
        serde_json::from_str(&global_contents).unwrap();
    global_versioned.value
}

#[cfg(test)]
pub fn read_ars_infos() -> BTreeMap<ArIdentity, ArInfo<constants::ArCurve>> {
    let base_path = base_path();
    let ar_info_contents = fs::read_to_string(format!("{}/{}", &base_path, "ars_infos.json"))
        .expect("Should have been able to read the file");
    let ar_info_versioned: Versioned<BTreeMap<ArIdentity, ArInfo<constants::ArCurve>>> =
        serde_json::from_str(&ar_info_contents).unwrap();
    ar_info_versioned.value
}
