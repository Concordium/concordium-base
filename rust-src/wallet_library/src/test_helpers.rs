use concordium_base::{
    common::Versioned,
    id::{
        constants::{self, AttributeKind},
        types::{ArIdentity, ArInfo, GlobalContext, IdentityObjectV1, IpInfo},
    },
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn base_path() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("resources") }

pub fn read_ip_info() -> IpInfo<constants::IpPairing> {
    let base_path = base_path();
    let contents = fs::read_to_string(base_path.join("ip_info.json"))
        .expect("Should have been able to read the file");
    let ip_info_versioned: Versioned<IpInfo<constants::IpPairing>> =
        serde_json::from_str(contents.as_str()).unwrap();
    ip_info_versioned.value
}

pub fn read_global() -> GlobalContext<constants::ArCurve> {
    let base_path = base_path();
    let global_contents = fs::read_to_string(base_path.join("global.json"))
        .expect("Should have been able to read the file");
    let global_versioned: Versioned<GlobalContext<constants::ArCurve>> =
        serde_json::from_str(&global_contents).unwrap();
    global_versioned.value
}

pub fn read_ars_infos() -> BTreeMap<ArIdentity, ArInfo<constants::ArCurve>> {
    let base_path = base_path();
    let ar_info_contents = fs::read_to_string(base_path.join("ars_infos.json"))
        .expect("Should have been able to read the file");
    let ar_info_versioned: Versioned<BTreeMap<ArIdentity, ArInfo<constants::ArCurve>>> =
        serde_json::from_str(&ar_info_contents).unwrap();
    ar_info_versioned.value
}

pub fn read_identity_object(
) -> IdentityObjectV1<constants::IpPairing, constants::ArCurve, AttributeKind> {
    let base_path = base_path();
    let identity_object_contents = fs::read_to_string(base_path.join("identity-object.json"))
        .expect("Should have been able to read the file");
    let identity_object_versioned: Versioned<
        IdentityObjectV1<constants::IpPairing, constants::ArCurve, AttributeKind>,
    > = serde_json::from_str(&identity_object_contents).unwrap();
    identity_object_versioned.value
}
