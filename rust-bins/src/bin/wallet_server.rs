use pairing::bls12_381::{Bls12, G1};

use curve_arithmetic::curve_arithmetic::*;
use id::{ffi::AttributeKind, identity_provider::verify_credentials, types::*};

use clap::{App, AppSettings, Arg};

use serde_json::{from_str, from_value, json, to_value, Value};

#[macro_use]
extern crate failure;
use failure::Fallible;

// server imports
#[macro_use]
extern crate rouille;

type ExampleCurve = G1;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

struct ServerState {
    /// Public and private information about the identity providers.
    /// This also contains information about anonymity revokers.
    ip_data: IpData<Bls12, ExampleCurve>,
    /// Global parameters needed for deployment of credentials.
    global_params: GlobalContext<ExampleCurve>,
}

// this needs to be in sync with ATTRIBUTE_NAMES
pub const DEFAULT_VALUES: [&str; 13] = [
    "John",
    "Doe",
    "1",
    "19800229",
    "DE",
    "DK",
    "1",
    "1234567890",
    "DK",
    "20200401",
    "20291231",
    "DK123456789",
    "DE987654321",
];

// Add data to the attribute list if needed. This is just to simulate the fact
// that not all attributes are needed.
fn dummy_alist() -> ExampleAttributeList {
    let created_at = YearMonth::now();
    let valid_to = YearMonth {
        year: created_at.year + 1,
        ..created_at
    }; // a year from now.
    let mut alist = std::collections::BTreeMap::new();
    // fill in the missing pieces with dummy values.
    for (i, &v) in DEFAULT_VALUES.iter().enumerate() {
        let idx = AttributeTag::from(i as u8);
        if alist.get(&idx).is_none() {
            let _ = alist.insert(idx, AttributeKind(v.to_string()));
        }
    }
    AttributeList {
        valid_to,
        created_at,
        max_accounts: 238,
        alist,
        _phantom: Default::default(),
    }
}

fn sign_id_object_aux(ip_data: &IpData<Bls12, ExampleCurve>, v: &str) -> Fallible<Value> {
    let v: Value = match from_str(v) {
        Ok(v) => v,
        Err(e) => bail!("Cannot decode input request: {}", e),
    };
    let id_obj_value = {
        match v.get("idObjectRequest") {
            Some(v) => v.clone(),
            None => bail!("Field 'idObjectRequest' not present but should be."),
        }
    };
    let request: PreIdentityObject<Bls12, ExampleCurve> = from_value(id_obj_value)?;

    // We create a dummy attribute list to simulate the workflow.
    // FIXME: This is temporary, of course, and should be replaced by business
    // logic.
    let alist = dummy_alist();
    let vf = verify_credentials(
        &request,
        &ip_data.public_ip_info,
        &alist,
        &ip_data.ip_secret_key,
    );
    match vf {
        Ok(signature) => {
            let id_object = IdentityObject {
                pre_identity_object: request,
                alist,
                signature,
            };
            Ok(to_value(&id_object)?)
        }
        Err(e) => bail!("Could not generate signature because {:?}.", e),
    }
}

fn respond_ips(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    // return an array to be consistent with future extensions
    let response = vec![json!({
        "metadata": s.ip_data.metadata,
        "ipInfo": s.ip_data.public_ip_info
    })];
    rouille::Response::json(&response)
}

fn respond_global(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    rouille::Response::json(&s.global_params)
}

fn sign_id_object(request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let param = match request.get_param("id_request") {
        Some(v) => v,
        None => {
            return rouille::log(&request, ::std::io::stderr(), || {
                rouille::Response::text("'id_request' parameter is mandatory.")
                    .with_status_code(400)
            })
        }
    };
    let response = sign_id_object_aux(&s.ip_data, &param);
    match response {
        Ok(v) => rouille::log(&request, ::std::io::stderr(), || {
            rouille::Response::json(&json!({ "identityObject": v }))
        }),
        Err(e) => rouille::log(&request, ::std::io::stderr(), || {
            rouille::Response::text(format!("{}", e)).with_status_code(400)
        }),
    }
}

pub fn main() {
    let app = App::new("Server exposing creation of identity objects and credentials")
        .version("0.36787944117")
        .author("Concordium")
        .setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("ip-data")
                .short("I")
                .long("ip-data")
                .default_value("identity-provider.json")
                .value_name("FILE")
                .help("File with public and private information on the identity provider."),
        )
        .arg(
            Arg::with_name("global")
                .short("G")
                .long("global")
                .default_value("global.json")
                .value_name("FILE")
                .help("File with global parameters."),
        )
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .default_value("localhost:8000")
                .value_name("HOST")
                .help("Address on which the server is listening."),
        );

    let matches = app.get_matches();

    let ips_file = matches
        .value_of("ip-data")
        .unwrap_or("identity-provider.json");

    let global_file = matches.value_of("global").unwrap_or("global.json");

    let address = matches.value_of("address").unwrap_or("localhost:8000");

    let file = match ::std::fs::File::open(ips_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "Could not open identity provider file because {}. Aborting.",
                e
            );
            return;
        }
    };

    let global_file = match ::std::fs::File::open(global_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Could not open global params file because {}. Aborting.", e);
            return;
        }
    };

    let reader = ::std::io::BufReader::new(file);
    let ip_data = {
        match serde_json::from_reader(reader) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Cannot read identity provider data due to {}. Aborting.", e);
                return;
            }
        }
    };

    let reader = ::std::io::BufReader::new(global_file);
    let global_params = {
        match serde_json::from_reader(reader) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Cannot read global parameters due to {}. Aborting.", e);
                return;
            }
        }
    };

    let ss = ServerState {
        ip_data,
        global_params,
    };

    rouille::start_server(address, move |request| {
        router!(request,
                // get public identity provider info
                (GET) (/global) => { respond_global(request, &ss) },
                // get public identity provider info
                (GET) (/ip_info) => { respond_ips(request, &ss) },
                // Respond with a signed identity object.
                (GET) (/request_id) => { sign_id_object(request, &ss) },
                _ => rouille::Response::empty_404()
        )
    });
}
