use pairing::bls12_381::{Bls12, G1};

use crypto_common::*;
use crypto_common_derive::*;

use curve_arithmetic::curve_arithmetic::*;
use id::types::*;

use clap::{App, AppSettings, Arg};

use failure::Fallible;

// server imports
#[macro_use]
extern crate rouille;

type ExampleCurve = G1;

/// Public data on an identity provider together with metadata to access it.
/// FIXME: Refactor these datatypes eventually to reduce duplication.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>"
))]
pub struct IpInfoWithMetadata<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Off-chain metadata about the identity provider
    #[serde(rename = "metadata")]
    pub metadata: IpMetadata,
    #[serde(rename = "ipInfo")]
    pub public_ip_info: IpInfo<P, C>,
}

struct ServerState {
    /// Public information about identity providers.
    ips: Vec<IpInfoWithMetadata<Bls12, ExampleCurve>>,
    /// Global parameters needed for deployment of credentials.
    global_params: GlobalContext<ExampleCurve>,
}

fn respond_ips(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    // return an array to be consistent with future extensions
    rouille::Response::json(&s.ips)
}

fn respond_global(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    rouille::Response::json(&s.global_params)
}

pub fn main() {
    let app = App::new("Server exposing creation of identity objects and credentials")
        .version("0.36787944117")
        .author("Concordium")
        .setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("ip-infos")
                .short("I")
                .long("ip-infos")
                .default_value("identity-providers-with-metadata.json")
                .value_name("FILE")
                .help("File with public information on the identity providers."),
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
        .value_of("ip-infos")
        .unwrap_or("identity-providers-with-metadata.json");

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
    let ips = {
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

    let ss = ServerState { ips, global_params };

    rouille::start_server(address, move |request| {
        router!(request,
                // get public identity provider info
                (GET) (/global) => { respond_global(request, &ss) },
                // get public identity provider info
                (GET) (/ip_info) => { respond_ips(request, &ss) },
                _ => rouille::Response::empty_404()
        )
    });
}
