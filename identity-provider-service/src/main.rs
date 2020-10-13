use std::{collections::BTreeMap, fs, fs::OpenOptions, io::prelude::*, path::PathBuf, sync::Arc};

use crypto_common::{Versioned, VERSION_0};
use curve_arithmetic::*;
use id::{
    ffi::AttributeKind,
    identity_provider::{sign_identity_object, validate_request as ip_validate_request},
    types::*,
};
use log::info;
use pairing::bls12_381::{Bls12, G1};
use serde::Deserialize;
use serde_json::{from_str, from_value, to_string, Value};
use structopt::StructOpt;
use uuid::Uuid;
use warp::{
    http::{Response, StatusCode},
    Filter,
};

type ExampleCurve = G1;
type ExamplePairing = Bls12;
type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

/// Holds the query parameters expected by the service.
/// * state: contains the JSON serialized and URL encoded identity request
///   object.
#[derive(Deserialize)]
struct Input {
    state: String,
}

/// Structure used to receive the correct command line arguments by using
/// StructOpt.
#[derive(Debug, StructOpt)]
struct IdentityProviderServiceConfiguration {
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context_file: PathBuf,
    #[structopt(
        long = "identity-provider",
        help = "File with the identity provider as JSON."
    )]
    identity_provider_file: PathBuf,
    #[structopt(
        long = "anonymity-revokers",
        help = "File with the list of anonymity revokers as JSON."
    )]
    anonymity_revokers_file: PathBuf,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = IdentityProviderServiceConfiguration::from_args();

    info!("Reading the provided IP, AR and global context configurations.");
    let ip_data_contents =
        fs::read_to_string(opt.identity_provider_file).expect("Unable to read ip data file.");
    let ar_info_contents =
        fs::read_to_string(opt.anonymity_revokers_file).expect("Unable to read ar info file.");
    let global_context_contents = fs::read_to_string(opt.global_context_file)
        .expect("Unable to read global context info file.");

    let ip_data: Arc<IpData<ExamplePairing>> = Arc::new(
        from_str(&ip_data_contents).expect("File did not contain a valid IpData object as JSON."),
    );
    let ar_info: Arc<ArInfos<ExampleCurve>> = Arc::new(
        from_str(&ar_info_contents).expect("File did not contain a valid ArInfos object as JSON"),
    );
    let global_context: Arc<GlobalContext<ExampleCurve>> = Arc::new(
        from_str(&global_context_contents)
            .expect("File did not contain a valid GlobalContext object as JSON"),
    );
    info!("Configurations have been loaded successfully.");

    let identity_route = warp::path("api")
        .and(warp::path("identity"))
        .and(warp::path::end())
        .and(warp::get())
        .and(warp::query().map(move |input: Input| {
            let request_id = Uuid::new_v4();
            info!("flowId={}, message=\"Received request\"", request_id);
            let result = validate_and_return_identity_object(
                &input.state,
                Arc::clone(&ip_data),
                Arc::clone(&ar_info),
                Arc::clone(&global_context),
            );
            info!(
                "flowId={}, message=\"Completed processing request\"",
                request_id
            );
            result
        }));

    info!("Booting up HTTP server. Listening on port 8100.");
    warp::serve(identity_route).run(([0, 0, 0, 0], 8100)).await;
}

/// Validates the received request and if valid returns a signed identity
/// object.
fn validate_and_return_identity_object(
    state: &str,
    ip_data: Arc<IpData<ExamplePairing>>,
    ar_info: Arc<ArInfos<ExampleCurve>>,
    global_context: Arc<GlobalContext<ExampleCurve>>,
) -> std::result::Result<warp::http::Response<String>, warp::http::Error> {
    let request = match deserialize_request(state) {
        Ok(request) => request,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(format!("Error during deserialization: {}", e))
        }
    };

    let context = IPContext {
        ip_info:        &ip_data.public_ip_info,
        ars_infos:      &ar_info.anonymity_revokers,
        global_context: &global_context,
    };

    // This is hardcoded for the proof-of-concept.
    let now = YearMonth::now();
    let valid_to_next_year = YearMonth {
        year:  now.year + 1,
        month: now.month,
    };

    let alist = ExampleAttributeList {
        valid_to:     valid_to_next_year,
        created_at:   now,
        alist:        BTreeMap::new(),
        max_accounts: 200,
        _phantom:     Default::default(),
    };

    match ip_validate_request(&request, context) {
        Ok(validation_result) => validation_result,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(format!(
                    "The request could not be successfully validated by the identity provider: {}",
                    e
                ))
        }
    };

    let signature = match sign_identity_object(
        &request,
        &ip_data.public_ip_info,
        &alist,
        &ip_data.ip_secret_key,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!("It was not possible to sign the request: {}", e))
        }
    };

    match save_revocation_record(&request) {
        Ok(_saved) => (),
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e)
        }
    };

    let id = IdentityObject {
        pre_identity_object: request,
        alist,
        signature,
    };
    let versioned_id = Versioned::new(VERSION_0, id);
    Response::builder().body(
        to_string(&versioned_id)
            .expect("JSON serialization of the identity object should not fail."),
    )
}

/// Deserialize the received request. Give a proper error message if it was not
/// possible, or if incorrect version of the request was received.
fn deserialize_request(
    request: &str,
) -> std::result::Result<PreIdentityObject<Bls12, ExampleCurve>, String> {
    let v: Value = match from_str(request) {
        Ok(v) => v,
        Err(_) => return Err("Could not deserialize the received JSON.".to_string()),
    };

    let pre_id_object = match v.get("idObjectRequest") {
        Some(id_object) => id_object,
        None => return Err("The received JSON is missing an 'idObjectRequest' entry.".to_string()),
    };

    let request = from_value(pre_id_object.clone());
    let request: Versioned<PreIdentityObject<Bls12, ExampleCurve>> = match request {
        Ok(request) => request,
        Err(e) => {
            return Err(format!(
                "An error was encountered during deserialization: {}",
                e
            ))
        }
    };

    if request.version != VERSION_0 {
        Err(format!(
            "The received request version number is unsupported: [version={}]",
            &request.version
        ))
    } else {
        Ok(request.value)
    }
}

/// Creates and saves the revocation record to the file system (which should be
/// a database, but for the proof-of-concept we use the file system).
fn save_revocation_record(
    pre_identity_object: &PreIdentityObject<Bls12, ExampleCurve>,
) -> std::result::Result<bool, String> {
    let ar_record = AnonymityRevocationRecord {
        id_cred_pub: pre_identity_object.id_cred_pub,
        ar_data:     pre_identity_object.ip_ar_data.clone(),
    };

    let serialized_ar_record = to_string(&ar_record).unwrap();

    let mut file = match OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("revocation_record_storage.data")
    {
        Ok(file) => file,
        Err(e) => {
            return Err(format!(
                "Failed accessing anonymization revocation record file: {}",
                e
            ))
        }
    };

    match writeln!(file, "{}", serialized_ar_record) {
        Ok(_result) => Ok(true),
        Err(e) => Err(format!(
            "Failed writing anonymization revocation record to file: {}",
            e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_successful_validation_and_response() {
        // Given
        let request = include_str!("../data/valid_request.json");
        let ip_data_contents = include_str!("../data/identity_provider.json");
        let ar_info_contents = include_str!("../data/anonymity_revokers.json");
        let global_context_contents = include_str!("../data/global.json");

        let ip_data: Arc<IpData<ExamplePairing>> = Arc::new(
            from_str(&ip_data_contents)
                .expect("File did not contain a valid IpData object as JSON."),
        );
        let ar_info: Arc<ArInfos<ExampleCurve>> = Arc::new(
            from_str(&ar_info_contents)
                .expect("File did not contain a valid ArInfos object as JSON"),
        );
        let global_context: Arc<GlobalContext<ExampleCurve>> = Arc::new(
            from_str(&global_context_contents)
                .expect("File did not contain a valid GlobalContext object as JSON"),
        );

        // When
        let response = validate_and_return_identity_object(
            &request.to_string(),
            Arc::clone(&ip_data),
            Arc::clone(&ar_info),
            Arc::clone(&global_context),
        );

        // Then (we return a JSON serialized IdentityObject that we verify by
        // deserializing, and a revocation file was written that can also be
        // deserialized)
        let _deserialized_identity_object: Versioned<
            IdentityObject<ExamplePairing, ExampleCurve, AttributeKind>,
        > = from_str(response.unwrap().body()).unwrap();
        let revocation_record = fs::read_to_string("revocation_record_storage.data").unwrap();
        let _revocation_record: AnonymityRevocationRecord<ExampleCurve> =
            from_str(&revocation_record).unwrap();

        // Cleanup the generated revocation_record_storage.data file to make the test
        // idempotent.
        fs::remove_file("revocation_record_storage.data").unwrap();
    }

    #[test]
    fn test_verify_failed_validation() {
        // Given
        let request = include_str!("../data/fail_validation_request.json");
        let ip_data_contents = include_str!("../data/identity_provider.json");
        let ar_info_contents = include_str!("../data/anonymity_revokers.json");
        let global_context_contents = include_str!("../data/global.json");

        let ip_data: Arc<IpData<ExamplePairing>> = Arc::new(
            from_str(&ip_data_contents)
                .expect("File did not contain a valid IpData object as JSON."),
        );
        let ar_info: Arc<ArInfos<ExampleCurve>> = Arc::new(
            from_str(&ar_info_contents)
                .expect("File did not contain a valid ArInfos object as JSON"),
        );
        let global_context: Arc<GlobalContext<ExampleCurve>> = Arc::new(
            from_str(&global_context_contents)
                .expect("File did not contain a valid GlobalContext object as JSON"),
        );

        // When
        let response = validate_and_return_identity_object(
            &request.to_string(),
            Arc::clone(&ip_data),
            Arc::clone(&ar_info),
            Arc::clone(&global_context),
        );

        // Then (the zero knowledge proofs could not be verified, so we fail)
        assert!(response
            .unwrap()
            .body()
            .contains("The request could not be successfully validated by the identity provider"));
    }
}
