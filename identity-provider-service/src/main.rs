use std::{convert::Infallible, fs, fs::OpenOptions, io::prelude::*, path::PathBuf, sync::Arc};

use crypto_common::{base16_encode_string, Versioned, VERSION_0};
use curve_arithmetic::*;
use id::{
    ffi::AttributeKind,
    identity_provider::{sign_identity_object, validate_request as ip_validate_request},
    types::*,
};
use log::info;
use pairing::bls12_381::{Bls12, G1};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{from_str, from_value, to_string, Value};
use structopt::StructOpt;
use warp::{
    http::{Response, StatusCode},
    hyper::header::{CONTENT_TYPE, LOCATION},
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

    // Create the 'database' directories for storing IdentityObjects and
    // AnonymityRevocationRecords.
    fs::create_dir_all("database/revocation").expect("Unable to create revocation directory.");
    fs::create_dir_all("database/identity").expect("Unable to create identity directory");
    info!("Configurations have been loaded successfully.");

    let retrieve_identity = warp::get()
        .and(warp::path("api"))
        .and(warp::path("identity"))
        .and(warp::path!(String).map(|id_cred_pub| {
            info!("Queried for receiving identity: {}", id_cred_pub);
            match fs::read_to_string(format!("database/identity/{}", id_cred_pub)) {
                Ok(identity_object) => {
                    info!("Identity object found");
                    Response::builder()
                        .header(CONTENT_TYPE, "application/json")
                        .body(identity_object)
                }
                Err(_e) => {
                    info!("Identity object does not exist");
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body("The identity is not available.".to_string())
                }
            }
        }));

    let create_identity = warp::path("api")
        .and(warp::path("identity"))
        .and(warp::path::end())
        .and(warp::get())
        .and(warp::query().map(move |input: Input| {
            let validated_pre_identity_object = validate_pre_identity_object(
                &input.state,
                Arc::clone(&ip_data),
                Arc::clone(&ar_info),
                Arc::clone(&global_context),
            );
            return (validated_pre_identity_object, Arc::clone(&ip_data));
        }))
        .and_then(create_signed_identity_object);

    info!("Booting up HTTP server. Listening on port 8100.");
    warp::serve(create_identity.or(retrieve_identity))
        .run(([0, 0, 0, 0], 8100))
        .await;
}

/// Asks the identity verifier to verify the person and return the associated
/// attribute list. The attribute list is used to create the identity object
/// that is then signed and saved. If successful a re-direct to the URL where
/// the identity object is available is returned.
async fn create_signed_identity_object(
    (request, ip_data): (
        Result<PreIdentityObject<Bls12, ExampleCurve>, String>,
        Arc<IpData<ExamplePairing>>,
    ),
) -> Result<impl warp::Reply, Infallible> {
    let request = match request {
        Ok(request) => request,
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(format!("Failed validation of pre-identity-object: {}", e)))
        }
    };

    // Identity verification process between the identity provider and the identity
    // verifier. In this example the identity verifier is queried and will
    // always just return a static attribute list without doing any actual
    // verification of an identity.
    let client = Client::new();
    let attribute_list = match client.post("http://localhost:8101/api/verify").send().await {
        Ok(attribute_list) => match attribute_list.json().await {
            Ok(attribute_list) => attribute_list,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(format!(
                        "Unable to deserialize attribute list received from identity verifier: {}",
                        e
                    )))
            }
        },
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(format!(
                    "The identity verifier service is unavailable. Try again later: {}",
                    e
                )))
        }
    };

    // At this point the identity has been verified, and the identity provider constructs the
    // identity object and signs it. An anonymity revocation record and the identity object
    // are persisted, so that they can be retrieved when needed. The constructed response
    // contains a redirect to a webservice that returns the identity object constructed here.

    // This is hardcoded for the proof-of-concept.
    let now = YearMonth::now();
    let valid_to_next_year = YearMonth {
        year:  now.year + 1,
        month: now.month,
    };

    let alist = ExampleAttributeList {
        valid_to:     valid_to_next_year,
        created_at:   now,
        alist:        attribute_list,
        max_accounts: 200,
        _phantom:     Default::default(),
    };

    let signature = match sign_identity_object(
        &request,
        &ip_data.public_ip_info,
        &alist,
        &ip_data.ip_secret_key,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!(
                    "It was not possible to sign the identity object: {}",
                    e
                )))
        }
    };

    let base16_encoded_id_cred_pub = base16_encode_string(&request.id_cred_pub);

    match save_revocation_record(&request, base16_encoded_id_cred_pub.clone()) {
        Ok(_saved) => (),
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e))
        }
    };

    let id = IdentityObject {
        pre_identity_object: request,
        alist,
        signature,
    };

    let versioned_id = Versioned::new(VERSION_0, id);
    let serialized_versioned_id = to_string(&versioned_id).unwrap();

    // Store a record containing the created IdentityObject.
    match store_record(
        &serialized_versioned_id,
        base16_encoded_id_cred_pub.clone(),
        "identity".to_string(),
    ) {
        Ok(_saved) => (),
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e))
        }
    };

    return Ok(Response::builder()
        .header(
            LOCATION,
            format!(
                "/api/identity/{}",
                base16_encoded_id_cred_pub
            ),
        )
        .status(StatusCode::FOUND)
        .body("Redirecting to identity object.".to_string()));
}

/// Deserializes the received pre-identity-object and then validates it. The
/// output is the deserialized pre-identity-object to be used later.
fn validate_pre_identity_object(
    state: &str,
    ip_data: Arc<IpData<ExamplePairing>>,
    ar_info: Arc<ArInfos<ExampleCurve>>,
    global_context: Arc<GlobalContext<ExampleCurve>>,
) -> Result<PreIdentityObject<Bls12, ExampleCurve>, String> {
    let request = match deserialize_request(state) {
        Ok(request) => request,
        Err(e) => return Err(format!("{}", e)),
    };

    let context = IPContext {
        ip_info:        &ip_data.public_ip_info,
        ars_infos:      &ar_info.anonymity_revokers,
        global_context: &global_context,
    };

    return match ip_validate_request(&request, context) {
        Ok(_validation_result) => return Ok(request),
        Err(e) => Err(format!(
            "The request could not be successfully validated by the identity provider: {}",
            e
        )),
    };
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
    base16_id_cred_pub: String,
) -> std::result::Result<(), String> {
    let ar_record = AnonymityRevocationRecord {
        id_cred_pub: pre_identity_object.id_cred_pub,
        ar_data:     pre_identity_object.ip_ar_data.clone(),
    };

    let serialized_ar_record = to_string(&ar_record).unwrap();
    return store_record(
        &serialized_ar_record,
        base16_id_cred_pub,
        "revocation".to_string(),
    );
}

/// Writes record to the provided subdirectory under 'database/'. The filename
/// is set to id_cred_pub, which is expected to be the base16 serialized
/// id_cred_pub.
fn store_record(
    record: &String,
    id_cred_pub: String,
    directory: String,
) -> std::result::Result<(), String> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("database/{}/{}", directory, id_cred_pub))
    {
        Ok(file) => file,
        Err(e) => return Err(format!("Failed accessing {} file: {}", directory, e)),
    };

    match writeln!(file, "{}", record) {
        Ok(_result) => Ok(()),
        Err(e) => Err(format!("Failed writing {} to file: {}", directory, e)),
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
        let response = validate_pre_identity_object(
            &request.to_string(),
            Arc::clone(&ip_data),
            Arc::clone(&ar_info),
            Arc::clone(&global_context),
        );

        // Then
        assert!(response.is_ok());
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
        let response = validate_pre_identity_object(
            &request.to_string(),
            Arc::clone(&ip_data),
            Arc::clone(&ar_info),
            Arc::clone(&global_context),
        );

        // Then (the zero knowledge proofs could not be verified, so we fail)
        assert!(response.is_err());
    }
}
