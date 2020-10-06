use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;

use curve_arithmetic::*;
use id::{
    ffi::AttributeKind,
    identity_provider::{sign_identity_object, validate_request as ip_validate_request},
    types::*,
};
use pairing::bls12_381::{Bls12, G1};
use serde::Deserialize;
use serde_json::{from_str, from_value, to_string, Value};
use warp::{
    Filter,
    http::Response
};

type ExampleCurve = G1;
type ExamplePairing = Bls12;
type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

#[derive(Deserialize)]
struct Input {
    state: String
}

#[tokio::main]
async fn main() {
    println!("Reading the provided IP and AR configurations.");
    let args: Vec<String> = env::args().collect();
    let ip_data_filename = &args[1];
    let ar_info_filename = &args[2];

    let ip_data_contents = fs::read_to_string(ip_data_filename).expect("Unable to read ip data file.");
    let ar_info_contents = fs::read_to_string(ar_info_filename).expect("Unable to read ar info file.");
    println!("Configurations have been loaded successfully.");

    let identity_route = warp::path("api")
        .and(warp::path("identity"))
        .and(warp::path::end())
        .and(warp::get())
        .and(warp::query().map(move |input: Input| {
            println!("Received request");
            let result = validate_and_return_identity_object(&input.state, &ip_data_contents, &ar_info_contents);
            println!("Completed processing request");
            result
        }));

    println!("Booting up HTTP server. Listening on port 8100.");
    warp::serve(identity_route)
        .run(([0, 0, 0, 0], 8100))
        .await;
}

/// Validates the received request and if valid returns a signed identity object.
fn validate_and_return_identity_object(state: &String, ip_data_contents: &String, ar_info_contents: &String) -> std::result::Result<warp::http::Response<String>, warp::http::Error>  {
    let request = match deserialize_request(state) {
        Ok(request) => request,
        Err(e) => return Response::builder().body(format!("The received request was invalid could not be de-serialized: {}", e))
    };

    // FIXME: Performance optimization - howto borrow references (without cloning) to the de-serialized types to avoid parsing for each request?
    let ip_data: IpData<ExamplePairing> = from_str(&ip_data_contents).expect("File did not contain a valid IpData object as JSON.");
    let ar_info: ArInfos<ExampleCurve> = from_str(&ar_info_contents).expect("File did not contain a valid ArInfos object as JSON");

    let global_context= GlobalContext::<G1>::generate();
    let context = IPContext {
        ip_info:        &ip_data.public_ip_info,
        ars_infos:      &ar_info.anonymity_revokers,
        global_context: &global_context
    };

    // This is hardcoded for the proof-of-concept.
    let now = YearMonth::now();
    let valid_to_next_year = YearMonth {
        year:   now.year + 1,
        month:  now.month
    };

    let alist = ExampleAttributeList {
        valid_to:       valid_to_next_year,
        created_at:     now,
        alist:          BTreeMap::new(),
        max_accounts:   200,
        _phantom:       Default::default()
    };

    match ip_validate_request(&request, context) {
        Ok(validation_result) => validation_result,
        Err(e) => return Response::builder().body(format!("The request could not be successfully validated by the identity provider: {}", e))
    };

    let signature = match sign_identity_object(&request, &ip_data.public_ip_info, &alist, &ip_data.ip_secret_key) {
        Ok(signature) => signature,
        Err(e) => return Response::builder().body(format!("It was not possible to sign the request: {}", e))
    };

    save_revocation_record(request);

    let id = IdentityObject {
        pre_identity_object: deserialize_request(&state).unwrap(),
        alist,
        signature
    };
    Response::builder().body(to_string(&id).expect("JSON serialization of the identity object should not fail."))
}

/// Deserialize the received request. Give a proper error message if it was not possible.
fn deserialize_request(request: &String) -> std::result::Result<PreIdentityObject<Bls12, ExampleCurve>, String> {
    let v: Value = match from_str(request) {
        Ok(v) => v,
        Err(_) => return Err("Could not deserialize the received JSON.".to_string()),
    };

    let pre_id_object = match v.get("idObjectRequest") {
        Some(id_object) => id_object,
        None => return Err("The received JSON is missing an 'idObjectRequest' entry.".to_string())
    };

    let request = from_value(pre_id_object.clone());
    let request: PreIdentityObject<Bls12, ExampleCurve> = match request {
        Ok(request) => request,
        Err(e) => return Err(format!("An error was encountered during deserialization: {}", e))
    };

    return Ok(request);
}

/// Creates and saves the revocation record to the file system (which should be a database, but
/// for the proof-of-concept we use the file system).
fn save_revocation_record(pre_identity_object: PreIdentityObject<Bls12, ExampleCurve>) {
    let ar_record = AnonymityRevocationRecord {
        id_cred_pub:    pre_identity_object.id_cred_pub,
        ar_data:        pre_identity_object.ip_ar_data
    };

    let mut serialized_ar_record = to_string(&ar_record).unwrap();
    serialized_ar_record.push_str("\n\n");

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("revocation_record_storage.data")
        .unwrap();
    writeln!(file, "{}", serialized_ar_record).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_successful_validation_and_response() {
        // Given
        let request = fs::read_to_string("data/valid_request.json").unwrap();
        let ip_data_contents = fs::read_to_string("data/identity_provider.json").unwrap();
        let ar_info_contents = fs::read_to_string("data/anonymity_revokers.json").unwrap();

        // When
        let response = validate_and_return_identity_object(&request, &ip_data_contents, &ar_info_contents);

        // Then (we return a JSON serialized IdentityObject that we verify by deserializing, and a revocation file was written that can also be deserialized)
        let _deserialized_identity_object: IdentityObject<ExamplePairing, ExampleCurve, AttributeKind> = from_str(response.unwrap().body()).unwrap();
        let revocation_record = fs::read_to_string("revocation_record_storage.data").unwrap();
        let revocation_record: AnonymityRevocationRecord<ExampleCurve> = from_str(&revocation_record).unwrap();
    }

    #[test]
    fn test_verify_failed_validation() {
        // Given
        let request = fs::read_to_string("data/fail_validation_request.json").unwrap();
        let ip_data_contents = fs::read_to_string("data/identity_provider.json").unwrap();
        let ar_info_contents = fs::read_to_string("data/anonymity_revokers.json").unwrap();

        // When
        let response = validate_and_return_identity_object(&request, &ip_data_contents, &ar_info_contents);

        // Then (the zero knowledge proofs could not be verified, so we fail)
        assert!(response.unwrap().body().contains("The request could not be successfully validated by the identity provider"));
    }
}