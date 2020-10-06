use std::collections::BTreeMap;
use std::env;
use std::fs;

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
            let result = build_response(input, &ip_data_contents, &ar_info_contents);
            println!("Completed processing request");
            result
        }));

    println!("Booting up HTTP server. Listening on port 8100.");
    warp::serve(identity_route)
        .run(([0, 0, 0, 0], 8100))
        .await;
}

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

fn build_response(query_param: Input, ip_data_contents: &String, ar_info_contents: &String) -> std::result::Result<warp::http::Response<String>, warp::http::Error>  {
    let request = match deserialize_request(&query_param.state) {
        Ok(request) => request,
        Err(e) => return Response::builder().body(format!("The received request was invalid could not be de-serialized: {}", e))
    };

    // TODO: How to borrow reference without clone inside async / await
    let ip_data: IpData<ExamplePairing> = from_str(&ip_data_contents).expect("File did not contain a valid IpData object as JSON.");
    let ar_info: ArInfos<ExampleCurve> = from_str(&ar_info_contents).expect("File did not contain a valid ArInfos object as JSON");

    let global_context= GlobalContext::<G1>::generate();
    let context = IPContext {
        ip_info:        &ip_data.public_ip_info,
        ars_infos:      &ar_info.anonymity_revokers,
        global_context: &global_context
    };

    // This is hardcoded for the proof-of-concept.
    let alist = ExampleAttributeList {
        valid_to:       YearMonth::now(),
        created_at:     YearMonth::now(),
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

    let id = IdentityObject {
        pre_identity_object: request,
        alist,
        signature
    };

    Response::builder().body(to_string(&id).expect("JSON serialization of the identity object should not fail."))
}