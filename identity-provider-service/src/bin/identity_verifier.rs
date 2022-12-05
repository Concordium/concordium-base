use std::{collections::BTreeMap, fs};

use crypto_common::{base16_decode_string, Versioned};
use ed25519_dalek::Verifier;
use id::{constants::IpPairing, types::IpInfo};
use log::{error, info};
use reqwest::header::LOCATION;
use rust_embed::RustEmbed;
use serde_json::from_str;
use std::{path::PathBuf, sync::Arc};
use structopt::StructOpt;
use url::Url;
use warp::{
    http::{Response, StatusCode},
    hyper::header::CONTENT_TYPE,
    Filter,
};

#[derive(Debug, StructOpt)]
struct Config {
    #[structopt(
        long = "port",
        default_value = "8101",
        help = "Port on which the server will listen on.",
        env = "IDENTITY_VERIFIER_PORT"
    )]
    port: u16,
    #[structopt(
        long = "id-provider-url",
        default_value = "http://localhost:8100",
        help = "Base URL for the identity provider service.",
        env = "IDENTITY_PROVIDER_URL"
    )]
    id_provider_url: Url,
    #[structopt(
        long = "identity-provider-public",
        help = "File with the versioned public identity provider information as JSON.",
        default_value = "identity_provider.pub.json",
        env = "IDENTITY_PROVIDER_PUBLIC"
    )]
    identity_provider_pub_file: PathBuf,
}

#[derive(RustEmbed)]
#[folder = "html/"]
struct Asset;

/// A small binary that simulates an identity verifier that always verifies an
/// identity, and returns a verified attribute list.
#[tokio::main]
async fn main() {
    env_logger::init();

    let app = Config::clap()
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .global_setting(clap::AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let opt = Config::from_clap(&matches);

    let attribute_form = Asset::get("attribute_form.html").unwrap();
    let attribute_form_html = std::str::from_utf8(&attribute_form.data)
        .unwrap()
        .to_string();

    let ip_data_contents = fs::read_to_string(&opt.identity_provider_pub_file).unwrap();
    let versioned_ip_data: Versioned<IpInfo<IpPairing>> = from_str(&ip_data_contents).unwrap();
    let ip_data_arc = Arc::new(versioned_ip_data.value);

    let database_root = std::path::Path::new("database").to_path_buf();
    fs::create_dir_all(database_root.join("attributes"))
        .expect("Unable to create attributes database directory.");

    // The path for serving the attribute form to the caller. The HTML form has a
    // hidden field containing the id_cred_pub so that the session is preserved
    // across the flow.
    // WARNING: This is not secure and is only for demonstration purposes. The
    // id_cred_pub value is a fairly sensitive value that should not be passed
    // around insecurely.
    let identity_verifier = warp::get()
        .and(warp::path!("api" / "verify" / String / String / String))
        .map(
            move |endpoint_version: String,
                  id_cred_pub_hash: String,
                  signed_id_cred_pub_hash: String| {
                info!(
                    "Received request to present attribute form for {}",
                    id_cred_pub_hash
                );

                let mut id_cred_pub_attribute_form = str::replace(
                    attribute_form_html.as_str(),
                    "$id_cred_pub$",
                    &id_cred_pub_hash,
                );
                id_cred_pub_attribute_form = str::replace(
                    id_cred_pub_attribute_form.as_str(),
                    "$id_cred_pub_signature$",
                    &signed_id_cred_pub_hash,
                );
                id_cred_pub_attribute_form = str::replace(
                    id_cred_pub_attribute_form.as_str(),
                    "$endpoint_version$",
                    &endpoint_version,
                );
                Response::builder()
                    .header(CONTENT_TYPE, "text/html")
                    .body(id_cred_pub_attribute_form)
            },
        );

    // The path for submitting an attribute list. The attribute list is serialized
    // as JSON and saved to the file database. If successful, then forward the
    // user back to the identity provider.
    let root_clone = database_root.clone();
    let id_provider_url = opt.id_provider_url.to_string();
    let submit_verification_attributes =
        warp::post()
            .and(warp::path!("api" / "submit"))
            .and(
                warp::body::form().map(move |mut input: BTreeMap<String, String>| {
                    let id_cred_pub_hash = match input.get("id_cred_pub") {
                        Some(hash) => hash.clone(),
                        None => {
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body("id_cred_pub not present.".to_string());
                        }
                    };

                    let endpoint_version = match input.get("endpoint_version") {
                        Some(version) => version.clone(),
                        None => {
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body("endpoint_version not present.".to_string());
                        }
                    };
                    input.remove("endpoint_version");

                    if input.get("fail").is_some() {
                        let delay = match input.get("fail_delay") {
                            Some(d) => d,
                            None => {
                                return Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body("expiry not present.".to_string());
                            }
                        };
                        let location = format!(
                            "{}api/{}/identity/fail/{}?delay={}",
                            id_provider_url, endpoint_version, id_cred_pub_hash, delay
                        );
                        return Response::builder()
                            .header(LOCATION, location)
                            .status(StatusCode::FOUND)
                            .body("Ok".to_string());
                    }
                    input.remove("fail_delay");

                    info!(
                        "Saving verified attributes and forwarding user back to identity provider."
                    );

                    let id_cred_pub_hash_bytes = hex::decode(&id_cred_pub_hash).unwrap();
                    input.remove("id_cred_pub");

                    let id_cred_pub_signature = match input.get("id_cred_pub_signature") {
                        Some(sig) => sig.clone(),
                        None => {
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body("id_cred_pub_signature not present.".to_string());
                        }
                    };
                    input.remove("id_cred_pub_signature");

                    let identity_endpoint = if endpoint_version.eq("v0") {
                        "v0/identity"
                    } else if endpoint_version.eq("v1") {
                        "v1/identity"
                    } else {
                        return Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body("Invalid endpoint version.".to_string());
                    };

                    // Verify that the signature comes from the identity provider, otherwise reject
                    // the request. This prevents the submission of attributes for an
                    // id_cred_pub that has not been processed by the identity provider.
                    let signature: ed25519_dalek::Signature =
                        match base16_decode_string(&id_cred_pub_signature) {
                            Ok(signature) => signature,
                            Err(error) => {
                                error!("Received invalid signature: {}", error);
                                return Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body("Invalid format of the received signature.".to_string());
                            }
                        };

                    match ip_data_arc
                        .clone()
                        .ip_cdi_verify_key
                        .verify(&id_cred_pub_hash_bytes, &signature)
                    {
                        Ok(_) => info!("Signature validated."),
                        Err(error) => {
                            error!("Received invalid signature: {}", error.to_string());
                            return Response::builder().status(StatusCode::BAD_REQUEST).body(
                                "The received request (id_cred_pub) was not correctly signed by \
                                 the identity provider."
                                    .to_string(),
                            );
                        }
                    }

                    let expiry = match input.get("expiry") {
                        Some(i) => i.replace('-', ""),
                        None => {
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body("expiry not present.".to_string());
                        }
                    };
                    input.remove("expiry");

                    // Remove all attributes that are empty strings
                    input.retain(|_, v| !v.is_empty());

                    // The signature was valid, so save the received attributes to the file
                    // database.
                    let file = match std::fs::File::create(
                        root_clone.join("attributes").join(&id_cred_pub_hash),
                    ) {
                        Ok(file) => file,
                        Err(e) => {
                            return Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(e.to_string())
                        }
                    };
                    match serde_json::to_writer(file, &input) {
                        Ok(()) => (),
                        Err(e) => {
                            return Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(e.to_string())
                        }
                    };

                    let location = format!(
                        "{}api/{}/create/{}?expiry={}",
                        id_provider_url, identity_endpoint, id_cred_pub_hash, expiry
                    );
                    Response::builder()
                        .header(LOCATION, location)
                        .status(StatusCode::FOUND)
                        .body("Ok".to_string())
                }),
            );

    // The path for reading an already created attribute list. The identity provider
    // will access this endpoint when creating an identity.
    let read_attributes = warp::get()
        .and(warp::path!("api" / "verify" / "attributes" / String))
        .map(move |id_cred_pub_hash: String| {
            let attributes =
                match fs::read_to_string(database_root.join("attributes").join(id_cred_pub_hash)) {
                    Ok(attributes) => attributes,
                    Err(e) => {
                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(e.to_string())
                    }
                };
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(attributes)
        });

    info!(
        "Booting up identity verifier service. Listening on port {}.",
        opt.port
    );

    warp::serve(
        read_attributes
            .or(submit_verification_attributes)
            .or(identity_verifier),
    )
    .run(([0, 0, 0, 0], opt.port))
    .await;
}
