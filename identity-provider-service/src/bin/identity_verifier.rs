use std::{collections::BTreeMap, fs, sync::RwLock};

use anyhow::Context;
use crypto_common::{base16_decode_string, Versioned};
use ed25519_dalek::Verifier;
use id::{constants::IpPairing, types::IpInfo};
use log::{error, info, warn};
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

/// A mockup of a database to store all the data.
/// In production this would be a real database, here we store everything as
/// files on disk and synchronize access to disk via a lock. Attributes are also
/// never deleted from the database.
#[derive(Clone)]
struct DB {
    /// Root directory where all the data is stored.
    /// The lock serves to guard all accesses to files in the directory.
    root: Arc<RwLock<std::path::PathBuf>>,
}

enum WriteAttributesError {
    InternalServer(String),
    FileExists,
}

impl DB {
    /// Create a new database.
    pub fn new(root: PathBuf) -> Self {
        fs::create_dir_all(root.join("attributes"))
            .expect("Unable to create attributes database directory.");
        Self {
            root: Arc::new(RwLock::new(root)),
        }
    }

    pub fn write_attributes(
        &self,
        id_cred_pub: &str,
        input: &BTreeMap<String, String>,
    ) -> Result<(), WriteAttributesError> {
        let attributes_dir = self
            .root
            .write()
            .expect("Cannot acquire lock, something is very wrong.");
        let attributes_file = attributes_dir.join(id_cred_pub);
        if std::path::Path::exists(&attributes_file) {
            return Err(WriteAttributesError::FileExists);
        }
        let file = std::fs::File::create(attributes_file)
            .map_err(|e| (WriteAttributesError::InternalServer(e.to_string())))?;
        serde_json::to_writer(file, input)
            .map_err(|e| WriteAttributesError::InternalServer(e.to_string()))
    }

    pub fn read_attributes(&self, id_cred_pub: &str) -> anyhow::Result<String> {
        // since we are writing to a location based on id_cred_pub we do a little sanity
        // checking that the path is a non-empty hex string, which
        // means it won't be used to write to silly locations.
        anyhow::ensure!(
            !id_cred_pub.is_empty() && hex::decode(id_cred_pub).is_ok(),
            "Invalid id_cred_pub format."
        );
        let attributes_dir = self
            .root
            .read()
            .expect("Cannot acquire read lock. Something is very wrong.");
        fs::read_to_string(attributes_dir.join(id_cred_pub)).context("Cannot read attributes file.")
    }
}

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
    let attribute_form_html = std::str::from_utf8(attribute_form.as_ref())
        .unwrap()
        .to_string();

    let ip_data_contents = fs::read_to_string(&opt.identity_provider_pub_file).unwrap();
    let versioned_ip_data: Versioned<IpInfo<IpPairing>> = from_str(&ip_data_contents).unwrap();
    let ip_data_arc = Arc::new(versioned_ip_data.value);

    let database_root = std::path::Path::new("database").to_path_buf();
    let db = DB::new(database_root);

    // The path for serving the attribute form to the caller. The HTML form has a
    // hidden field containing the id_cred_pub so that the session is preserved
    // across the flow.
    // WARNING: This is not secure and is only for demonstration purposes. The
    // id_cred_pub value is a fairly sensitive value that should not be passed
    // around insecurely.
    let identity_verifier = warp::get()
        .and(warp::path!("api" / "verify" / String / String))
        .map(move |id_cred_pub: String, signed_id_cred_pub: String| {
            info!(
                "Received request to present attribute form for {}",
                id_cred_pub
            );

            let mut id_cred_pub_attribute_form =
                str::replace(attribute_form_html.as_str(), "$id_cred_pub$", &id_cred_pub);
            id_cred_pub_attribute_form = str::replace(
                id_cred_pub_attribute_form.as_str(),
                "$id_cred_pub_signature$",
                &signed_id_cred_pub,
            );
            Response::builder()
                .header(CONTENT_TYPE, "text/html")
                .body(id_cred_pub_attribute_form)
        });

    // The path for submitting an attribute list. The attribute list is serialized
    // as JSON and saved to the file database. If successful, then forward the
    // user back to the identity provider.
    let db_get = db.clone();
    let id_provider_url = opt.id_provider_url.to_string();
    let submit_verification_attributes =
        warp::post()
            .and(warp::path!("api" / "submit"))
            .and(
                warp::body::form().map(move |mut input: BTreeMap<String, String>| {
                    info!(
                        "Saving verified attributes and forwarding user back to identity provider."
                    );
                    let id_cred_pub = input.get("id_cred_pub").unwrap().clone();
                    // since we are writing to a location based on id_cred_pub we do a little sanity
                    // checking that the path is a non-empty hex string, which
                    // means it won't be used to write to silly locations.
                    let id_cred_pub_bytes = match hex::decode(&id_cred_pub) {
                        Ok(bs) if !bs.is_empty() => bs,
                        _ => {
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body("Invalid format of id_cred_pub.".to_string());
                        }
                    };
                    input.remove("id_cred_pub");

                    let id_cred_pub_signature = input.get("id_cred_pub_signature").unwrap().clone();
                    input.remove("id_cred_pub_signature");

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
                        .verify(&id_cred_pub_bytes, &signature)
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

                    // The signature was valid, so attempt to save the received attributes to the
                    // file database. If the file with attributes already exists fail.
                    if let Err(e) = db.write_attributes(&id_cred_pub, &input) {
                        match e {
                            WriteAttributesError::InternalServer(msg) => {
                                error!("Could not store attributes: {}", msg);
                                return Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(msg);
                            }
                            WriteAttributesError::FileExists => {
                                warn!("Duplicate submission for id_cred_pub {}", id_cred_pub);
                                return Response::builder().status(StatusCode::BAD_REQUEST).body(
                                    "The received request for attributes for (id_cred_pub) is \
                                     duplicate."
                                        .to_string(),
                                );
                            }
                        }
                    }
                    let location = format!(
                        "{}{}{}",
                        id_provider_url, "api/identity/create/", id_cred_pub
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
        .map(move |id_cred_pub: String| {
            let attributes = match db_get.read_attributes(&id_cred_pub) {
                Ok(attributes) => attributes,
                Err(e) => {
                    warn!("Could not read attributes for {}: {}", id_cred_pub, e);
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(format!("Attributes for {} not found.", id_cred_pub));
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
