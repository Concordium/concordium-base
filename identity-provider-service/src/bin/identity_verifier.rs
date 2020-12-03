use log::info;
use reqwest::header::LOCATION;
use std::{collections::BTreeMap, fs};
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

    // TODO Embed into binary.
    let attribute_form = fs::read_to_string("html/attribute_form.html")
        .expect("Unable to read attribute form HTML template file.");

    let database_root = std::path::Path::new("database").to_path_buf();
    fs::create_dir_all(database_root.join("attributes"))
        .expect("Unable to create attributes database directory.");

    // The path for serving the attribute form to the caller. The HTML form has a
    // hidden field containing the id_cred_pub so that the session is preserved
    // across the flow.
    let identity_verifier =
        warp::get()
            .and(warp::path!("api" / "verify" / String))
            .map(move |id_cred_pub: String| {
                info!(
                    "Received request to present attribute form for {}",
                    id_cred_pub
                );
                let id_cred_pub_attribute_form =
                    str::replace(attribute_form.as_str(), "$id_cred_pub$", &id_cred_pub);
                Response::builder()
                    .header(CONTENT_TYPE, "text/html")
                    .body(id_cred_pub_attribute_form)
            });

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
                    info!(
                        "Saving verified attributes and forwarding user back to identity provider."
                    );
                    let id_cred_pub = input.get("id_cred_pub").unwrap().clone();
                    input.remove("id_cred_pub");

                    let file = match std::fs::File::create(
                        root_clone.join("attributes").join(&id_cred_pub),
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
            let attributes =
                match fs::read_to_string(database_root.join("attributes").join(id_cred_pub)) {
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
        identity_verifier
            .or(submit_verification_attributes)
            .or(read_attributes),
    )
    .run(([0, 0, 0, 0], opt.port))
    .await;
}
