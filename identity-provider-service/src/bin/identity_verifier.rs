use std::{collections::BTreeMap, sync::Arc};

use id::{ffi::AttributeKind, types::*};
use log::info;
use serde_json::to_string;
use warp::{http::Response, hyper::header::CONTENT_TYPE, Filter};

/// A small binary that simulates an identity verifier that always verifies an
/// identity, and returns a verified attribute list.
#[tokio::main]
async fn main() {
    env_logger::init();

    let attribute_list = {
        let mut alist: BTreeMap<AttributeTag, AttributeKind> = BTreeMap::new();
        alist.insert(AttributeTag::from(0u8), AttributeKind("John".to_string()));
        alist.insert(AttributeTag::from(1u8), AttributeKind("Doe".to_string()));
        alist.insert(AttributeTag::from(2u8), AttributeKind("1".to_string()));
        alist.insert(
            AttributeTag::from(3u8),
            AttributeKind("19700101".to_string()),
        );
        alist.insert(AttributeTag::from(4u8), AttributeKind("DE".to_string()));
        alist.insert(AttributeTag::from(5u8), AttributeKind("DK".to_string()));
        alist.insert(AttributeTag::from(6u8), AttributeKind("1".to_string()));
        alist.insert(
            AttributeTag::from(7u8),
            AttributeKind("1234567890".to_string()),
        );
        alist.insert(AttributeTag::from(8u8), AttributeKind("DK".to_string()));
        alist.insert(
            AttributeTag::from(9u8),
            AttributeKind("20200401".to_string()),
        );
        alist.insert(
            AttributeTag::from(10u8),
            AttributeKind("20291231".to_string()),
        );
        alist
    };
    let serialized_attribute_list = Arc::new(
        to_string(&attribute_list)
            .expect("JSON serialization of the attribute list should not fail."),
    );

    let identity_verifier = warp::path("api")
        .and(warp::path("verify"))
        .and(warp::path::end())
        .and(warp::post().map(move || {
            // When receiving a request from the identity issuer, verification of the
            // identity should be performed, and a valid attribute list should
            // then be returned. For this example there is no verification, i.e.
            // we always verify, and a static attribute list is returned.
            let serialized_attribute_list = Arc::clone(&serialized_attribute_list);
            info!("Verified identity and returned associated attribute list");
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(serialized_attribute_list.to_string())
        }));

    info!("Booting up identity verifier service. Listening on port 8101.");
    warp::serve(identity_verifier)
        .run(([0, 0, 0, 0], 8101))
        .await;
}
