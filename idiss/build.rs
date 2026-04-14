fn main() {
    if std::env::var_os("CARGO_FEATURE_NODEJS").is_some() {
        napi_build::setup();
    }
}
