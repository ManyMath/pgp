// Regenerates pgp-ffi.h with `cargo build --features header`. Other builds
// (cargokit, crates.io consumers) leave the source tree alone.
fn main() {
    #[cfg(feature = "header")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let config = cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml")).unwrap();
        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(config)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(format!("{crate_dir}/pgp-ffi.h"));
    }
}
