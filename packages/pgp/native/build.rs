fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if vendor == "apple" {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-x");
    } else if os == "linux" || os == "android" {
        println!("cargo:rustc-link-arg-cdylib=-Wl,--strip-debug");
    }

    #[cfg(feature = "header")]
    {
        println!("cargo:rerun-if-changed=src/lib.rs");
        println!("cargo:rerun-if-changed=cbindgen.toml");
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
