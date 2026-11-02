// Shared C source for the iOS and macOS plugin frameworks.
//
// The real OpenPGP entry points live in libpgp_ffi (the Rust crate), which
// the podspec force-links into the framework via -force_load. This file only
// has to make the framework non-empty so Xcode is happy compiling it.

void pgp_keep_alive(void) {}
