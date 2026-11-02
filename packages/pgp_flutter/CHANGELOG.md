## 0.0.1

- Initial release: builds the `pgp-ffi` crate with cargokit on Android, iOS,
  Linux, macOS and Windows and re-exports `pgp_dart`. Adds
  `PgpFlutter.ensureInitialized` and `PgpFlutter.certificateFromAsset`.
  Windows builds use Sequoia's CNG backend through `windows/rust`; the other
  platforms link a statically built OpenSSL.
- Requires `pgp_dart` ^0.0.1. The repository is https://github.com/ManyMath/pgp.
