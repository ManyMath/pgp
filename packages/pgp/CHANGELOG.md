## 0.0.1

- `pgp` is now the Flutter plugin. The pure-Dart bindings published as `pgp`
  0.0.1-dev.1 continue as [`pgp_dart`](https://pub.dev/packages/pgp_dart);
  depend on that instead in Dart code without Flutter.
- Builds the `pgp-ffi` crate with cargokit on Android, iOS, Linux, macOS and
  Windows and re-exports `pgp_dart`. Adds `PgpFlutter.ensureInitialized` and
  `PgpFlutter.certificateFromAsset`. Windows builds use Sequoia's CNG backend
  through `windows/rust`; the other platforms link a statically built OpenSSL.
- Requires `pgp_dart` ^0.0.2. The repository is https://github.com/ManyMath/pgp.

## 0.0.1-dev.1

- Initial version (pure-Dart bindings, now `pgp_dart`).
