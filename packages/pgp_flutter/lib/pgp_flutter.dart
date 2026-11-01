/// Flutter integration for the `pgp_dart` package.
///
/// This package contributes the native `pgp_ffi` library to your Flutter app
/// (built automatically via cargokit) and re-exports the full `pgp_dart` API:
///
/// ```dart
/// import 'package:pgp_flutter/pgp_flutter.dart';
///
/// await PgpFlutter.ensureInitialized();
/// final pgp = PGP();
/// final cert = pgp.generateKey('someone@example.org');
/// ```
library;

import 'package:flutter/services.dart' show AssetBundle, rootBundle;
import 'package:pgp_dart/pgp_dart.dart';

export 'package:pgp_dart/pgp_dart.dart';

/// Flutter-side conveniences over `pgp_dart`.
abstract final class PgpFlutter {
  /// Loads the bundled `pgp_ffi` library now, so a missing or broken build
  /// fails at startup rather than on the first PGP call. Returns the name of
  /// the backend in use (`ffi`), like the other ManyMath Flutter plugins.
  static Future<String> ensureInitialized() async {
    ensureNativeLibrary();
    return 'ffi';
  }

  /// Parses an ASCII-armored certificate bundled as a Flutter asset.
  ///
  /// [assetPath] is the key as declared in `pubspec.yaml`. Pass [package] to
  /// load an asset that ships with another package, or [bundle] to read from
  /// a non-default [AssetBundle]. The caller owns the returned certificate and
  /// must dispose it.
  static Future<Certificate> certificateFromAsset(
    String assetPath, {
    String? package,
    AssetBundle? bundle,
  }) async {
    final key = package == null ? assetPath : 'packages/$package/$assetPath';
    final armored = await (bundle ?? rootBundle).loadString(key, cache: false);
    return PGP().certificateFromArmored(armored);
  }
}
