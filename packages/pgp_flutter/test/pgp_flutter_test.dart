import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pgp_flutter/pgp_flutter.dart';

/// An [AssetBundle] that returns fixed text for any key.
class _FakeBundle extends CachingAssetBundle {
  _FakeBundle(this._text);
  final String _text;
  String? requested;

  @override
  Future<ByteData> load(String key) async {
    requested = key;
    return ByteData.sublistView(utf8.encode(_text));
  }
}

bool _nativeAvailable() {
  try {
    PgpFlutter.ensureInitialized();
    return true;
  } on Object {
    return false;
  }
}

void main() {
  // The native tests need a host build of the crate:
  // cargo build --release --manifest-path packages/pgp_flutter/rust/Cargo.toml
  final skip = _nativeAvailable() ? false : 'pgp_ffi is not built';

  test('certificateFromAsset parses an armored certificate', () async {
    final pgp = PGP();
    final cert = pgp.generateKey('asset@example.org');
    final bundle = _FakeBundle(cert.exportPublicArmored());

    final loaded = await PgpFlutter.certificateFromAsset(
      'keys/asset.asc',
      bundle: bundle,
    );
    expect(bundle.requested, 'keys/asset.asc');
    expect(loaded.fingerprint(), cert.fingerprint());
    loaded.dispose();
    cert.dispose();
  }, skip: skip);

  test('certificateFromAsset prefixes package assets', () async {
    final pgp = PGP();
    final cert = pgp.generateKey('pkg@example.org');
    final bundle = _FakeBundle(cert.exportPublicArmored());

    final loaded = await PgpFlutter.certificateFromAsset(
      'keys/asset.asc',
      package: 'other',
      bundle: bundle,
    );
    expect(bundle.requested, 'packages/other/keys/asset.asc');
    loaded.dispose();
    cert.dispose();
  }, skip: skip);
}
