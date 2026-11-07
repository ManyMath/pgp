#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORK_DIR="$(mktemp -d)"
KEEP="${KEEP:-0}"

cleanup() {
  if [[ "$KEEP" == "1" ]]; then
    echo "KEEP=1 preserved workspace: $WORK_DIR"
  else
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

export DASH__SUPPRESS_ANALYTICS="${DASH__SUPPRESS_ANALYTICS:-true}"
export FLUTTER_SUPPRESS_ANALYTICS="${FLUTTER_SUPPRESS_ANALYTICS:-true}"

git -C "$REPO_ROOT" archive HEAD packages/pgp_dart packages/pgp | tar -x -C "$WORK_DIR"

# Standalone Dart CLI consumer outside the repository workspace.
CLI_DIR="$WORK_DIR/dart_consumer"
mkdir -p "$CLI_DIR/bin" "$CLI_DIR/test"

cat >"$CLI_DIR/pubspec.yaml" <<'EOF'
name: pgp_consumer_cli
publish_to: none

environment:
  sdk: ^3.10.0

dependencies:
  pgp:
    path: ../packages/pgp
  pgp_dart:
    path: ../packages/pgp_dart

dependency_overrides:
  pgp_dart:
    path: ../packages/pgp_dart

dev_dependencies:
  test: ^1.24.0
EOF

cat >"$CLI_DIR/bin/pgp_consumer_cli.dart" <<'EOF'
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pgp/pgp.dart';
import 'package:pgp_dart/pgp_dart.dart' as models;

void main() {
  ensureNativeLibrary();
  ensureNativeLibrary();

  final pgp = PGP();
  final ed = pgp.generateKey('cli-ed@example.org');
  final rsa = pgp.generateKeyWithCipherSuite(
    'cli-rsa@example.org',
    CipherSuite.rsa2k,
  );

  final edPub = pgp.certificateFromArmored(ed.exportPublicArmored());
  final clear = rsa.signCleartext('monero-release-check');
  final clearVerified = rsa.verifyCleartextWithSigner(clear);
  if (clearVerified.plaintext != 'monero-release-check' ||
      clearVerified.hashAlgorithm != models.HashAlgorithmPreference.sha512) {
    stderr.writeln('Unexpected cleartext verification result');
    exit(1);
  }

  final payload = Uint8List.fromList(<int>[0x7f, 0x45, 0x00, 0x46, 0xff]);
  final sig = ed.signDetachedBytes(payload);
  final detachedInfo = edPub.verifyDetachedBytes(payload, sig);
  if (detachedInfo.signerFingerprint.isEmpty || !detachedInfo.hasSignedAt) {
    stderr.writeln('Unexpected detached bytes verification metadata');
    exit(1);
  }

  final tmp = Directory.systemTemp.createTempSync('pgp_cli_file_');
  try {
    final dataFile = File('${tmp.path}/blob.bin');
    final sigFile = File('${tmp.path}/blob.bin.asc');
    dataFile.writeAsBytesSync(
      Uint8List.fromList(<int>[...utf8.encode('tarball'), 0x00, 0xaa, 0xbb]),
    );
    ed.signDetachedFile(dataFile.path, sigFile.path);
    final fileInfo = edPub.verifyDetachedFile(
      dataFile.path,
      sigFile.readAsStringSync(),
    );
    if (fileInfo.hashAlgorithm != models.HashAlgorithmPreference.sha512) {
      stderr.writeln('Unexpected detached file hash algorithm');
      exit(1);
    }
  } finally {
    tmp.deleteSync(recursive: true);
    edPub.dispose();
    ed.dispose();
    rsa.dispose();
  }

  print('consumer cli ok');
}
EOF

cat >"$CLI_DIR/test/consumer_test.dart" <<'EOF'
import 'dart:typed_data';

import 'package:pgp/pgp.dart';
import 'package:test/test.dart';

void main() {
  test('consumer round-trip with PgpException detail', () {
    ensureNativeLibrary();
    final pgp = PGP();
    final cert = pgp.generateKey('consumer-test@example.org');
    final payload = Uint8List.fromList([0x00, 0x01, 0x02, 0xff]);
    final sig = cert.signDetachedBytes(payload);
    final info = cert.verifyDetachedBytes(payload, sig);
    expect(info.hashAlgorithm, HashAlgorithmPreference.sha512);
    expect(
      () => pgp.certificateFromArmored('invalid armor'),
      throwsA(isA<PgpException>().having((e) => e.message, 'message', isNotEmpty)),
    );
    cert.dispose();
  });
}
EOF

(
  cd "$CLI_DIR"
  dart pub get
  dart test
  dart build cli -t bin/pgp_consumer_cli.dart -o cli_out
  ./cli_out/bundle/bin/pgp_consumer_cli
)

if [[ $# -eq 0 ]]; then
  exit 0
fi

FLUTTER_DIR="$WORK_DIR/flutter_consumer"
flutter create --no-pub --project-name pgp_flutter_consumer "$FLUTTER_DIR"

python3 - "$FLUTTER_DIR/pubspec.yaml" "$WORK_DIR" <<'PY'
import pathlib, sys

pubspec_path = pathlib.Path(sys.argv[1])
work_dir = pathlib.Path(sys.argv[2])
text = pubspec_path.read_text()

needle = "dependencies:\n  flutter:\n    sdk: flutter\n"
replacement = (
    f"{needle}"
    f"  pgp:\n    path: {work_dir / 'packages' / 'pgp'}\n"
)
if needle not in text:
    raise SystemExit("Expected dependencies block not found in pubspec.yaml")
text = text.replace(needle, replacement, 1)
text += (
    "\ndependency_overrides:\n"
    f"  pgp_dart:\n    path: {work_dir / 'packages' / 'pgp_dart'}\n"
)
pubspec_path.write_text(text)
PY

cat >"$FLUTTER_DIR/lib/main.dart" <<'EOF'
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:pgp/pgp.dart';

void main() {
  runApp(const PgpApp());
}

class PgpApp extends StatelessWidget {
  const PgpApp({super.key});

  String _exercisePgp() {
    ensureNativeLibrary();
    final pgp = PGP();
    final cert = pgp.generateKey('flutter@example.org');
    try {
      final sig = cert.signDetachedBytes(Uint8List.fromList([0, 1, 2, 255]));
      final info = cert.verifyDetachedBytes(
        Uint8List.fromList([0, 1, 2, 255]),
        sig,
      );
      return '${info.signerFingerprint} (${info.hashAlgorithm?.standardName})';
    } finally {
      cert.dispose();
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(body: Center(child: Text(_exercisePgp()))),
    );
  }
}
EOF

(
  cd "$FLUTTER_DIR"
  flutter pub get
  for target in "$@"; do
    case "$target" in
      linux|apk|macos|windows)
        flutter build "$target" --release
        ;;
      ios)
        flutter build ios --release --no-codesign
        ;;
      *)
        echo "Unsupported Flutter target: $target" >&2
        exit 2
        ;;
    esac
  done
)
