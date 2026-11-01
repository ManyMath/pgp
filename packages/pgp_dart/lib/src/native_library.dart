import 'dart:ffi';
import 'dart:io';

/// Explicit path to the native `pgp_ffi` library. Set it before the first
/// [PGP] call. When it (or the `PGP_DART_LIB` environment variable) is set,
/// no other location is tried.
String? nativeLibraryOverridePath;

String get _fileName => switch (Platform.operatingSystem) {
  'windows' => 'pgp_ffi.dll',
  'macos' || 'ios' => 'libpgp_ffi.dylib',
  'android' || 'linux' => 'libpgp_ffi.so',
  _ => throw UnsupportedError(
    'Unsupported platform: ${Platform.operatingSystem}',
  ),
};

Iterable<String> _candidates() sync* {
  // pgp_flutter force-loads the static library into its framework on Apple
  // platforms; the loader resolves the framework binary by its short path.
  if (Platform.isMacOS || Platform.isIOS) {
    yield 'pgp_flutter.framework/pgp_flutter';
  }
  // A Flutter desktop bundle, or a CLI shipped next to the library.
  final executableDir = File(Platform.resolvedExecutable).parent.path;
  yield '$executableDir/lib/$_fileName';
  yield '$executableDir/$_fileName';
  // The OS loader path, which covers Android's jniLibs.
  yield _fileName;
  // Developer builds of the in-repo crate, searched from the cwd upward.
  var dir = Directory.current.absolute;
  for (var i = 0; i < 6; i++) {
    for (final profile in ['release', 'debug']) {
      yield '${dir.path}/packages/pgp_flutter/rust/target/$profile/$_fileName';
      // The CNG build, which needs no perl or NASM on Windows.
      if (Platform.isWindows) {
        yield '${dir.path}/packages/pgp_flutter/windows/rust/target/$profile/$_fileName';
      }
    }
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
}

DynamicLibrary _loadLibrary() {
  // An explicit path must load; falling back to another copy would hide it.
  final fromEnv = Platform.environment['PGP_DART_LIB'];
  final explicit =
      nativeLibraryOverridePath ??
      (fromEnv != null && fromEnv.isNotEmpty ? fromEnv : null);
  if (explicit != null) {
    try {
      return DynamicLibrary.open(explicit);
    } catch (error) {
      throw ArgumentError(
        'Failed to load the pgp_ffi native library from '
        '$explicit: $error',
      );
    }
  }

  final attempted = <String>[];
  Object? lastError;
  for (final candidate in _candidates()) {
    try {
      return DynamicLibrary.open(candidate);
    } catch (error) {
      attempted.add(candidate);
      lastError = error;
    }
  }

  // The symbols may already be linked into the host process (an Apple plugin
  // framework the loader opened for us).
  try {
    final process = DynamicLibrary.process();
    process.lookup('pgp_free');
    return process;
  } catch (_) {
    // Fall through to the error below.
  }

  throw ArgumentError(
    'Failed to load the pgp_ffi native library. Build it with '
    '`cargo build --release --manifest-path '
    'packages/pgp_flutter/rust/Cargo.toml`, depend on pgp_flutter in a '
    'Flutter app, or set PGP_DART_LIB.\n'
    'Resolved executable: ${Platform.resolvedExecutable}\n'
    'Current directory: ${Directory.current.path}\n'
    'Attempted paths:\n${attempted.map((path) => '- $path').join('\n')}\n'
    'Last error: $lastError',
  );
}

final DynamicLibrary nativeLibrary = _loadLibrary();

/// Loads the native library now rather than on first use.
///
/// Throws an [ArgumentError] listing every path tried if it cannot be found.
void ensureNativeLibrary() {
  if (!nativeLibrary.providesSymbol('pgp_free')) {
    throw ArgumentError('The loaded library does not export pgp_free.');
  }
}
