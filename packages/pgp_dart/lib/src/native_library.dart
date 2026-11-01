import 'dart:ffi';
import 'dart:io';

/// Explicit path to the native `pgp_ffi` library. Highest priority; set it
/// before the first [PGP] call.
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
  if (nativeLibraryOverridePath != null) yield nativeLibraryOverridePath!;
  final fromEnv = Platform.environment['PGP_DART_LIB'];
  if (fromEnv != null && fromEnv.isNotEmpty) yield fromEnv;
  // Resolved via the OS loader path or the Flutter app bundle (pgp_flutter).
  yield _fileName;
  // pgp_flutter force-loads the static library into its framework on Apple
  // platforms; the loader resolves the framework binary by its short path.
  if (Platform.isMacOS || Platform.isIOS) {
    yield 'pgp_flutter.framework/pgp_flutter';
  }
  final executableDir = File(Platform.resolvedExecutable).parent.path;
  yield '$executableDir/$_fileName';
  yield '$executableDir/lib/$_fileName';
  // Developer builds of the in-repo crate, searched from the cwd upward.
  var dir = Directory.current.absolute;
  for (var i = 0; i < 6; i++) {
    yield '${dir.path}/$_fileName';
    for (final profile in ['release', 'debug']) {
      yield '${dir.path}/packages/pgp_flutter/rust/target/$profile/$_fileName';
    }
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
}

DynamicLibrary _loadLibrary() {
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
