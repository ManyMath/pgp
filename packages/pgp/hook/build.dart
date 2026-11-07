import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

/// Native code asset identifier matching `ffigen.yaml` `@DefaultAsset`.
const String pgpAssetName = 'src/pgp-ffi_bindings_generated.dart';

/// Default base URL for prebuilt `pgp_ffi` release archives.
const String defaultPrebuiltBaseUrl =
    'https://github.com/ManyMath/pgp/releases/download/pgp-v0.0.2';

/// Pinned SHA-256 digests keyed by `<os>-<arch>` (for example, `linux-x64`).
/// Populated per target when publishing release archives.
const Map<String, String> pinnedPrebuiltSha256 = <String, String>{};

Future<void> main(List<String> args) async {
  await build(args, runPgpBuild);
}

/// Resolves or builds `pgp_ffi` using a three-tier strategy:
/// 1. `local_lib` user-define override
/// 2. SHA-256-verified prebuilt `.tar.gz` download into shared output cache
/// 3. Source compilation via [RustBuilder]
Future<void> runPgpBuild(
  BuildInput input,
  BuildOutputBuilder output, {
  Future<void> Function(BuildInput input, BuildOutputBuilder output)?
  sourceBuilder,
}) async {
  if (!input.config.buildCodeAssets) {
    return;
  }

  final code = input.config.code;
  final localLib = _nonEmptyString(input.userDefines['local_lib']);
  if (localLib != null) {
    final libUri = _resolvePath(input.packageRoot, localLib);
    if (!File.fromUri(libUri).existsSync()) {
      throw StateError(
        'Configured local_lib not found: ${libUri.toFilePath()}',
      );
    }
    output.dependencies.add(libUri);
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: pgpAssetName,
        linkMode: DynamicLoadingBundled(),
        file: libUri,
      ),
    );
    return;
  }

  final buildFromSource = _asBool(input.userDefines['build_from_source']);
  final requirePrebuilt = _asBool(input.userDefines['require_prebuilt']);
  if (!buildFromSource &&
      code.linkModePreference != LinkModePreference.static) {
    final cachedUri = await _tryDownloadPrebuilt(
      input,
      code,
      requirePrebuilt: requirePrebuilt,
    );
    if (cachedUri != null) {
      output.assets.code.add(
        CodeAsset(
          package: input.packageName,
          name: pgpAssetName,
          linkMode: DynamicLoadingBundled(),
          file: cachedUri,
        ),
      );
      return;
    }
  } else if (requirePrebuilt) {
    throw StateError(
      'require_prebuilt is incompatible with build_from_source or static link mode.',
    );
  }

  if (sourceBuilder != null) {
    await sourceBuilder(input, output);
    return;
  }

  final useWindowsCng = code.targetOS == OS.windows;
  await RustBuilder(
    assetName: pgpAssetName,
    cratePath: 'native',
    enableDefaultFeatures: !useWindowsCng,
    features: useWindowsCng ? const <String>['crypto-cng'] : const <String>[],
    extraCargoBuildArgs: const <String>['--locked'],
    extraCargoEnvironmentVariables: _cargoEnvForTarget(code),
  ).run(input: input, output: output);
}

Future<Uri?> _tryDownloadPrebuilt(
  BuildInput input,
  CodeConfig code, {
  required bool requirePrebuilt,
}) async {
  final targetKey = '${code.targetOS.name}-${code.targetArchitecture.name}';
  final overrideSha = _nonEmptyString(
    input.userDefines['prebuilt_sha256'],
  )?.toLowerCase();
  if (overrideSha != null && !RegExp(r'^[0-9a-f]{64}$').hasMatch(overrideSha)) {
    throw ArgumentError.value(
      overrideSha,
      'prebuilt_sha256',
      'Must be a 64-character hexadecimal SHA-256 digest.',
    );
  }

  final expectedSha = overrideSha ?? pinnedPrebuiltSha256[targetKey];
  if (expectedSha == null) {
    if (requirePrebuilt) {
      throw StateError(
        'No pinned prebuilt SHA-256 digest for target $targetKey.',
      );
    }
    return null;
  }

  final libFileName = code.targetOS.libraryFileName(
    'pgp_ffi',
    DynamicLoadingBundled(),
  );
  final cachedUri = input.outputDirectoryShared.resolve(
    'prebuilt/$targetKey/$expectedSha/$libFileName',
  );
  final cachedFile = File.fromUri(cachedUri);
  if (cachedFile.existsSync() && cachedFile.lengthSync() > 0) {
    return cachedUri;
  }

  final rawBaseUrl =
      _nonEmptyString(input.userDefines['prebuilt_base_url']) ??
      defaultPrebuiltBaseUrl;
  final baseUrl = rawBaseUrl.endsWith('/')
      ? rawBaseUrl.substring(0, rawBaseUrl.length - 1)
      : rawBaseUrl;
  final archiveUri = Uri.parse('$baseUrl/pgp_ffi-$targetKey.tar.gz');

  try {
    final archiveBytes = await _fetchBytes(archiveUri);
    final actualSha = sha256.convert(archiveBytes).toString();
    if (actualSha != expectedSha) {
      throw FormatException(
        'SHA-256 mismatch for $archiveUri: expected $expectedSha, got $actualSha.',
      );
    }

    final tarBytes = Uint8List.fromList(gzip.decode(archiveBytes));
    final libBytes = _extractTarMemberByBasename(tarBytes, libFileName);
    if (libBytes == null || libBytes.isEmpty) {
      throw FormatException(
        'Archive $archiveUri did not contain a valid $libFileName entry.',
      );
    }

    await cachedFile.parent.create(recursive: true);
    final tmpFile = File('${cachedFile.path}.tmp.$pid');
    await tmpFile.writeAsBytes(libBytes, flush: true);
    await tmpFile.rename(cachedFile.path);
    return cachedUri;
  } catch (error) {
    if (requirePrebuilt) {
      rethrow;
    }
    stderr.writeln(
      'pgp build hook: prebuilt download failed ($error); falling back to Rust source build.',
    );
    return null;
  }
}

Future<Uint8List> _fetchBytes(Uri url) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 15);
  try {
    final request = await client
        .getUrl(url)
        .timeout(const Duration(seconds: 15));
    final response = await request.close().timeout(const Duration(seconds: 60));
    if (response.statusCode != HttpStatus.ok) {
      throw HttpException(
        'HTTP ${response.statusCode} while downloading prebuilt archive',
        uri: url,
      );
    }
    final builder = BytesBuilder(copy: false);
    await for (final chunk in response.timeout(const Duration(seconds: 60))) {
      builder.add(chunk);
    }
    return builder.takeBytes();
  } finally {
    client.close(force: true);
  }
}

/// Extracts the first regular file whose basename matches [targetBasename]
/// from a POSIX/USTAR tar buffer.
Uint8List? _extractTarMemberByBasename(
  Uint8List tarBytes,
  String targetBasename,
) {
  var offset = 0;
  String? gnuLongName;
  while (offset + 512 <= tarBytes.length) {
    final header = Uint8List.sublistView(tarBytes, offset, offset + 512);
    offset += 512;

    if (_isAllZero(header)) {
      break;
    }

    final size = _parseOctal(Uint8List.sublistView(header, 124, 136));
    final paddedSize = ((size + 511) ~/ 512) * 512;
    if (size < 0 || offset + paddedSize > tarBytes.length) {
      throw const FormatException('Truncated tar archive entry.');
    }

    final typeFlag = header[156];
    final payload = Uint8List.sublistView(tarBytes, offset, offset + size);
    offset += paddedSize;

    // Handle GNU long filename extension block (`L`).
    if (typeFlag == 0x4c) {
      gnuLongName = _readCString(payload);
      continue;
    }
    // Skip PAX extended/global headers (`x`, `g`) and other metadata blocks.
    if (typeFlag == 0x78 || typeFlag == 0x67 || typeFlag == 0x4b) {
      continue;
    }

    final namePart = _readCString(Uint8List.sublistView(header, 0, 100));
    final prefixPart = _readCString(Uint8List.sublistView(header, 345, 500));
    final entryName =
        gnuLongName ??
        (prefixPart.isEmpty ? namePart : '$prefixPart/$namePart');
    gnuLongName = null;

    // Match regular files (`0` or NUL) by basename only.
    if (typeFlag == 0 || typeFlag == 0x30) {
      final base = entryName.split('/').last;
      if (base == targetBasename) {
        return Uint8List.fromList(payload);
      }
    }
  }
  return null;
}

bool _isAllZero(Uint8List block) {
  for (final byte in block) {
    if (byte != 0) return false;
  }
  return true;
}

int _parseOctal(Uint8List field) {
  final raw = ascii
      .decode(field, allowInvalid: true)
      .replaceAll('\x00', '')
      .trim();
  if (raw.isEmpty) return 0;
  return int.parse(raw, radix: 8);
}

String _readCString(Uint8List field) {
  var end = 0;
  while (end < field.length && field[end] != 0) {
    end++;
  }
  return utf8.decode(
    Uint8List.sublistView(field, 0, end),
    allowMalformed: true,
  );
}

Map<String, String> _cargoEnvForTarget(CodeConfig code) {
  final env = <String, String>{};
  if (code.targetOS == OS.android) {
    final existing = Platform.environment['RUSTFLAGS'];
    const androidFlags =
        '-C link-arg=-Wl,--pack-dyn-relocs=none -C link-arg=-Wl,-z,max-page-size=16384';
    env['RUSTFLAGS'] = (existing != null && existing.isNotEmpty)
        ? '$existing $androidFlags'
        : androidFlags;
  } else if (code.targetOS == OS.iOS) {
    env['IPHONEOS_DEPLOYMENT_TARGET'] = _formatAppleVersion(
      code.iOS.deploymentVersion,
    );
  } else if (code.targetOS == OS.macOS) {
    env['MACOSX_DEPLOYMENT_TARGET'] = _formatAppleVersion(
      code.macOS.deploymentVersion,
    );
  }
  return env;
}

String _formatAppleVersion(AppleVersion version) => version.patch > 0
    ? '${version.major}.${version.minor}.${version.patch}'
    : '${version.major}.${version.minor}';

Uri _resolvePath(Uri packageRoot, String rawPath) {
  final file = File(rawPath);
  if (file.isAbsolute) return file.uri;
  return packageRoot.resolveUri(Uri.file(rawPath));
}

String? _nonEmptyString(Object? value) {
  if (value is! String) return null;
  final trimmed = value.trim();
  return trimmed.isEmpty ? null : trimmed;
}

bool _asBool(Object? value) {
  if (value is bool) return value;
  if (value is String) {
    final normalized = value.trim().toLowerCase();
    return normalized == 'true' || normalized == '1' || normalized == 'yes';
  }
  return false;
}
