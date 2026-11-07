import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:test/test.dart';

import '../hook/build.dart' as build_hook;

void main() {
  group('build hook', () {
    test('uses local_lib override without calling sourceBuilder', () async {
      final tempDir = await Directory.systemTemp.createTemp('pgp_hook_local_');
      try {
        final libName = OS.current.libraryFileName(
          'pgp_ffi',
          DynamicLoadingBundled(),
        );
        final localFile = File.fromUri(tempDir.uri.resolve(libName));
        await localFile.writeAsBytes(
          _syntheticValidLibraryBytes(OS.current, Architecture.current),
        );

        var sourceCalled = false;
        await testCodeBuildHook(
          mainMethod: (args) => build(
            args,
            (input, output) => build_hook.runPgpBuild(
              input,
              output,
              sourceBuilder: (i, o) async {
                sourceCalled = true;
              },
            ),
          ),
          userDefines: _defines({'local_lib': localFile.path}),
          check: (input, output) {
            expect(sourceCalled, isFalse);
            final assets = output.assets.code;
            expect(assets, hasLength(1));
            expect(assets.single.file, localFile.uri);
            expect(output.dependencies, contains(localFile.uri));
          },
        );
      } finally {
        await tempDir.delete(recursive: true);
      }
    });

    test(
      'downloads and verifies prebuilt tar.gz archive with matching sha256',
      () async {
        final os = OS.current;
        final arch = Architecture.current;
        final libName = os.libraryFileName('pgp_ffi', DynamicLoadingBundled());
        final libBytes = _syntheticValidLibraryBytes(os, arch);
        final archiveBytes = _buildTarGzArchive(libName, libBytes);
        final expectedSha = sha256.convert(archiveBytes).toString();
        final expectedFilename = 'pgp_ffi-${os.name}-${arch.name}.tar.gz';

        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((request) async {
          if (request.uri.path == '/$expectedFilename') {
            request.response
              ..statusCode = HttpStatus.ok
              ..add(archiveBytes);
          } else {
            request.response.statusCode = HttpStatus.notFound;
          }
          await request.response.close();
        });

        var sourceCalled = false;
        await testCodeBuildHook(
          mainMethod: (args) => build(
            args,
            (input, output) => build_hook.runPgpBuild(
              input,
              output,
              sourceBuilder: (i, o) async {
                sourceCalled = true;
              },
            ),
          ),
          userDefines: _defines({
            'prebuilt_base_url': 'http://127.0.0.1:${server.port}',
            'prebuilt_sha256': expectedSha,
            'require_prebuilt': true,
          }),
          check: (input, output) {
            expect(sourceCalled, isFalse);
            final assets = output.assets.code;
            expect(assets, hasLength(1));
            final extractedFile = File.fromUri(assets.single.file!);
            expect(extractedFile.existsSync(), isTrue);
            expect(extractedFile.readAsBytesSync(), orderedEquals(libBytes));
          },
        );
      },
    );

    test(
      'rejects tampered prebuilt archive when require_prebuilt is true',
      () async {
        final os = OS.current;
        final arch = Architecture.current;
        final libName = os.libraryFileName('pgp_ffi', DynamicLoadingBundled());
        final archiveBytes = _buildTarGzArchive(
          libName,
          _syntheticValidLibraryBytes(os, arch),
        );

        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((request) async {
          request.response
            ..statusCode = HttpStatus.ok
            ..add(archiveBytes);
          await request.response.close();
        });

        var sourceCalled = false;
        await expectLater(
          testCodeBuildHook(
            mainMethod: (args) => build(
              args,
              (input, output) => build_hook.runPgpBuild(
                input,
                output,
                sourceBuilder: (i, o) async {
                  sourceCalled = true;
                },
              ),
            ),
            userDefines: _defines({
              'prebuilt_base_url': 'http://127.0.0.1:${server.port}',
              'prebuilt_sha256': '0' * 64,
              'require_prebuilt': true,
            }),
            check: (_, _) {},
          ),
          throwsA(isA<FormatException>()),
        );
        expect(sourceCalled, isFalse);
      },
    );

    test(
      'rejects checksum mismatch and falls back to sourceBuilder when allowed',
      () async {
        final os = OS.current;
        final arch = Architecture.current;
        final libName = os.libraryFileName('pgp_ffi', DynamicLoadingBundled());
        final archiveBytes = _buildTarGzArchive(
          libName,
          _syntheticValidLibraryBytes(os, arch),
        );

        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((request) async {
          request.response
            ..statusCode = HttpStatus.ok
            ..add(archiveBytes);
          await request.response.close();
        });

        final fallbackDir = await Directory.systemTemp.createTemp(
          'pgp_hook_fallback_',
        );
        try {
          final fallbackFile = File.fromUri(fallbackDir.uri.resolve(libName));
          final expectedFallbackBytes = _syntheticValidLibraryBytes(os, arch);
          await fallbackFile.writeAsBytes(expectedFallbackBytes);

          var sourceCalled = false;
          await testCodeBuildHook(
            mainMethod: (args) => build(
              args,
              (input, output) => build_hook.runPgpBuild(
                input,
                output,
                sourceBuilder: (i, o) async {
                  sourceCalled = true;
                  o.assets.code.add(
                    CodeAsset(
                      package: i.packageName,
                      name: build_hook.pgpAssetName,
                      linkMode: DynamicLoadingBundled(),
                      file: fallbackFile.uri,
                    ),
                  );
                },
              ),
            ),
            userDefines: _defines({
              'prebuilt_base_url': 'http://127.0.0.1:${server.port}',
              'prebuilt_sha256': 'f' * 64,
              'require_prebuilt': false,
            }),
            check: (input, output) {
              expect(sourceCalled, isTrue);
              expect(output.assets.code.single.file, fallbackFile.uri);
            },
          );
        } finally {
          await fallbackDir.delete(recursive: true);
        }
      },
    );
  });
}

PackageUserDefines _defines(Map<String, Object> values) => PackageUserDefines(
  workspacePubspec: PackageUserDefinesSource(
    defines: values,
    basePath: Directory.current.uri,
  ),
);

Uint8List _syntheticValidLibraryBytes(OS os, Architecture arch) {
  if (os == OS.macOS || os == OS.iOS) {
    final bytes = Uint8List(32);
    ByteData.sublistView(bytes)
      ..setUint32(0, 0xfeedfacf, Endian.little)
      ..setUint32(
        4,
        arch == Architecture.arm64 ? 0x0100000c : 0x01000007,
        Endian.little,
      )
      ..setUint32(8, 0, Endian.little);
    return bytes;
  }
  if (os == OS.windows) {
    final bytes = Uint8List(128);
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    final bd = ByteData.sublistView(bytes);
    bd.setUint32(0x3c, 0x40, Endian.little);
    bytes[0x40] = 0x50;
    bytes[0x41] = 0x45;
    bd.setUint16(
      0x44,
      arch == Architecture.arm64 ? 0xaa64 : 0x8664,
      Endian.little,
    );
    return bytes;
  }
  final is32 = arch == Architecture.ia32 || arch == Architecture.arm;
  final bytes = Uint8List(64);
  bytes.setAll(0, const [0x7f, 0x45, 0x4c, 0x46]);
  bytes[4] = is32 ? 1 : 2;
  bytes[5] = 1;
  final machine = switch (arch) {
    Architecture.arm => 40,
    Architecture.arm64 => 183,
    Architecture.ia32 => 3,
    Architecture.riscv32 || Architecture.riscv64 => 243,
    _ => 62,
  };
  ByteData.sublistView(bytes).setUint16(18, machine, Endian.little);
  return bytes;
}

Uint8List _buildTarGzArchive(String entryName, Uint8List contents) {
  final header = Uint8List(512);
  header.setAll(0, utf8.encode(entryName));
  header.setAll(100, ascii.encode('0000755\x00'));
  header.setAll(108, ascii.encode('0000000\x00'));
  header.setAll(116, ascii.encode('0000000\x00'));
  final sizeOctal = contents.length.toRadixString(8).padLeft(11, '0');
  header.setAll(124, ascii.encode('$sizeOctal\x00'));
  header.setAll(136, ascii.encode('00000000000\x00'));
  header.fillRange(148, 156, 0x20);
  header[156] = 0x30;
  header.setAll(257, ascii.encode('ustar\x00'));
  header.setAll(263, ascii.encode('00'));

  var checksum = 0;
  for (final byte in header) {
    checksum += byte;
  }
  final checksumOctal = checksum.toRadixString(8).padLeft(6, '0');
  header.setAll(148, ascii.encode('$checksumOctal\x00 '));

  final paddedDataLen = ((contents.length + 511) ~/ 512) * 512;
  final tar = Uint8List(512 + paddedDataLen + 1024);
  tar.setAll(0, header);
  tar.setAll(512, contents);
  return Uint8List.fromList(gzip.encode(tar));
}
