import 'dart:io';

import 'package:build_tool/src/crate_hash.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  late String fixtureDir;

  setUp(() {
    fixtureDir =
        path.join(Directory.current.path, 'test', 'fixtures', 'rust_crate');
  });

  group('CrateHash.enumerateFiles', () {
    test('returns a non-empty list of files for a valid crate directory', () {
      final files = CrateHash.enumerateFiles(fixtureDir);
      expect(files, isA<List<File>>());
      expect(files, isNotEmpty);
    });

    test('returned files include Cargo.toml', () {
      final files = CrateHash.enumerateFiles(fixtureDir);
      final paths = files.map((f) => f.path).toList();
      expect(paths.any((p) => p.contains('Cargo.toml')), isTrue,
          reason: 'Expected at least one file path containing Cargo.toml');
    });

    test('returned files include .rs files from src/', () {
      final files = CrateHash.enumerateFiles(fixtureDir);
      final paths = files.map((f) => f.path).toList();
      expect(paths.any((p) => p.endsWith('.rs')), isTrue,
          reason: 'Expected at least one file path ending with .rs');
    });

    test('handles non-existent directory gracefully', () {
      final nonExistent = path.join(fixtureDir, 'does_not_exist');
      expect(
        () => CrateHash.enumerateFiles(nonExistent),
        throwsA(isA<FileSystemException>()),
      );
    });
  });
}
