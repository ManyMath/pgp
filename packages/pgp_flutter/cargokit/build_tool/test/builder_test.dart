import 'dart:io';

import 'package:build_tool/src/builder.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  test('parseBuildConfiguration', () {
    var b = BuildEnvironment.parseBuildConfiguration('debug');
    expect(b, BuildConfiguration.debug);

    b = BuildEnvironment.parseBuildConfiguration('profile');
    expect(b, BuildConfiguration.profile);

    b = BuildEnvironment.parseBuildConfiguration('release');
    expect(b, BuildConfiguration.release);

    b = BuildEnvironment.parseBuildConfiguration('debug-dev');
    expect(b, BuildConfiguration.debug);

    b = BuildEnvironment.parseBuildConfiguration('profile');
    expect(b, BuildConfiguration.profile);

    b = BuildEnvironment.parseBuildConfiguration('profile-prod');
    expect(b, BuildConfiguration.profile);

    // fallback to release
    b = BuildEnvironment.parseBuildConfiguration('unknown');
    expect(b, BuildConfiguration.release);
  });

  group('BuildEnvironment.fromBuildInput', () {
    late Directory tempDir;
    late String manifestDir;
    late String targetTempDir;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('builder_test_');
      manifestDir = tempDir.path;
      targetTempDir = path.join(tempDir.path, 'target');

      File(path.join(manifestDir, 'Cargo.toml')).writeAsStringSync('''
[package]
name = "test_crate"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
''');
    });

    tearDown(() {
      tempDir.deleteSync(recursive: true);
    });

    test('creates BuildEnvironment with release configuration', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.release,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.configuration, BuildConfiguration.release);
    });

    test('creates BuildEnvironment with debug configuration', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.debug,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.configuration, BuildConfiguration.debug);
    });

    test('sets isAndroid to false', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.release,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.isAndroid, isFalse);
    });

    test('sets Android fields to null', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.release,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.androidSdkPath, isNull);
      expect(env.androidNdkVersion, isNull);
      expect(env.androidMinSdkVersion, isNull);
      expect(env.javaHome, isNull);
    });

    test('sets manifestDir and targetTempDir from parameters', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.release,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.manifestDir, manifestDir);
      expect(env.targetTempDir, targetTempDir);
    });

    test('loads CrateInfo from manifestDir', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.release,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.crateInfo.packageName, 'test_crate');
    });

    test('loads CargokitCrateOptions from manifestDir', () {
      final env = BuildEnvironment.fromBuildInput(
        configuration: BuildConfiguration.release,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );
      expect(env.crateOptions.cargo, isEmpty);
      expect(env.crateOptions.precompiledBinaries, isNull);
    });
  });
}
