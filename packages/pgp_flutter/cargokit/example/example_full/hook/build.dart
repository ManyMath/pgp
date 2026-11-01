import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:build_tool/src/artifacts_provider.dart';
import 'package:build_tool/src/builder.dart';
import 'package:build_tool/src/cargo.dart';
import 'package:build_tool/src/crate_hash.dart';
import 'package:build_tool/src/logging.dart';
import 'package:build_tool/src/options.dart';
import 'package:build_tool/src/target.dart';
import 'package:build_tool/src/util.dart';
import 'package:path/path.dart' as path;

void main(List<String> args) async {
  await build(args, (input, output) async {
    final os = input.config.code.targetOS.toString();
    final arch = input.config.code.targetArchitecture.toString();
    final target = Target.forCodeAssets(os, arch);

    // Each entry: (crate directory name, CodeAsset name matching the
    // @Native() default assetId for the corresponding Dart library file).
    final crates = [
      ('rust_math', 'math_ffi.dart'),
      ('rust_strings', 'strings_ffi.dart'),
    ];

    for (final (crateDir, assetName) in crates) {
      final manifestDir = path.join(input.packageRoot.toFilePath(), crateDir);
      final crateInfo = CrateInfo.load(manifestDir);
      final fileName =
          input.config.code.targetOS.dylibFileName(crateInfo.libraryName);

      for (final file in CrateHash.enumerateFiles(manifestDir)) {
        output.dependencies.add(Uri.file(file.path));
      }

      if (!input.config.buildCodeAssets) {
        output.assets.code.add(CodeAsset(
          package: input.packageName,
          name: assetName,
          linkMode: DynamicLoadingBundled(),
        ));
        continue;
      }

      final configStr =
          Platform.environment['CARGOKIT_CONFIGURATION'] ?? 'release';
      final configuration =
          BuildEnvironment.parseBuildConfiguration(configStr);

      final verbose = Platform.environment['CARGOKIT_VERBOSE'] == '1';
      if (verbose) {
        initLogging();
        enableVerboseLogging();
      }

      final userOptions = CargokitUserOptions(
        usePrecompiledBinaries:
            CargokitUserOptions.defaultUsePrecompiledBinaries(),
        verboseLogging: verbose,
        useLocalPrecompiledBinaries: false,
        cacheLocalBuilds: true,
      );

      final targetTempDir = path.join(
        input.outputDirectoryShared.toFilePath(),
        '${crateDir}_build',
      );
      Directory(targetTempDir).createSync(recursive: true);

      final env = BuildEnvironment.fromBuildInput(
        configuration: configuration,
        manifestDir: manifestDir,
        targetTempDir: targetTempDir,
      );

      try {
        final provider = ArtifactProvider(
          environment: env,
          userOptions: userOptions,
        );
        final artifactMap = await provider.getArtifacts([target]);
        final artifacts = artifactMap[target] ?? [];

        final dylib = artifacts.firstWhere(
          (a) => a.finalFileName == fileName,
          orElse: () => throw Exception(
            'Build completed but expected artifact $fileName not found for $crateDir. '
            'Found: ${artifacts.map((a) => a.finalFileName).join(", ")}',
          ),
        );

        output.assets.code.add(CodeAsset(
          package: input.packageName,
          name: assetName,
          linkMode: DynamicLoadingBundled(),
          file: Uri.file(dylib.path),
        ));
      } on RustupNotFoundException {
        throw Exception(
          'Rust toolchain not found. Install from https://rustup.rs '
          'and ensure rustup is on your PATH.',
        );
      }
    }
  });
}
