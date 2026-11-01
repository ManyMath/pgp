import 'package:build_tool/src/target.dart';
import 'package:test/test.dart';

void main() {
  group('Target.forCodeAssets', () {
    test('linux/x64 returns x86_64-unknown-linux-gnu', () {
      final target = Target.forCodeAssets('linux', 'x64');
      expect(target.rust, 'x86_64-unknown-linux-gnu');
    });

    test('linux/arm64 returns aarch64-unknown-linux-gnu', () {
      final target = Target.forCodeAssets('linux', 'arm64');
      expect(target.rust, 'aarch64-unknown-linux-gnu');
    });

    test('macos/x64 returns x86_64-apple-darwin', () {
      final target = Target.forCodeAssets('macos', 'x64');
      expect(target.rust, 'x86_64-apple-darwin');
    });

    test('macos/arm64 returns aarch64-apple-darwin', () {
      final target = Target.forCodeAssets('macos', 'arm64');
      expect(target.rust, 'aarch64-apple-darwin');
    });

    test('windows/x64 returns x86_64-pc-windows-msvc', () {
      final target = Target.forCodeAssets('windows', 'x64');
      expect(target.rust, 'x86_64-pc-windows-msvc');
    });

    test('windows/arm64 returns aarch64-pc-windows-msvc', () {
      final target = Target.forCodeAssets('windows', 'arm64');
      expect(target.rust, 'aarch64-pc-windows-msvc');
    });

    test('unsupported OS throws ArgumentError', () {
      expect(
        () => Target.forCodeAssets('freebsd', 'x64'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('unsupported architecture throws ArgumentError', () {
      expect(
        () => Target.forCodeAssets('linux', 'ia32'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('error message lists all 6 supported combinations', () {
      try {
        Target.forCodeAssets('freebsd', 'x64');
        fail('Expected ArgumentError');
      } on ArgumentError catch (e) {
        final message = e.message as String;
        expect(message, contains('linux/x64'));
        expect(message, contains('linux/arm64'));
        expect(message, contains('macos/x64'));
        expect(message, contains('macos/arm64'));
        expect(message, contains('windows/x64'));
        expect(message, contains('windows/arm64'));
      }
    });

    test('returns Target instances from Target.all', () {
      final target = Target.forCodeAssets('linux', 'x64');
      expect(Target.all.contains(target), isTrue);
    });
  });
}
