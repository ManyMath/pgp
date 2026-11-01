import 'package:ffi/ffi.dart';
import 'package:test/test.dart';
import 'package:dart_cli_example/native.dart';

void main() {
  group('arithmetic', () {
    test('add returns correct sum', () {
      expect(add(2, 3), equals(5));
    });

    test('add handles zero', () {
      expect(add(0, 0), equals(0));
    });

    test('add handles negative numbers', () {
      expect(add(-1, 1), equals(0));
    });
  });

  group('structs', () {
    test('create_point stores coordinates', () {
      final p = create_point(1.5, 2.5);
      expect(p.x, equals(1.5));
      expect(p.y, equals(2.5));
    });

    test('distance calculates correctly', () {
      final p1 = create_point(0, 0);
      final p2 = create_point(3, 4);
      expect(distance(p1, p2), closeTo(5.0, 0.001));
    });
  });

  group('strings', () {
    test('reverse_string reverses input', () {
      final input = 'hello'.toNativeUtf8();
      final result = reverse_string(input.cast());
      expect(result.cast<Utf8>().toDartString(), equals('olleh'));
      free_rust_string(result);
      malloc.free(input);
    });

    test('reverse_string handles empty string', () {
      final input = ''.toNativeUtf8();
      final result = reverse_string(input.cast());
      expect(result.cast<Utf8>().toDartString(), equals(''));
      free_rust_string(result);
      malloc.free(input);
    });
  });
}
