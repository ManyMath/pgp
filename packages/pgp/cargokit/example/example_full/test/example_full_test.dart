import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:test/test.dart';
import 'package:example_full/math_ffi.dart';
import 'package:example_full/strings_ffi.dart';

void main() {
  group('rust_math', () {
    test('vec2_add adds components', () {
      final aPtr = malloc<Vec2>();
      aPtr.ref.x = 1.0;
      aPtr.ref.y = 2.0;
      final bPtr = malloc<Vec2>();
      bPtr.ref.x = 3.0;
      bPtr.ref.y = 4.0;
      final result = vec2_add(aPtr.ref, bPtr.ref);
      expect(result.x, equals(4.0));
      expect(result.y, equals(6.0));
      malloc.free(aPtr);
      malloc.free(bPtr);
    });

    test('vec2_length calculates magnitude', () {
      final vPtr = malloc<Vec2>();
      vPtr.ref.x = 3.0;
      vPtr.ref.y = 4.0;
      expect(vec2_length(vPtr.ref), closeTo(5.0, 0.001));
      malloc.free(vPtr);
    });

    test('safe_divide returns 0 on success', () {
      final resultPtr = malloc<Double>();
      final status = safe_divide(10.0, 2.0, resultPtr);
      expect(status, equals(0));
      expect(resultPtr.value, equals(5.0));
      malloc.free(resultPtr);
    });

    test('safe_divide returns -1 on division by zero', () {
      final resultPtr = malloc<Double>();
      final status = safe_divide(10.0, 0.0, resultPtr);
      expect(status, equals(-1));
      malloc.free(resultPtr);
    });

    test('sort_array sorts with callback', () {
      final arr = malloc<Int32>(3);
      arr[0] = 3; arr[1] = 1; arr[2] = 2;
      int compareAsc(int a, int b) => a - b;
      final callback = NativeCallable<SortCallback>.isolateLocal(compareAsc, exceptionalReturn: 0);
      sort_array(arr, 3, callback.nativeFunction);
      expect(arr[0], equals(1));
      expect(arr[1], equals(2));
      expect(arr[2], equals(3));
      callback.close();
      malloc.free(arr);
    });
  });

  group('rust_strings', () {
    test('to_uppercase converts string', () {
      final input = 'hello'.toNativeUtf8();
      final result = to_uppercase(input.cast());
      expect(result.toDartString(), equals('HELLO'));
      free_rust_string(result.cast());
      malloc.free(input);
    });

    test('opaque StringBuilder lifecycle', () {
      final sb = string_builder_new();
      expect(sb.address, isNot(0));

      final p1 = 'foo'.toNativeUtf8();
      final p2 = 'bar'.toNativeUtf8();
      string_builder_append(sb, p1.cast());
      string_builder_append(sb, p2.cast());
      expect(string_builder_count(sb), equals(2));

      final sep = ', '.toNativeUtf8();
      final result = string_builder_build(sb, sep.cast());
      expect(result.toDartString(), equals('foo, bar'));

      free_rust_string(result.cast());
      malloc.free(sep);
      malloc.free(p1);
      malloc.free(p2);
      string_builder_free(sb);
    });
  });
}
