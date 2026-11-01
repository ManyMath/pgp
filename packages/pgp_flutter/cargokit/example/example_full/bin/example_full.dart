import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:example_full/math_ffi.dart';
import 'package:example_full/strings_ffi.dart';

void main() {
  print('=== rust_math crate ===');

  // Vec2 struct operations
  final aPtr = malloc<Vec2>();
  aPtr.ref.x = 1.0;
  aPtr.ref.y = 2.0;
  final bPtr = malloc<Vec2>();
  bPtr.ref.x = 3.0;
  bPtr.ref.y = 4.0;
  final sum = vec2_add(aPtr.ref, bPtr.ref);
  print('Vec2 add: (${aPtr.ref.x},${aPtr.ref.y}) + (${bPtr.ref.x},${bPtr.ref.y}) = (${sum.x},${sum.y})');
  final lenPtr = malloc<Vec2>();
  lenPtr.ref.x = 3.0;
  lenPtr.ref.y = 4.0;
  print('Vec2 length of (3,4): ${vec2_length(lenPtr.ref)}');
  malloc.free(aPtr);
  malloc.free(bPtr);
  malloc.free(lenPtr);

  // Error code pattern
  final resultPtr = malloc<Double>();
  final status = safe_divide(10.0, 3.0, resultPtr);
  print('safe_divide(10, 3): status=$status, result=${resultPtr.value}');
  final errStatus = safe_divide(10.0, 0.0, resultPtr);
  print('safe_divide(10, 0): status=$errStatus (error)');
  malloc.free(resultPtr);

  // Callback pattern
  final arr = malloc<Int32>(4);
  arr[0] = 3; arr[1] = 1; arr[2] = 4; arr[3] = 2;
  int compareAsc(int a, int b) => a - b;
  final callback = NativeCallable<SortCallback>.isolateLocal(compareAsc, exceptionalReturn: 0);
  sort_array(arr, 4, callback.nativeFunction);
  print('Sorted: [${arr[0]}, ${arr[1]}, ${arr[2]}, ${arr[3]}]');
  callback.close();
  malloc.free(arr);

  print('');
  print('=== rust_strings crate ===');

  // String interchange
  final input = 'hello world'.toNativeUtf8();
  final upper = to_uppercase(input.cast());
  print('Uppercase: "${upper.toDartString()}"');
  free_rust_string(upper.cast());
  malloc.free(input);

  // Opaque pointer lifecycle
  final sb = string_builder_new();
  final p1 = 'Hello'.toNativeUtf8();
  final p2 = 'from'.toNativeUtf8();
  final p3 = 'Rust'.toNativeUtf8();
  string_builder_append(sb, p1.cast());
  string_builder_append(sb, p2.cast());
  string_builder_append(sb, p3.cast());
  print('StringBuilder parts: ${string_builder_count(sb)}');
  final sep = ' '.toNativeUtf8();
  final built = string_builder_build(sb, sep.cast());
  print('Built string: "${built.toDartString()}"');
  free_rust_string(built.cast());
  malloc.free(sep);
  malloc.free(p1); malloc.free(p2); malloc.free(p3);
  string_builder_free(sb);
}
