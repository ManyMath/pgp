import 'package:ffi/ffi.dart';
import 'package:dart_cli_example/native.dart';

void main() {
  // Arithmetic
  print('Arithmetic: 2 + 3 = ${add(2, 3)}');

  // Structs
  final p1 = create_point(0, 0);
  final p2 = create_point(3, 4);
  print('Distance from (${p1.x}, ${p1.y}) to (${p2.x}, ${p2.y}) = ${distance(p1, p2)}');

  // Strings
  final input = 'Hello from Dart'.toNativeUtf8();
  final result = reverse_string(input.cast());
  print('Reversed: "${result.cast<Utf8>().toDartString()}"');
  free_rust_string(result);
  malloc.free(input);
}
