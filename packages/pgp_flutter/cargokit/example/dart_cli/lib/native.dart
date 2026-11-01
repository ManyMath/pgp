import 'dart:ffi';
import 'package:ffi/ffi.dart';

final class Point extends Struct {
  @Double()
  external double x;

  @Double()
  external double y;
}

@Native<Int32 Function(Int32, Int32)>()
external int add(int a, int b);

@Native<Point Function(Double, Double)>()
external Point create_point(double x, double y);

@Native<Double Function(Point, Point)>()
external double distance(Point a, Point b);

@Native<Pointer<Utf8> Function(Pointer<Utf8>)>()
external Pointer<Utf8> reverse_string(Pointer<Utf8> input);

@Native<Void Function(Pointer<Utf8>)>()
external void free_rust_string(Pointer<Utf8> s);
