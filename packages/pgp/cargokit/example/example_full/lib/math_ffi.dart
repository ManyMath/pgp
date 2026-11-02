import 'dart:ffi';

final class Vec2 extends Struct {
  @Double()
  external double x;

  @Double()
  external double y;
}

@Native<Vec2 Function(Vec2, Vec2)>()
external Vec2 vec2_add(Vec2 a, Vec2 b);

@Native<Double Function(Vec2)>()
external double vec2_length(Vec2 v);

typedef SortCallback = Int32 Function(Int32, Int32);

@Native<Void Function(Pointer<Int32>, Int32, Pointer<NativeFunction<SortCallback>>)>()
external void sort_array(Pointer<Int32> arr, int len, Pointer<NativeFunction<SortCallback>> cmp);

@Native<Int32 Function(Double, Double, Pointer<Double>)>()
external int safe_divide(double a, double b, Pointer<Double> result);
