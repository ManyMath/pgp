import 'dart:ffi';
import 'package:ffi/ffi.dart';

@Native<Pointer<Utf8> Function(Pointer<Utf8>)>()
external Pointer<Utf8> to_uppercase(Pointer<Utf8> input);

@Native<Void Function(Pointer<Utf8>)>()
external void free_rust_string(Pointer<Utf8> s);

final class OpaqueStringBuilder extends Opaque {}

@Native<Pointer<OpaqueStringBuilder> Function()>()
external Pointer<OpaqueStringBuilder> string_builder_new();

@Native<Void Function(Pointer<OpaqueStringBuilder>, Pointer<Utf8>)>()
external void string_builder_append(Pointer<OpaqueStringBuilder> ptr, Pointer<Utf8> s);

@Native<Int32 Function(Pointer<OpaqueStringBuilder>)>()
external int string_builder_count(Pointer<OpaqueStringBuilder> ptr);

@Native<Pointer<Utf8> Function(Pointer<OpaqueStringBuilder>, Pointer<Utf8>)>()
external Pointer<Utf8> string_builder_build(Pointer<OpaqueStringBuilder> ptr, Pointer<Utf8> separator);

@Native<Void Function(Pointer<OpaqueStringBuilder>)>()
external void string_builder_free(Pointer<OpaqueStringBuilder> ptr);
