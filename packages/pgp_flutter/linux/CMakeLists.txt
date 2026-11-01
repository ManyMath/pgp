# Builds the shared `pgp_ffi` Rust crate via cargokit and bundles the
# resulting libpgp_ffi.so with the Flutter app.
cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "pgp_flutter")
project(${PROJECT_NAME} LANGUAGES CXX)

include("${CMAKE_CURRENT_SOURCE_DIR}/../cargokit/cmake/cargokit.cmake")

# apply_cargokit(<target> <manifest_dir, relative to this file> <lib_name> <force-link symbol>)
# The crate lives in ../rust so it ships with the published package.
apply_cargokit(${PROJECT_NAME} ../rust pgp_ffi "")

set(pgp_flutter_bundled_libraries
  "${${PROJECT_NAME}_cargokit_lib}"
  PARENT_SCOPE
)
