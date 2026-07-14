cmake_minimum_required(VERSION 3.24)

project(palmod_native VERSION 0.1.0 LANGUAGES CXX)

option(PALMOD_BUILD_TESTS "Build the native test harness" ON)
option(PALMOD_REQUIRE_LUA "Fail configuration when Lua 5.4 is unavailable" OFF)
set(PALMOD_FRIDA_GUM_ROOT "" CACHE PATH "Pinned Frida Gum devkit directory (opt-in)")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LUA54 IMPORTED_TARGET lua5.4)
endif()

if(PALMOD_REQUIRE_LUA AND NOT LUA54_FOUND)
  message(FATAL_ERROR "Lua 5.4 was requested but pkg-config could not find lua5.4")
endif()

# --- Embed the Lua standard library into the loader -------------------------
# sdk/lua/stdlib.lua is authored as real Lua but compiled into libpalmod so the
# helpers (palmod.reply / broadcast / paginate / ...) are always available to
# every plugin with no runtime file dependency. DEPENDS makes edits recompile.
set(PALMOD_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(PALMOD_STDLIB_LUA "${CMAKE_CURRENT_SOURCE_DIR}/../sdk/lua/stdlib.lua")
set(PALMOD_STDLIB_HEADER "${PALMOD_GENERATED_DIR}/palmod/generated/plugin_stdlib_lua.hpp")
add_custom_command(
  OUTPUT "${PALMOD_STDLIB_HEADER}"
  COMMAND "${CMAKE_COMMAND}"
    "-DINPUT=${PALMOD_STDLIB_LUA}"
    "-DOUTPUT=${PALMOD_STDLIB_HEADER}"
    "-DVAR=kPluginStdlibLua"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_lua.cmake"
  DEPENDS "${PALMOD_STDLIB_LUA}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_lua.cmake"
  COMMENT "Embedding Lua stdlib ${PALMOD_STDLIB_LUA}"
  VERBATIM
)
add_custom_target(palmod_stdlib_header DEPENDS "${PALMOD_STDLIB_HEADER}")

add_library(palmod_core STATIC
  src/action_queue.cpp
  src/build_profile.cpp
  src/chat_message.cpp
  src/chat_hook.cpp
  src/command_router.cpp
  src/control_server.cpp
  src/fingerprint.cpp
  src/fname_pool.cpp
  src/generic_call.cpp
  src/generic_hook.cpp
  src/hook_backend.cpp
  src/invoke.cpp
  src/json.cpp
  src/json_log.cpp
  src/object_array.cpp
  src/object_walk.cpp
  src/parms_decode.cpp
  src/parms_encode.cpp
  src/reflect_layout.cpp
  src/reflection_reader.cpp
  src/player_auth.cpp
  src/player_directory.cpp
  src/plugin_runtime.cpp
  src/reflection_backend.cpp
  src/reflection_resolver.cpp
  src/utf16.cpp
  src/runtime.cpp
  src/sha256.cpp
)

target_include_directories(palmod_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/include
  PRIVATE
    ${PALMOD_GENERATED_DIR}
)
add_dependencies(palmod_core palmod_stdlib_header)
target_link_libraries(palmod_core PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(palmod_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

if(LUA54_FOUND)
  target_compile_definitions(palmod_core PUBLIC PALMOD_HAS_LUA=1)
  target_link_libraries(palmod_core PUBLIC PkgConfig::LUA54)
else()
  target_compile_definitions(palmod_core PUBLIC PALMOD_HAS_LUA=0)
  message(STATUS "Lua 5.4 not found: plugin execution will be explicitly disabled")
endif()

if(PALMOD_FRIDA_GUM_ROOT)
  if(NOT EXISTS "${PALMOD_FRIDA_GUM_ROOT}/frida-gum.h" OR
     NOT EXISTS "${PALMOD_FRIDA_GUM_ROOT}/libfrida-gum.a")
    message(FATAL_ERROR "PALMOD_FRIDA_GUM_ROOT does not contain the pinned Gum devkit")
  endif()
  target_sources(palmod_core PRIVATE src/frida_gum_backend.cpp)
  target_include_directories(palmod_core SYSTEM PRIVATE "${PALMOD_FRIDA_GUM_ROOT}")
  target_link_libraries(palmod_core PUBLIC
    "${PALMOD_FRIDA_GUM_ROOT}/libfrida-gum.a" rt resolv m
  )
  target_compile_definitions(palmod_core PUBLIC PALMOD_HAS_FRIDA_GUM=1)
else()
  target_compile_definitions(palmod_core PUBLIC PALMOD_HAS_FRIDA_GUM=0)
endif()

add_library(palmod_loader SHARED src/bootstrap.cpp)
target_link_libraries(palmod_loader PRIVATE palmod_core)
set_target_properties(palmod_loader PROPERTIES
  OUTPUT_NAME palmod
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
)

include(GNUInstallDirs)
install(TARGETS palmod_loader LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(PALMOD_BUILD_TESTS)
  enable_testing()
  add_executable(palmod_native_tests tests/native_tests.cpp)
  target_link_libraries(palmod_native_tests PRIVATE palmod_core)
  target_link_options(palmod_native_tests PRIVATE -no-pie)
  target_compile_definitions(palmod_native_tests PRIVATE
    PALMOD_TEST_PLUGIN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../plugins"
  )
  add_test(NAME palmod_native_tests COMMAND palmod_native_tests)

  add_executable(palmod_fake_server tests/fake_server.cpp)
  target_link_libraries(palmod_fake_server PRIVATE palmod_core)
  target_compile_definitions(palmod_fake_server PRIVATE
    PALMOD_TEST_PLUGIN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../plugins"
  )
  add_test(NAME palmod_fake_server COMMAND palmod_fake_server)
endif()
