# Embed a Lua source file into a C++ header as a raw-string constant.
# Script-mode use: cmake -DINPUT=<lua> -DOUTPUT=<hpp> -DVAR=<name> -P embed_lua.cmake
#
# Kept as a build-time codegen step (with DEPENDS on the .lua) so the stdlib is
# authored as real Lua yet ships compiled into the loader — always available to
# every plugin, with no runtime file-path dependency.

file(READ "${INPUT}" _lua)
if(_lua MATCHES "\\)PALMODLUA\"")
  message(FATAL_ERROR "embed_lua: ${INPUT} contains the raw-string delimiter )PALMODLUA\"")
endif()
get_filename_component(_name "${INPUT}" NAME)
file(WRITE "${OUTPUT}"
"// Generated from ${_name} by embed_lua.cmake. Do not edit by hand.
#pragma once
namespace palmod {
inline constexpr char ${VAR}[] = R\"PALMODLUA(${_lua})PALMODLUA\";
}  // namespace palmod
")
