#include "palmod/runtime.hpp"

#include <cstdlib>

namespace {

__attribute__((constructor(200))) void palmod_bootstrap() {
  const char* disabled = std::getenv("PALMOD_DISABLE_AUTOLOAD");
  if (disabled != nullptr && disabled[0] == '1' && disabled[1] == '\0') return;
  palmod::start_process_runtime_async();
}

}  // namespace
