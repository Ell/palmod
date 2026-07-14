#include "palmod/hook_backend.hpp"

#include "palmod/reflection_backend.hpp"

#include <cstdlib>
#include <string_view>
#include <utility>

namespace palmod {

bool NoopHookBackend::install(const BuildProfile&, HookCallbacks,
                              std::string& error) {
  error.clear();
  return true;
}

bool NoopHookBackend::execute_action(const SemanticAction&, std::string& error) {
  error = "no-op hook backend cannot execute game actions";
  return false;
}

bool TestHookBackend::install(const BuildProfile&, HookCallbacks callbacks,
                              std::string&) {
  callbacks_ = std::move(callbacks);
  return true;
}

void TestHookBackend::uninstall() { callbacks_ = {}; }

bool TestHookBackend::execute_action(const SemanticAction& action,
                                     std::string&) {
  executed_.push_back(action);
  return true;
}

bool TestHookBackend::emit_chat(std::string_view text, std::string player,
                                std::uint64_t player_handle, int auth_state) {
  if (!callbacks_.on_chat) return false;
  return callbacks_.on_chat(text, std::move(player), player_handle, auth_state);
}

void TestHookBackend::emit_tick() {
  if (callbacks_.on_game_tick) callbacks_.on_game_tick();
}

void TestHookBackend::emit_player_join(std::string stable_id,
                                       std::string display_name,
                                       std::uint64_t handle) {
  if (callbacks_.on_player_join) {
    callbacks_.on_player_join(std::move(stable_id), std::move(display_name), handle);
  }
}

void TestHookBackend::emit_player_leave(std::string stable_id) {
  if (callbacks_.on_player_leave) callbacks_.on_player_leave(std::move(stable_id));
}

std::unique_ptr<HookBackend> make_default_hook_backend() {
  const char* requested = std::getenv("PALMOD_HOOK_BACKEND");
  if (requested != nullptr && std::string_view(requested) == "reflection") {
    // Preferred production approach: data-pointer (reflection/vtable) hooks.
    // Fails closed at install time until a validated reflection layout exists.
    return std::make_unique<ReflectionHookBackend>();
  }
  if (requested != nullptr && std::string_view(requested) == "frida-gum-passive") {
#if PALMOD_HAS_FRIDA_GUM
    return make_frida_gum_hook_backend();
#else
    class Unavailable final : public HookBackend {
     public:
      std::string_view name() const override { return "frida-gum-unavailable"; }
      bool install(const BuildProfile&, HookCallbacks, std::string& error) override {
        error = "PALMOD_HOOK_BACKEND requested Frida Gum, but the loader was built without PALMOD_FRIDA_GUM_ROOT";
        return false;
      }
      bool execute_action(const SemanticAction&, std::string& error) override {
        error = "Frida Gum backend is unavailable";
        return false;
      }
      void uninstall() override {}
    };
    return std::make_unique<Unavailable>();
#endif
  }
  return std::make_unique<NoopHookBackend>();
}

}  // namespace palmod
