#pragma once

#include "palmod/build_profile.hpp"
#include "palmod/generic_hook.hpp"
#include "palmod/types.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace palmod {

struct HookCallbacks {
  std::function<bool(std::string_view, std::string, std::uint64_t, int)> on_chat;
  std::function<void()> on_game_tick;
  std::function<void(std::string, std::string, std::uint64_t)> on_player_join;
  std::function<void(std::string)> on_player_leave;
  // A game hook decodes its payload into a PluginEvent and calls this to fan it
  // out to subscribed plugins (async). This is the generic event-delivery seam.
  std::function<void(const PluginEvent&)> on_event;
};

class HookBackend {
 public:
  virtual ~HookBackend() = default;
  virtual std::string_view name() const = 0;
  virtual bool install(const BuildProfile& profile, HookCallbacks callbacks,
                       std::string& error) = 0;
  virtual bool execute_action(const SemanticAction& action,
                              std::string& error) = 0;
  virtual void uninstall() = 0;

  // Install a reflection hook on an arbitrary UFunction by its recovered spec
  // (thunk VA + Parms layout), delivering decoded calls as PluginEvents through
  // the callbacks passed to install(). Backends that cannot do reflection hooks
  // fail closed. Called by the runtime for each function a plugin subscribes to;
  // the reflection backend resolves it live by name (no baked catalog).
  virtual bool install_generic_hook(const GenericHookSpec& /*spec*/,
                                    std::string& error) {
    error = "hook backend does not support generic by-name hooks";
    return false;
  }
};

class NoopHookBackend final : public HookBackend {
 public:
  std::string_view name() const override { return "noop"; }
  bool install(const BuildProfile&, HookCallbacks, std::string& error) override;
  bool execute_action(const SemanticAction&, std::string& error) override;
  void uninstall() override {}
};

class TestHookBackend final : public HookBackend {
 public:
  std::string_view name() const override { return "test"; }
  bool install(const BuildProfile&, HookCallbacks callbacks,
               std::string& error) override;
  bool execute_action(const SemanticAction& action, std::string& error) override;
  void uninstall() override;
  bool emit_chat(std::string_view text, std::string player,
                 std::uint64_t player_handle, int auth_state);
  void emit_tick();
  void emit_player_join(std::string stable_id, std::string display_name,
                        std::uint64_t handle);
  void emit_player_leave(std::string stable_id);
  std::vector<SemanticAction> executed_actions() const { return executed_; }

 private:
  HookCallbacks callbacks_;
  std::vector<SemanticAction> executed_;
};

std::unique_ptr<HookBackend> make_default_hook_backend();

#if PALMOD_HAS_FRIDA_GUM
std::unique_ptr<HookBackend> make_frida_gum_hook_backend();
#endif

}  // namespace palmod
