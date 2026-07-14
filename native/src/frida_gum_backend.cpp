#include "palmod/hook_backend.hpp"

#include "palmod/json_log.hpp"

#include <frida-gum.h>

#include <cstdint>
#include <exception>
#include <utility>

namespace palmod {
namespace {

class FridaGumHookBackend final : public HookBackend {
 public:
  std::string_view name() const override { return "frida-gum-passive"; }

  bool install(const BuildProfile& profile, HookCallbacks callbacks,
               std::string& error) override {
    const auto tick = profile.hooks.find("game_tick");
    if (tick == profile.hooks.end()) {
      error = "validated profile lacks the game_tick anchor required by the passive Gum adapter";
      return false;
    }
    callbacks_ = std::move(callbacks);
    gum_init_embedded();
    gum_initialized_ = true;
    interceptor_ = gum_interceptor_obtain();
    listener_ = gum_make_probe_listener(on_tick, this, nullptr);
    const std::uint64_t absolute = profile.image_base + tick->second.rva;
    gum_interceptor_begin_transaction(interceptor_);
    const auto attached = gum_interceptor_attach(
        interceptor_, GSIZE_TO_POINTER(static_cast<gsize>(absolute)), listener_,
        nullptr, GUM_ATTACH_FLAGS_NONE);
    gum_interceptor_end_transaction(interceptor_);
    if (attached != GUM_ATTACH_OK) {
      error = "gum_interceptor_attach(game_tick) failed with code " +
              std::to_string(static_cast<int>(attached));
      uninstall();
      return false;
    }
    attached_ = true;
    JsonLog::instance().write(
        JsonLog::Level::Warn, "hook.passive_only",
        "Frida Gum game-tick probe installed; chat decoding and mutation remain disabled until their ABI is validated");
    return true;
  }

  bool execute_action(const SemanticAction&, std::string& error) override {
    error = "passive Frida Gum adapter cannot execute semantic actions; a validated Palworld ABI adapter is required";
    return false;
  }

  void uninstall() override {
    if (attached_ && interceptor_ && listener_) {
      gum_interceptor_detach(interceptor_, listener_);
      attached_ = false;
    }
    if (listener_) {
      g_object_unref(listener_);
      listener_ = nullptr;
    }
    if (interceptor_) {
      g_object_unref(interceptor_);
      interceptor_ = nullptr;
    }
    callbacks_ = {};
    if (gum_initialized_) {
      gum_deinit_embedded();
      gum_initialized_ = false;
    }
  }

  ~FridaGumHookBackend() override { uninstall(); }

 private:
  static void on_tick(GumInvocationContext*, gpointer opaque) {
    auto* self = static_cast<FridaGumHookBackend*>(opaque);
    try {
      if (self->callbacks_.on_game_tick) self->callbacks_.on_game_tick();
    } catch (const std::exception& failure) {
      JsonLog::instance().write(JsonLog::Level::Error, "hook.callback_exception",
                                failure.what());
    } catch (...) {
      JsonLog::instance().write(JsonLog::Level::Error, "hook.callback_exception",
                                "unknown exception escaped a game-tick callback");
    }
  }

  HookCallbacks callbacks_;
  GumInterceptor* interceptor_{nullptr};
  GumInvocationListener* listener_{nullptr};
  bool gum_initialized_{false};
  bool attached_{false};
};

}  // namespace

std::unique_ptr<HookBackend> make_frida_gum_hook_backend() {
  return std::make_unique<FridaGumHookBackend>();
}

}  // namespace palmod
