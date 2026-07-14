#include "palmod/action_queue.hpp"
#include "palmod/command_router.hpp"
#include "palmod/json.hpp"
#include "palmod/player_directory.hpp"
#include "palmod/plugin_runtime.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

int main() {
  palmod::ActionQueue game_actions;
  palmod::CommandRouter command_router;
  palmod::PluginRuntime plugins(game_actions);
  palmod::PlayerDirectory players;
  std::string directory_error;
  if (!players.upsert("steam_76561190000000001", "Alice", 0x100000001ULL,
                      directory_error)) {
    std::cerr << "failed to register fake player: " << directory_error << '\n';
    return 1;
  }
  const auto loaded = plugins.load_directory(PALMOD_TEST_PLUGIN_DIR, command_router);
  if (!palmod::PluginRuntime::lua_available()) {
    std::cerr << "Lua 5.4 support disabled; fake server cannot execute plugins\n";
    return loaded == 0 ? 0 : 1;
  }
  if (loaded != 3) {  // give_item + find_item (commands) + hook_watch (pal.hook)
    std::cerr << "expected three reference plugins, loaded " << loaded << '\n';
    return 1;
  }

  const auto route = command_router.route(
      "/GiveItem PalSphere_Mega Alice 3", "LabAdmin", 0x100000001ULL,
      palmod::AuthState::Admin,
      [&](palmod::CommandInvocation invocation) {
        return plugins.dispatch(std::move(invocation));
      });
  if (!route.matched || !route.suppress || !route.dispatched ||
      !plugins.wait_idle(std::chrono::seconds(2))) {
    std::cerr << "command did not reach the plugin: " << route.error << '\n';
    return 1;
  }

  game_actions.bind_game_thread();
  std::vector<palmod::SemanticAction> executed;
  game_actions.drain([&](const palmod::SemanticAction& action) {
    executed.push_back(action);
  });
  // The plugin issues generic UFunction calls by name; pick out the AddItem
  // grant and read its item id + count out of the call arguments.
  const palmod::SemanticAction* add_item = nullptr;
  for (const auto& action : executed) {
    if (action.kind == palmod::ActionKind::CallFunction &&
        action.function_path.find("AddItem_ServerInternal") != std::string::npos) {
      add_item = &action;
    }
  }
  std::string item_id;
  std::int64_t count = 0;
  if (add_item != nullptr) {
    for (const auto& arg : add_item->call_args) {
      if (arg.name == "StaticItemId") item_id = arg.text;
      if (arg.name == "Count") count = static_cast<std::int64_t>(arg.number);
    }
  }
  if (add_item == nullptr || item_id != "PalSphere_Mega" || count != 3) {
    std::cerr << "reference plugin emitted an unexpected action\n";
    return 1;
  }

  // The PlayerDirectory stays a reusable primitive (resolve a display name to an
  // authoritative player) for future per-target calls; demonstrate it here.
  const auto resolution = players.resolve("Alice");
  if (resolution.status != palmod::ResolveStatus::Resolved) {
    std::cerr << "player resolution failed for Alice\n";
    return 1;
  }

  palmod::json::Object output;
  output.emplace("event", "fake_server.give_item");
  output.emplace("item_id", item_id);
  output.emplace("resolved_stable_id", resolution.player.stable_id);
  output.emplace("resolved_handle",
                 static_cast<std::int64_t>(resolution.player.handle));
  output.emplace("count", count);
  output.emplace("source_plugin", add_item->source_plugin);
  std::cout << palmod::json::stringify(palmod::json::Value{std::move(output)}) << '\n';
  return 0;
}
