#pragma once

#include "palmod/parms_decode.hpp"
#include "palmod/parms_encode.hpp"  // ParamInput

#include <cstdint>
#include <string>
#include <vector>

namespace palmod {

enum class AuthState : std::uint8_t { Unknown = 0, Player = 1, Admin = 2 };
enum class PrincipalKind : std::uint8_t { InGamePlayer = 0, LocalOperator = 1 };

struct CommandInvocation {
  std::string plugin_id;
  std::string command;
  std::vector<std::string> args;
  std::string raw;
  std::string player;
  std::uint64_t player_handle{0};
  AuthState auth{AuthState::Unknown};
  PrincipalKind principal{PrincipalKind::InGamePlayer};
  std::uint32_t operator_uid{0};
};

// An immutable, asynchronous event snapshot delivered to subscribed plugins.
// Every game hook decodes its payload into one of these (chat, player join, ...);
// a plugin reacts off the game thread and may emit semantic actions. `kind`
// names the event; the flat fields are a typed payload whose meaning depends on
// the kind (for "chat": source=sender, text=message). `args` carries the decoded
// named parameters for generic by-name hooks (empty for the flat/bespoke events);
// in Lua it surfaces as `event.args[name] = value`.
struct PluginEvent {
  std::string kind;
  std::uint64_t sequence{0};
  std::string source;
  std::string text;
  std::string subject;
  std::uint64_t handle{0};
  std::int64_t number{0};
  std::vector<EventArg> args;
};

// A game-thread action a plugin requests. There is one, generic kind: call a
// UFunction by name. `function_path` is its UE path, `target_class` the class of
// the object to call it on (first live instance), and `call_args` the arguments
// as a value tree, encoded on the game thread from the function's live layout.
enum class ActionKind : std::uint8_t { CallFunction = 1 };

struct SemanticAction {
  ActionKind kind{ActionKind::CallFunction};
  std::string source_plugin;
  std::string actor;
  std::uint64_t actor_handle{0};
  std::string function_path;
  std::string target_class;
  // A specific object handle to call on; when 0, the first live instance of
  // `target_class` is used.
  std::uint64_t target_object{0};
  std::vector<ParamInput> call_args;
};

}  // namespace palmod
