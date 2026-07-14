#pragma once

#include "palmod/types.hpp"

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace palmod {

enum class Permission { Everyone, ServerAdmin };

struct CommandSpec {
  std::string plugin_id;
  std::string name;
  Permission permission{Permission::Everyone};
  bool suppress{true};
};

struct ParsedCommand {
  std::string name;
  std::vector<std::string> args;
};

struct RouteResult {
  bool matched{false};
  bool suppress{false};
  bool dispatched{false};
  std::string error;
};

// Parses a leading-slash command from UTF-8 text. Palworld chat is UTF-16 on the
// wire, so the chat hook adapter must transcode UTF-16 -> UTF-8 before calling
// the router; the tokenizer here is deliberately byte-oriented UTF-8.
std::optional<ParsedCommand> parse_slash_command(std::string_view text,
                                                 std::string& error);

class CommandRouter {
 public:
  using Dispatcher = std::function<bool(CommandInvocation)>;

  bool register_command(CommandSpec command, std::string& error);
  RouteResult route(std::string_view text, std::string player,
                    std::uint64_t player_handle, AuthState auth,
                    const Dispatcher& dispatch) const;
  std::size_t command_count() const { return commands_.size(); }

 private:
  static std::string canonical(std::string_view name);
  std::map<std::string, CommandSpec, std::less<>> commands_;
};

}  // namespace palmod
