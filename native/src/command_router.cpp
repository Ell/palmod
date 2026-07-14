#include "palmod/command_router.hpp"

#include <algorithm>
#include <cctype>

namespace palmod {

std::optional<ParsedCommand> parse_slash_command(std::string_view text,
                                                 std::string& error) {
  if (text.empty() || text.front() != '/') return std::nullopt;
  if (text.size() > 2048) {
    error = "command exceeds 2048 bytes";
    return std::nullopt;
  }
  std::vector<std::string> tokens;
  std::string current;
  bool quoted = false;
  bool escaped = false;
  auto flush = [&]() {
    if (!current.empty()) {
      tokens.push_back(std::move(current));
      current.clear();
    }
  };
  for (std::size_t i = 1; i < text.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if (c == 0 || (c < 0x20U && c != '\t')) {
      error = "command contains a control byte";
      return std::nullopt;
    }
    if (escaped) {
      if (c != '\\' && c != '"' && c != ' ') {
        error = "unsupported command escape";
        return std::nullopt;
      }
      current.push_back(static_cast<char>(c));
      escaped = false;
    } else if (c == '\\') {
      escaped = true;
    } else if (c == '"') {
      quoted = !quoted;
    } else if (!quoted && std::isspace(c) != 0) {
      flush();
    } else {
      current.push_back(static_cast<char>(c));
      if (current.size() > 512) {
        error = "command token exceeds 512 bytes";
        return std::nullopt;
      }
    }
    if (tokens.size() > 32) {
      error = "command has too many arguments";
      return std::nullopt;
    }
  }
  if (escaped || quoted) {
    error = escaped ? "trailing command escape" : "unterminated command quote";
    return std::nullopt;
  }
  flush();
  if (tokens.empty()) {
    error = "empty slash command";
    return std::nullopt;
  }
  ParsedCommand command;
  command.name = std::move(tokens.front());
  command.args.assign(std::make_move_iterator(tokens.begin() + 1),
                      std::make_move_iterator(tokens.end()));
  return command;
}

std::string CommandRouter::canonical(std::string_view name) {
  std::string result(name);
  std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return result;
}

bool CommandRouter::register_command(CommandSpec command, std::string& error) {
  if (command.name.empty() || command.name.size() > 32 ||
      !std::isalpha(static_cast<unsigned char>(command.name.front()))) {
    error = "invalid command name: " + command.name;
    return false;
  }
  for (const unsigned char c : command.name) {
    if (std::isalnum(c) == 0 && c != '_' && c != '-') {
      error = "invalid command name: " + command.name;
      return false;
    }
  }
  const auto key = canonical(command.name);
  if (!commands_.emplace(key, std::move(command)).second) {
    error = "duplicate command: " + key;
    return false;
  }
  return true;
}

RouteResult CommandRouter::route(std::string_view text, std::string player,
                                 std::uint64_t player_handle, AuthState auth,
                                 const Dispatcher& dispatch) const {
  std::string parse_error;
  auto parsed = parse_slash_command(text, parse_error);
  if (!parsed) return {false, false, false, std::move(parse_error)};
  const auto found = commands_.find(canonical(parsed->name));
  if (found == commands_.end()) return {};
  const auto& spec = found->second;
  RouteResult result{true, spec.suppress, false, {}};
  if (spec.permission == Permission::ServerAdmin && auth != AuthState::Admin) {
    result.error = "server administrator permission required";
    return result;
  }
  CommandInvocation invocation;
  invocation.plugin_id = spec.plugin_id;
  invocation.command = spec.name;
  invocation.args = std::move(parsed->args);
  invocation.raw = std::string(text);
  invocation.player = std::move(player);
  invocation.player_handle = player_handle;
  invocation.auth = auth;
  result.dispatched = dispatch(std::move(invocation));
  if (!result.dispatched) result.error = "plugin command queue rejected invocation";
  return result;
}

}  // namespace palmod
