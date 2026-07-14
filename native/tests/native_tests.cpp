#include "palmod/action_queue.hpp"
#include "palmod/build_profile.hpp"
#include "palmod/command_router.hpp"
#include "palmod/control_server.hpp"
#include "palmod/fingerprint.hpp"
#include "palmod/handle_table.hpp"
#include "palmod/player_directory.hpp"
#include "palmod/plugin_runtime.hpp"
#include "palmod/reflection_backend.hpp"
#include "palmod/chat_hook.hpp"
#include "palmod/chat_message.hpp"
#include "palmod/fname_pool.hpp"
#include "palmod/generic_call.hpp"
#include "palmod/generic_hook.hpp"
#include "palmod/invoke.hpp"
#include "palmod/object_array.hpp"
#include "palmod/object_walk.hpp"
#include "palmod/parms_decode.hpp"
#include "palmod/parms_encode.hpp"
#include "palmod/player_auth.hpp"
#include "palmod/reflection_resolver.hpp"
#include "palmod/runtime.hpp"
#include "palmod/utf16.hpp"
#include "palmod/sha256.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {

int failures = 0;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: "          \
                << #condition << '\n';                                         \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

std::string profile_json(const palmod::BuildFingerprint& fingerprint,
                         std::string_view status = "validated",
                         std::string_view capabilities =
                             "\"inventory.give\",\"chat.send\"",
                         std::string_view reflection = "",
                         std::string_view functions = "") {
  return "{\"schema\":1,\"status\":\"" + std::string(status) +
      "\",\"profile_id\":\"test-profile\",\"steam_build_id\":\"test\","
      "\"elf\":{\"sha256\":\"" + fingerprint.sha256 +
      "\",\"build_id\":\"" + fingerprint.elf_build_id +
      "\",\"machine\":\"x86_64\",\"bits\":64,\"endian\":\"little\","
      "\"elf_type\":\"ET_EXEC\",\"image_base\":4194304,\"file_size\":" +
      std::to_string(fingerprint.size) +
      "},\"anchors\":{\"test\":{\"rva\":0,\"expected_bytes\":\"7f 45 4c 46\","
      "\"validators\":[\"fixture\"]}},\"functions\":{" + std::string(functions) +
      "},\"capabilities\":[" +
      std::string(capabilities) + "]" + std::string(reflection) + "}";
}

std::string sha256_text(std::string_view text) {
  palmod::Sha256 hash;
  hash.update(std::as_bytes(std::span(text.data(), text.size())));
  return palmod::hex(hash.finish());
}

int sealed_memfd(std::string_view contents) {
  const int fd = memfd_create("palmod-test-profile", MFD_ALLOW_SEALING);
  if (fd < 0) return -1;
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count = write(fd, contents.data() + offset, contents.size() - offset);
    if (count <= 0) {
      close(fd);
      return -1;
    }
    offset += static_cast<std::size_t>(count);
  }
  const int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
  if (fcntl(fd, F_ADD_SEALS, seals) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

void test_sha256() {
  palmod::Sha256 hash;
  const std::string input = "abc";
  hash.update(std::as_bytes(std::span(input.data(), input.size())));
  CHECK(palmod::hex(hash.finish()) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void test_fingerprint_and_profile() {
  const auto result = palmod::fingerprint_self();
  CHECK(result.fingerprint.has_value());
  if (!result.fingerprint) return;
  std::string error;
  auto profile = palmod::BuildProfile::parse_json(profile_json(*result.fingerprint), error);
  CHECK(profile.has_value());
  CHECK(error.empty());
  std::string mismatch;
  CHECK(profile && profile->exactly_matches(*result.fingerprint, mismatch));
  auto candidate = palmod::BuildProfile::parse_json(
      profile_json(*result.fingerprint, "candidate"), error);
  CHECK(candidate.has_value());
  CHECK(candidate && !candidate->exactly_matches(*result.fingerprint, mismatch));
}

void test_handles() {
  palmod::HandleTable<std::string> table;
  const auto first = table.insert("first");
  CHECK(first != 0);
  CHECK(table.get(first) == std::optional<std::string>{"first"});
  CHECK(table.erase(first));
  CHECK(!table.get(first));
  const auto second = table.insert("second");
  CHECK(second != first);
  CHECK(!table.erase(first));
  CHECK(table.get(second) == std::optional<std::string>{"second"});
}

void test_player_directory() {
  palmod::PlayerDirectory directory;
  std::string error;
  CHECK(directory.upsert("steam_1", "Alice", 11, error));
  CHECK(directory.upsert("steam_2", "Bob", 22, error));
  CHECK(directory.upsert("steam_3", "Bob", 33, error));  // duplicate display name
  CHECK(error.empty());
  CHECK(directory.size() == 3);

  // A unique display name resolves to its owner's stable id.
  const auto alice = directory.resolve("Alice");
  CHECK(alice.status == palmod::ResolveStatus::Resolved);
  CHECK(alice.player.stable_id == "steam_1");
  CHECK(alice.player.handle == 11);

  // An exact stable id resolves even though it is not a display name.
  const auto by_id = directory.resolve("steam_2");
  CHECK(by_id.status == palmod::ResolveStatus::Resolved);
  CHECK(by_id.player.handle == 22);

  // A stable id wins over a colliding display name; the tool never guesses.
  CHECK(directory.upsert("Bob", "Zed", 44, error));  // stable id literally "Bob"
  const auto id_beats_name = directory.resolve("Bob");
  CHECK(id_beats_name.status == palmod::ResolveStatus::Resolved);
  CHECK(id_beats_name.player.stable_id == "Bob");
  CHECK(id_beats_name.player.handle == 44);
  CHECK(directory.remove("Bob"));

  // Without that stable id, "Bob" is an ambiguous display name and is refused.
  const auto ambiguous = directory.resolve("Bob");
  CHECK(ambiguous.status == palmod::ResolveStatus::Ambiguous);
  CHECK(ambiguous.candidate_count == 2);

  // Unknown or empty queries are refused, never coerced to a nearby player.
  CHECK(directory.resolve("Nobody").status == palmod::ResolveStatus::NotFound);
  CHECK(directory.resolve("").status == palmod::ResolveStatus::NotFound);

  // Identity fields are validated.
  CHECK(!directory.upsert("", "Nameless", 1, error));
  CHECK(!error.empty());
  CHECK(!directory.upsert("steam_9", "", 1, error));

  CHECK(directory.remove("steam_1"));
  CHECK(!directory.remove("steam_1"));
  CHECK(directory.size() == 2);
}

void test_command_parser() {
  std::string error;
  auto command = palmod::parse_slash_command(
      "/GiveItem Pal_Sphere \"Player One\" 4", error);
  CHECK(command.has_value());
  CHECK(command && command->name == "GiveItem");
  CHECK(command && command->args.size() == 3);
  CHECK(command && command->args[1] == "Player One");
  CHECK(!palmod::parse_slash_command("ordinary chat", error));
  CHECK(!palmod::parse_slash_command("/broken \"quote", error));
  CHECK(!error.empty());
}

void test_control_socket() {
  palmod::ControlServer server;
  const auto path = std::filesystem::temp_directory_path() /
                    ("palmod-test-" + std::to_string(getpid()) + ".sock");
  std::string error;
  CHECK(server.start(path, [](std::string_view packet, uid_t uid) {
    CHECK(uid == geteuid());
    return packet == "request" ? "response" : "unexpected";
  }, error));
  const int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  CHECK(fd >= 0);
  if (fd >= 0) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto encoded = path.string();
    std::memcpy(address.sun_path, encoded.c_str(), encoded.size() + 1);
    CHECK(connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    CHECK(send(fd, "request", 7, MSG_NOSIGNAL) == 7);
    std::array<char, 128> response{};
    const auto count = recv(fd, response.data(), response.size(), 0);
    CHECK(count == 8);
    CHECK(std::string_view(response.data(), static_cast<std::size_t>(count)) == "response");
    close(fd);
  }
  server.stop();
  CHECK(!std::filesystem::exists(path));
}

void test_environment_contract() {
  setenv(palmod::kEnvProfileFd, "19", 1);
  setenv(palmod::kEnvProfileSha256,
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
  setenv(palmod::kEnvPluginDirectory, "/tmp/palmod-plugins", 1);
  setenv(palmod::kEnvControlSocket, "/tmp/palmod.sock", 1);
  const auto config = palmod::Runtime::config_from_environment();
  CHECK(config.profile_fd == 19);
  CHECK(config.expected_profile_sha256.size() == 64);
  CHECK(config.plugin_directory == "/tmp/palmod-plugins");
  CHECK(config.control_socket == "/tmp/palmod.sock");
  unsetenv(palmod::kEnvProfileFd);
  unsetenv(palmod::kEnvProfileSha256);
  unsetenv(palmod::kEnvPluginDirectory);
  unsetenv(palmod::kEnvControlSocket);
}

void test_lua_give_item() {
  palmod::ActionQueue actions;
  palmod::CommandRouter commands;
  palmod::PluginRuntime plugins(actions);
  if (!palmod::PluginRuntime::lua_available()) {
    CHECK(plugins.load_directory(PALMOD_TEST_PLUGIN_DIR, commands) == 0);
    return;
  }
  // plugins/ ships give_item + find_item (commands) and hook_watch (pal.hook).
  CHECK(plugins.load_directory(PALMOD_TEST_PLUGIN_DIR, commands) == 3);

  auto non_admin = commands.route("/GiveItem Pal_Sphere Alice 2", "Operator", 7,
                                  palmod::AuthState::Player,
                                  [&](palmod::CommandInvocation invocation) {
                                    return plugins.dispatch(std::move(invocation));
                                  });
  CHECK(non_admin.matched);
  CHECK(non_admin.suppress);
  CHECK(!non_admin.dispatched);
  CHECK(actions.size() == 0);

  auto admin = commands.route("/GiveItem Pal_Sphere Alice 2", "Operator", 7,
                              palmod::AuthState::Admin,
                              [&](palmod::CommandInvocation invocation) {
                                return plugins.dispatch(std::move(invocation));
                              });
  CHECK(admin.matched && admin.suppress && admin.dispatched);
  CHECK(plugins.wait_idle(std::chrono::seconds(2)));
  std::vector<palmod::SemanticAction> executed;
  actions.bind_game_thread();
  actions.drain([&](const palmod::SemanticAction& action) {
    executed.push_back(action);
  });
  // The generic plugin emits two calls by name: AddItem_ServerInternal (the
  // grant) and BroadcastChatMessage (the confirmation). No bespoke action kind.
  const palmod::SemanticAction* add_item = nullptr;
  bool has_broadcast = false;
  for (const auto& action : executed) {
    if (action.kind != palmod::ActionKind::CallFunction) continue;
    if (action.function_path.find("AddItem_ServerInternal") != std::string::npos) {
      add_item = &action;
    }
    if (action.function_path.find("BroadcastChatMessage") != std::string::npos) {
      has_broadcast = true;
    }
  }
  CHECK(add_item != nullptr);
  CHECK(has_broadcast);
  if (add_item != nullptr) {
    CHECK(add_item->actor == "Operator");
    // The item id + count arrived as named call arguments.
    const palmod::ParamInput* item = nullptr;
    const palmod::ParamInput* count = nullptr;
    for (const auto& arg : add_item->call_args) {
      if (arg.name == "StaticItemId") item = &arg;
      if (arg.name == "Count") count = &arg;
    }
    CHECK(item != nullptr && item->is_text && item->text == "Pal_Sphere");
    CHECK(count != nullptr && count->number == 2.0);
  }
}

void test_sealed_profile_runtime() {
  if (!palmod::PluginRuntime::lua_available()) return;
  const auto fingerprint = palmod::fingerprint_self();
  CHECK(fingerprint.fingerprint.has_value());
  if (!fingerprint.fingerprint) return;
  const auto json = profile_json(*fingerprint.fingerprint);
  const int fd = sealed_memfd(json);
  CHECK(fd >= 3);
  if (fd < 3) return;

  auto backend = std::make_unique<palmod::TestHookBackend>();
  auto* test_backend = backend.get();
  palmod::Runtime runtime(std::move(backend));
  palmod::RuntimeConfig config;
  config.profile_fd = fd;
  config.expected_profile_sha256 = sha256_text(json);
  config.plugin_directory = std::filesystem::absolute(PALMOD_TEST_PLUGIN_DIR);
  config.enable_control = false;
  std::string error;
  CHECK(runtime.start(config, error));
  CHECK(error.empty());
  close(fd);
  if (runtime.state() != palmod::RuntimeState::Running) return;

  // A GiveItem command routes to the plugin, which issues a generic call to
  // AddItem_ServerInternal by name (encoded from the item id + count).
  CHECK(test_backend->emit_chat("/GiveItem PalSphere_Mega Bob", "Root", 99, 2));
  CHECK(runtime.wait_plugins_idle(std::chrono::seconds(2)));
  test_backend->emit_tick();
  const auto executed = test_backend->executed_actions();
  const palmod::SemanticAction* add_item = nullptr;
  for (const auto& a : executed) {
    if (a.kind == palmod::ActionKind::CallFunction &&
        a.function_path.find("AddItem_ServerInternal") != std::string::npos) {
      add_item = &a;
    }
  }
  CHECK(add_item != nullptr);
  if (add_item != nullptr) {
    const palmod::ParamInput* item = nullptr;
    const palmod::ParamInput* count = nullptr;
    for (const auto& arg : add_item->call_args) {
      if (arg.name == "StaticItemId") item = &arg;
      if (arg.name == "Count") count = &arg;
    }
    CHECK(item != nullptr && item->is_text && item->text == "PalSphere_Mega");
    CHECK(count != nullptr && count->number == 1.0);
  }
  runtime.stop();
}

int g_reflection_tick_calls = 0;
int g_reflection_original_calls = 0;
// Matches UEngine::Tick(this, float, bool) — the drain pump's hooked signature.
void fake_original_tick(void*, float, bool) { ++g_reflection_original_calls; }

void test_reflection_hook_backend() {
  // The pointer-swap primitive: atomically swap a slot and restore it.
  void* original_value = reinterpret_cast<void*>(0x1111);
  void* slot = original_value;
  palmod::PointerSlotHook hook;
  std::string error;
  CHECK(hook.install(&slot, reinterpret_cast<void*>(0x2222), error));
  CHECK(error.empty());
  CHECK(slot == reinterpret_cast<void*>(0x2222));
  CHECK(hook.original() == original_value);
  hook.uninstall();
  CHECK(slot == original_value);

  // The backend fails closed when no reflection layout is available.
  {
    palmod::ReflectionHookBackend backend;
    palmod::HookCallbacks callbacks;
    std::string install_error;
    CHECK(!backend.install(palmod::BuildProfile{}, std::move(callbacks), install_error));
    CHECK(!install_error.empty());
  }

  // With a simulated tick slot, install swaps the pointer so an engine call to
  // the slot routes through our game-thread callback and chains the original,
  // and uninstall restores the slot exactly.
  g_reflection_tick_calls = 0;
  g_reflection_original_calls = 0;
  using TickFn = void (*)(void*, float, bool);
  TickFn tick_slot = &fake_original_tick;
  palmod::ReflectionLayout layout;
  layout.tick_slot = reinterpret_cast<void**>(&tick_slot);
  palmod::ReflectionHookBackend backend(layout);
  palmod::HookCallbacks callbacks;
  callbacks.on_game_tick = [] { ++g_reflection_tick_calls; };
  std::string install_error;
  CHECK(backend.install(palmod::BuildProfile{}, std::move(callbacks), install_error));
  CHECK(install_error.empty());
  CHECK(tick_slot != &fake_original_tick);       // swapped to the trampoline
  tick_slot(nullptr, 0.016F, false);             // the engine "calls" GEngine->Tick
  CHECK(g_reflection_tick_calls == 1);      // our callback fired
  CHECK(g_reflection_original_calls == 1);  // original was chained

  // A generic call fails closed until the reflection facts are present.
  palmod::SemanticAction action;  // default kind is CallFunction
  std::string execute_error;
  CHECK(!backend.execute_action(action, execute_error));
  CHECK(!execute_error.empty());

  backend.uninstall();
  CHECK(tick_slot == &fake_original_tick);  // restored
}

// Write an FString {u16* data, i32 num, i32 max} into a buffer at `off`.
void write_fstring(std::uint8_t* base, std::size_t off, const char16_t* data,
                   std::int32_t num, std::int32_t max) {
  std::memcpy(base + off, &data, sizeof(data));
  std::memcpy(base + off + 8, &num, sizeof(num));
  std::memcpy(base + off + 12, &max, sizeof(max));
}

void test_chat_decode() {
  // Build a synthetic FPalChatMessage: sender FString @ +0x08, text @ +0x28.
  const std::u16string sender = u"Player";
  const std::u16string text = u"hello world";
  alignas(8) std::array<std::uint8_t, 0x40> message{};
  // num counts the null terminator (e.g. "Player" -> num 7).
  write_fstring(message.data(), 0x08, sender.c_str(), 7, 8);
  write_fstring(message.data(), 0x28, text.c_str(), 12, 16);

  const auto event = palmod::decode_chat_event(message.data());
  CHECK(event.has_value());
  CHECK(event && event->kind == "chat");
  CHECK(event && event->source == "Player");
  CHECK(event && event->text == "hello world");
  CHECK(!palmod::decode_chat_event(nullptr).has_value());
}

int g_chat_original_calls = 0;
void fake_broadcast_thunk(void*, void*, void*) { ++g_chat_original_calls; }

void test_chat_hook() {
  // --- handler core: FFrame.Locals -> FPalChatMessage -> chat event ---
  const std::u16string sender = u"Bob";
  const std::u16string text = u"hi there";
  alignas(8) std::array<std::uint8_t, 0x40> message{};
  write_fstring(message.data(), 0x08, sender.c_str(), 4, 8);   // "Bob" + null
  write_fstring(message.data(), 0x28, text.c_str(), 9, 16);    // "hi there" + null
  alignas(8) std::array<std::uint8_t, 0x40> fframe{};
  void* locals = message.data();
  std::memcpy(fframe.data() + 0x18, &locals, sizeof(locals));  // FFrame.Locals

  palmod::PluginEvent captured;
  int handled = 0;
  CHECK(!palmod::handle_broadcast_chat(fframe.data(), 0x18, {},
                                       [&](const palmod::DecodedChat& c) {
                                         captured = c.event;
                                         ++handled;
                                         return false;  // observe, don't suppress
                                       }));
  CHECK(handled == 1);
  CHECK(captured.kind == "chat");
  CHECK(captured.source == "Bob");
  CHECK(captured.text == "hi there");
  // A handler that asks to suppress propagates true.
  CHECK(palmod::handle_broadcast_chat(fframe.data(), 0x18, {},
                                      [&](const palmod::DecodedChat&) { return true; }));
  // A null frame delivers nothing.
  int none = 0;
  palmod::handle_broadcast_chat(nullptr, 0x18, {},
                                [&](const palmod::DecodedChat&) { ++none; return false; });
  CHECK(none == 0);

  // --- full install: resolve a synthetic UFunction, swap Func, run trampoline ---
  using ThunkFn = void (*)(void*, void*, void*);
  constexpr std::uint64_t kVtable = 0xABCD000011112222ULL;
  constexpr std::size_t kOffset = 0xd8;
  ThunkFn thunk = &fake_broadcast_thunk;
  std::uint64_t thunk_va = 0;
  std::memcpy(&thunk_va, &thunk, sizeof(thunk_va));
  auto ufunction = std::make_unique<std::array<std::uint8_t, kOffset + 8>>();
  ufunction->fill(0);
  std::memcpy(ufunction->data(), &kVtable, sizeof(kVtable));
  std::memcpy(ufunction->data() + kOffset, &thunk_va, sizeof(thunk_va));
  __asm__ __volatile__("" : : "r"(ufunction->data()) : "memory");

  palmod::ReflectionResolver resolver{kOffset, kVtable};
  palmod::ChatHook hook;
  palmod::ChatHook::Config config;
  config.broadcast_thunk_va = thunk_va;
  config.fframe_locals_offset = 0x18;

  palmod::PluginEvent delivered;
  int deliveries = 0;
  std::string error;
  CHECK(hook.install(config, resolver,
                     [&](const palmod::DecodedChat& c) {
                       delivered = c.event;
                       ++deliveries;
                       return false;
                     },
                     error));
  CHECK(error.empty());

  // The Func slot now points at the trampoline; invoke it as the VM would.
  g_chat_original_calls = 0;
  ThunkFn installed = nullptr;
  std::memcpy(&installed, ufunction->data() + kOffset, sizeof(installed));
  installed(reinterpret_cast<void*>(0x1), fframe.data(), reinterpret_cast<void*>(0x2));
  CHECK(deliveries == 1);
  CHECK(delivered.source == "Bob");
  CHECK(delivered.text == "hi there");
  CHECK(g_chat_original_calls == 1);  // original chained

  hook.uninstall();
  ThunkFn restored = nullptr;
  std::memcpy(&restored, ufunction->data() + kOffset, sizeof(restored));
  CHECK(restored == &fake_broadcast_thunk);  // slot restored
}

const palmod::EventArg* find_arg(const std::vector<palmod::EventArg>& args,
                                 const std::string& name) {
  for (const auto& a : args) {
    if (a.name == name) return &a;
  }
  return nullptr;
}

void test_parms_decode() {
  // A synthetic Parms buffer mixing every decodable FProperty type. This is the
  // generic core the by-name hook engine uses to turn any function's arguments
  // into an event payload from its reflection layout alone.
  const std::u16string item = u"BerryRed";
  alignas(8) std::array<std::uint8_t, 0x60> parms{};
  const std::int32_t count = 42;
  const float weight = 1.5F;
  const std::uint8_t flag = 1;
  const std::uint32_t name_index = 0xABCD;
  const std::uint32_t big = 0x8000'0001U;   // > INT32_MAX, so unsigned matters
  const std::uint64_t obj_ptr = 0x7f00'1234'5678ULL;
  std::memcpy(parms.data() + 0x00, &count, sizeof(count));       // IntProperty
  std::memcpy(parms.data() + 0x08, &weight, sizeof(weight));     // FloatProperty
  std::memcpy(parms.data() + 0x10, &flag, sizeof(flag));         // BoolProperty
  std::memcpy(parms.data() + 0x14, &name_index, sizeof(name_index));  // NameProperty
  const std::int32_t name_number = 4;  // instance suffix -> "_3"
  std::memcpy(parms.data() + 0x18, &name_number, sizeof(name_number));
  write_fstring(parms.data(), 0x20, item.c_str(), 9, 16);        // StrProperty
  std::memcpy(parms.data() + 0x40, &big, sizeof(big));           // UInt32Property
  std::memcpy(parms.data() + 0x48, &obj_ptr, sizeof(obj_ptr));   // ObjectProperty
  // TArray<int32> {data, num, max} at 0x50, elements in a separate buffer.
  alignas(4) std::array<std::int32_t, 3> elements = {10, 20, 30};
  __asm__ __volatile__("" : : "r"(elements.data()) : "memory");
  std::uint64_t elements_va = 0;
  void* elements_ptr = elements.data();
  std::memcpy(&elements_va, &elements_ptr, sizeof(elements_va));
  const std::int32_t elements_num = 3;
  std::memcpy(parms.data() + 0x50, &elements_va, sizeof(elements_va));
  std::memcpy(parms.data() + 0x58, &elements_num, sizeof(elements_num));

  const std::vector<palmod::ParamSpec> params = {
      {"Count", "IntProperty", 0x00},
      {"Weight", "FloatProperty", 0x08},
      {"Active", "BoolProperty", 0x10},
      {"ItemId", "NameProperty", 0x14},
      {"Label", "StrProperty", 0x20},
      {"Ignored", "StructProperty", 0x38},  // no fields -> empty struct table
      {"Big", "UInt32Property", 0x40},
      {"Owner", "ObjectProperty", 0x48},
      {"Scores", "ArrayProperty", 0x50, "IntProperty", 4},
  };

  // Without a resolver, NameProperty falls back to the numeric index.
  const auto raw = palmod::decode_parms(parms.data(), params);
  // The StructProperty with no declared fields decodes to an empty struct table.
  CHECK(raw.size() == 9);
  const auto* big_arg = find_arg(raw, "Big");
  CHECK(big_arg && !big_arg->is_text && big_arg->number == 2147483649.0);
  const auto* owner = find_arg(raw, "Owner");
  CHECK(owner && !owner->is_text &&
        owner->number == static_cast<double>(0x7f00'1234'5678ULL));
  const auto* scores = find_arg(raw, "Scores");
  CHECK(scores && scores->is_array && scores->items.size() == 3);
  if (scores && scores->items.size() == 3) {
    CHECK(scores->items[0].number == 10.0);
    CHECK(scores->items[1].number == 20.0);
    CHECK(scores->items[2].number == 30.0);
  }

  // A StructProperty decodes recursively into named members (offsets relative to
  // the struct's start). Here a struct at 0x28 with an int X @0 and float Y @4.
  const std::int32_t vec_x = 7;
  const float vec_y = 2.5F;
  std::memcpy(parms.data() + 0x28, &vec_x, sizeof(vec_x));
  std::memcpy(parms.data() + 0x2c, &vec_y, sizeof(vec_y));
  palmod::ParamSpec vector_param;
  vector_param.name = "Where";
  vector_param.type = "StructProperty";
  vector_param.offset = 0x28;
  vector_param.fields = {{"X", "IntProperty", 0x00}, {"Y", "FloatProperty", 0x04}};
  const auto with_struct = palmod::decode_parms(parms.data(), {vector_param});
  CHECK(with_struct.size() == 1);
  const auto* where = find_arg(with_struct, "Where");
  CHECK(where && where->is_struct && where->items.size() == 2);
  if (where && where->items.size() == 2) {
    CHECK(where->items[0].name == "X" && where->items[0].number == 7.0);
    CHECK(where->items[1].name == "Y" && where->items[1].number == 2.5);
  }

  // TArray<FVector2> — array of structs. Two elements {X,Y} in a backing buffer.
  struct Vec2 { std::int32_t x; float y; };
  alignas(8) std::array<Vec2, 2> vec_elements = {Vec2{1, 1.0F}, Vec2{2, 2.0F}};
  __asm__ __volatile__("" : : "r"(vec_elements.data()) : "memory");
  alignas(8) std::array<std::uint8_t, 0x10> vec_array{};
  std::uint64_t vec_elements_va = 0;
  void* vec_elements_ptr = vec_elements.data();
  std::memcpy(&vec_elements_va, &vec_elements_ptr, sizeof(vec_elements_va));
  const std::int32_t vec_num = 2;
  std::memcpy(vec_array.data() + 0x00, &vec_elements_va, sizeof(vec_elements_va));
  std::memcpy(vec_array.data() + 0x08, &vec_num, sizeof(vec_num));
  palmod::ParamSpec vec_list;
  vec_list.name = "Path";
  vec_list.type = "ArrayProperty";
  vec_list.offset = 0x00;
  vec_list.inner_type = "StructProperty";
  vec_list.inner_size = sizeof(Vec2);
  vec_list.fields = {{"X", "IntProperty", 0x00}, {"Y", "FloatProperty", 0x04}};
  const auto with_array = palmod::decode_parms(vec_array.data(), {vec_list});
  const auto* path = find_arg(with_array, "Path");
  CHECK(path && path->is_array && path->items.size() == 2);
  if (path && path->items.size() == 2) {
    CHECK(path->items[0].is_struct && path->items[0].items.size() == 2);
    CHECK(path->items[0].items[0].number == 1.0 && path->items[0].items[1].number == 1.0);
    CHECK(path->items[1].items[0].number == 2.0 && path->items[1].items[1].number == 2.0);
  }
  const auto* c = find_arg(raw, "Count");
  CHECK(c && !c->is_text && c->number == 42.0);
  const auto* w = find_arg(raw, "Weight");
  CHECK(w && !w->is_text && w->number == 1.5);
  const auto* a = find_arg(raw, "Active");
  CHECK(a && !a->is_text && a->number == 1.0);
  const auto* label = find_arg(raw, "Label");
  CHECK(label && label->is_text && label->text == "BerryRed");
  const auto* id_raw = find_arg(raw, "ItemId");
  CHECK(id_raw && !id_raw->is_text && id_raw->number == 0xABCD);
  const auto* ignored = find_arg(raw, "Ignored");
  CHECK(ignored && ignored->is_struct && ignored->items.empty());

  // With a resolver, NameProperty resolves to the pooled string.
  std::uint32_t seen_index = 0;
  const auto resolved = palmod::decode_parms(
      parms.data(), params, [&](std::uint32_t idx) {
        seen_index = idx;
        return std::string("BerryRed_C");
      });
  CHECK(seen_index == 0xABCD);
  const auto* id = find_arg(resolved, "ItemId");
  // Number 4 -> "_3" instance suffix appended to the resolved base name.
  CHECK(id && id->is_text && id->text == "BerryRed_C_3");

  // A null Parms decodes to nothing.
  CHECK(palmod::decode_parms(nullptr, params).empty());
}

// Build a synthetic FNamePool holding one narrow "BerryRed" and one wide "Hi",
// then resolve both by comparison index. Uses an asm barrier because the pool
// reads through raw integer VAs the optimizer can't see (would dead-store the
// synthetic buffers otherwise).
void test_fname_pool() {
  alignas(8) std::array<std::uint8_t, 0x100> block{};
  // Narrow "BerryRed" (len 8) at block offset 4.
  const std::uint16_t narrow_header = static_cast<std::uint16_t>((8u << 6) | 0u);
  std::memcpy(block.data() + 4, &narrow_header, sizeof(narrow_header));
  std::memcpy(block.data() + 6, "BerryRed", 8);
  // Wide u"Hi" (len 2) at block offset 32.
  const std::uint16_t wide_header = static_cast<std::uint16_t>((2u << 6) | 1u);
  std::memcpy(block.data() + 32, &wide_header, sizeof(wide_header));
  const char16_t hi[] = u"Hi";
  std::memcpy(block.data() + 34, hi, 4);
  __asm__ __volatile__("" : : "r"(block.data()) : "memory");

  std::array<std::uint64_t, 4> blocks{};
  std::uint64_t block_va = 0;
  void* block_ptr = block.data();
  std::memcpy(&block_va, &block_ptr, sizeof(block_va));
  blocks[0] = block_va;
  std::uint64_t blocks_va = 0;
  void* blocks_ptr = blocks.data();
  std::memcpy(&blocks_va, &blocks_ptr, sizeof(blocks_va));
  __asm__ __volatile__("" : : "r"(blocks.data()) : "memory");

  palmod::FNamePool pool(blocks_va);
  CHECK(pool.valid());
  // (index & 0xffff) * 2 must equal the entry offset; block = index >> 16 = 0.
  CHECK(pool.resolve(4 / 2) == "BerryRed");
  CHECK(pool.resolve(32 / 2) == "Hi");
  // Index 0, and an unconfigured pool, resolve to empty.
  CHECK(pool.resolve(0).empty());
  CHECK(palmod::FNamePool{}.resolve(2).empty());
  CHECK(!palmod::FNamePool{}.valid());
}

void test_fname_lookup() {
  // Reverse lookup needs the allocator extent: CurrentBlock @ Blocks-8,
  // CurrentByteCursor @ Blocks-4 (confirmed live). Model that exact layout.
#pragma pack(push, 1)
  struct FakeAllocator {
    std::uint32_t current_block;
    std::uint32_t cursor;
    std::uint64_t blocks[4];
  };
#pragma pack(pop)
  // Block bytes: "None" (len4) at off 0, then "PalSphere" (len9) at the next
  // 2-byte-aligned offset. resolve/lookup index = (block<<16) | (byteoff>>1).
  alignas(2) std::array<std::uint8_t, 0x40> block{};
  const std::uint16_t none_hdr = static_cast<std::uint16_t>((4u << 6) | 0u);
  std::memcpy(block.data() + 0, &none_hdr, 2);
  std::memcpy(block.data() + 2, "None", 4);          // entry ends at 6
  const std::uint16_t item_hdr = static_cast<std::uint16_t>((9u << 6) | 0u);
  std::memcpy(block.data() + 6, &item_hdr, 2);
  std::memcpy(block.data() + 8, "PalSphere", 9);     // entry ends at 6+2+9=17
  const std::uint32_t used = 18;                      // aligned past the last entry

  FakeAllocator alloc{};
  alloc.current_block = 0;
  alloc.cursor = used;
  std::uint64_t block_va = 0;
  void* block_ptr = block.data();
  std::memcpy(&block_va, &block_ptr, sizeof(block_va));
  alloc.blocks[0] = block_va;
  __asm__ __volatile__("" : : "r"(block.data()), "r"(&alloc) : "memory");

  std::uint64_t blocks_va = 0;
  void* blocks_ptr = &alloc.blocks[0];
  std::memcpy(&blocks_va, &blocks_ptr, sizeof(blocks_va));
  palmod::FNamePool pool(blocks_va);

  const std::uint32_t idx = pool.lookup("PalSphere");
  CHECK(idx == (6 >> 1));                 // byte offset 6 -> index 3
  CHECK(pool.resolve(idx) == "PalSphere");  // round-trips back
  CHECK(pool.lookup("None") == 0);          // offset 0 -> index 0
  CHECK(pool.lookup("NotThere") == 0);      // absent -> 0
  CHECK(palmod::FNamePool{}.lookup("PalSphere") == 0);  // no pool -> 0
}

std::uint64_t va_of(const void* p) {
  std::uint64_t v = 0;
  std::memcpy(&v, &p, sizeof(v));
  return v;
}

void* g_pe_target = nullptr;
void* g_pe_function = nullptr;
int g_pe_calls = 0;
std::array<std::uint8_t, 0x18> g_pe_parms_copy{};  // snapshot: caller's buffer is transient
void fake_process_event(void* target, void* function, void* parms) {
  g_pe_target = target;
  g_pe_function = function;
  if (parms != nullptr) std::memcpy(g_pe_parms_copy.data(), parms, g_pe_parms_copy.size());
  ++g_pe_calls;
}

void test_invoke() {
  // read_vtable_slot: an object whose first 8 bytes point to a vtable; slot 68
  // holds ProcessEvent's address (the slot index is the build-specific value).
  using PEFn = void (*)(void*, void*, void*);
  alignas(8) std::array<std::uint64_t, 80> vtable{};
  PEFn pe = &fake_process_event;
  std::uint64_t pe_va = 0;
  std::memcpy(&pe_va, &pe, sizeof(pe_va));
  vtable[68] = pe_va;
  alignas(8) std::array<std::uint8_t, 0x20> object{};
  std::uint64_t vtable_va = 0;
  void* vtable_ptr = vtable.data();
  std::memcpy(&vtable_va, &vtable_ptr, sizeof(vtable_va));
  std::memcpy(object.data(), &vtable_va, sizeof(vtable_va));
  __asm__ __volatile__("" : : "r"(vtable.data()), "r"(object.data()) : "memory");
  std::uint64_t object_va = 0;
  void* object_ptr = object.data();
  std::memcpy(&object_va, &object_ptr, sizeof(object_va));

  CHECK(palmod::read_vtable_slot(object_va, 68) == pe_va);
  CHECK(palmod::read_vtable_slot(0, 68) == 0);  // fail closed

  // call_process_event forwards (this, function, parms) to ProcessEvent.
  g_pe_calls = 0;
  g_pe_parms_copy = {};
  std::array<std::uint8_t, 0x18> parms{};
  parms[0] = 0xAB;  // a sentinel the fake ProcessEvent snapshots
  const std::uint64_t function_va = 0x1234'5678;
  palmod::call_process_event(pe_va, object_va, function_va, parms.data());
  CHECK(g_pe_calls == 1);
  CHECK(g_pe_target == object.data());
  CHECK(g_pe_parms_copy[0] == 0xAB);
  std::uint64_t seen_function = 0;
  std::memcpy(&seen_function, &g_pe_function, sizeof(seen_function));
  CHECK(seen_function == function_va);

  // A null ProcessEvent / target does nothing (fail closed).
  g_pe_calls = 0;
  palmod::call_process_event(0, object_va, function_va, parms.data());
  palmod::call_process_event(pe_va, 0, function_va, parms.data());
  CHECK(g_pe_calls == 0);

  // read_global_pointer: dereference a global that holds the object pointer.
  std::uint64_t engine_global = object_va;  // stands in for the GEngine variable
  __asm__ __volatile__("" : : "r"(&engine_global) : "memory");
  CHECK(palmod::read_global_pointer(va_of(&engine_global)) == object_va);
  CHECK(palmod::read_global_pointer(0) == 0);

  // vtable_slot_address: the address of the Tick entry (to install a slot hook on),
  // distinct from read_vtable_slot which returns the entry's value.
  const std::uint64_t slot_addr = palmod::vtable_slot_address(object_va, 68);
  CHECK(slot_addr == vtable_va + 68 * sizeof(std::uint64_t));
  std::uint64_t via_addr = 0;  // *(slot_addr) is the same pointer read_vtable_slot gives
  std::memcpy(&via_addr, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(slot_addr)),
              sizeof(via_addr));
  CHECK(via_addr == pe_va);
  CHECK(palmod::vtable_slot_address(0, 68) == 0);
}

void test_object_array() {
  // Build a synthetic FName pool with the class/instance names we need.
  struct Pool { std::uint32_t current_block; std::uint32_t cursor; std::uint64_t blocks[4]; };
  alignas(2) std::array<std::uint8_t, 0x200> nameblock{};
  std::size_t noff = 0;
  auto add_name = [&](std::string_view s) -> std::uint32_t {
    const std::uint16_t hdr = static_cast<std::uint16_t>(s.size() << 6);
    std::memcpy(nameblock.data() + noff, &hdr, 2);
    std::memcpy(nameblock.data() + noff + 2, s.data(), s.size());
    const std::uint32_t index = static_cast<std::uint32_t>(noff >> 1);
    noff += 2 + s.size();
    noff = (noff + 1) & ~static_cast<std::size_t>(1);
    return index;
  };
  add_name("None");  // index 0
  const std::uint32_t i_base = add_name("PalPlayerInventoryData");
  const std::uint32_t i_bp = add_name("BP_PalPlayerInventoryData_C");
  const std::uint32_t i_cdo = add_name("Default__PalPlayerInventoryData");
  const std::uint32_t i_other = add_name("SomeOtherClass");
  Pool pool_meta{};
  pool_meta.current_block = 0;
  pool_meta.cursor = static_cast<std::uint32_t>(noff);
  pool_meta.blocks[0] = va_of(nameblock.data());
  __asm__ __volatile__("" : : "r"(nameblock.data()), "r"(&pool_meta) : "memory");
  palmod::FNamePool names(va_of(&pool_meta.blocks[0]));

  constexpr std::size_t kClassOff = 0x10, kNameOff = 0x18, kSuperOff = 0x30;
  // Classes: BP subclass -> native base (super chain).
  alignas(8) std::array<std::uint8_t, 0x40> class_base{};
  alignas(8) std::array<std::uint8_t, 0x40> class_bp{};
  alignas(8) std::array<std::uint8_t, 0x40> class_other{};
  auto set_class = [&](std::array<std::uint8_t, 0x40>& c, std::uint32_t name_idx,
                       const void* super) {
    std::memcpy(c.data() + kNameOff, &name_idx, 4);
    const std::uint64_t s = super ? va_of(super) : 0;
    std::memcpy(c.data() + kSuperOff, &s, 8);
  };
  set_class(class_base, i_base, nullptr);
  set_class(class_bp, i_bp, class_base.data());
  set_class(class_other, i_other, nullptr);

  // Instances: a CDO, the live BP instance, and an unrelated object.
  alignas(8) std::array<std::uint8_t, 0x40> obj_cdo{};
  alignas(8) std::array<std::uint8_t, 0x40> obj_live{};
  alignas(8) std::array<std::uint8_t, 0x40> obj_other{};
  auto set_obj = [&](std::array<std::uint8_t, 0x40>& o, const void* cls, std::uint32_t name_idx) {
    const std::uint64_t c = va_of(cls);
    std::memcpy(o.data() + kClassOff, &c, 8);
    std::memcpy(o.data() + kNameOff, &name_idx, 4);
  };
  set_obj(obj_cdo, class_base.data(), i_cdo);   // Default__PalPlayerInventoryData
  set_obj(obj_live, class_bp.data(), i_bp);      // the connected player's inventory
  set_obj(obj_other, class_other.data(), i_other);

  // GUObjectArray: objects_va -> {chunk_array ptr @0, i32 num @0x14}; one chunk of
  // 3 FUObjectItems (24 bytes each, Object ptr at offset 0).
  alignas(8) std::array<std::uint8_t, 3 * 24> chunk{};
  const std::uint64_t o0 = va_of(obj_cdo.data()), o1 = va_of(obj_live.data()), o2 = va_of(obj_other.data());
  std::memcpy(chunk.data() + 0 * 24, &o0, 8);
  std::memcpy(chunk.data() + 1 * 24, &o1, 8);
  std::memcpy(chunk.data() + 2 * 24, &o2, 8);
  alignas(8) std::array<std::uint64_t, 4> chunk_array{};
  chunk_array[0] = va_of(chunk.data());
  alignas(8) std::array<std::uint8_t, 0x20> objects_field{};
  const std::uint64_t ca = va_of(chunk_array.data());
  std::memcpy(objects_field.data() + 0, &ca, 8);
  const std::int32_t num = 3;
  std::memcpy(objects_field.data() + 0x14, &num, 4);
  __asm__ __volatile__("" : : "r"(chunk.data()), "r"(chunk_array.data()),
                       "r"(objects_field.data()), "r"(class_bp.data()),
                       "r"(obj_live.data()) : "memory");

  palmod::ObjectArrayLayout layout;
  layout.objects_va = va_of(objects_field.data());
  layout.class_offset = kClassOff;
  layout.name_offset = kNameOff;
  layout.super_offset = 0;  // exact-match mode first

  palmod::ObjectArray arr(layout, names);
  CHECK(arr.for_each([](std::uint64_t) { return true; }) == 3);
  CHECK(arr.class_name(o1) == "BP_PalPlayerInventoryData_C");
  CHECK(arr.object_name(o0) == "Default__PalPlayerInventoryData");

  // Exact-match: finds the BP class by exact name, but NOT the native base name —
  // which is exactly why the live walk needs IsA (the gotcha we hit).
  CHECK(arr.find("BP_PalPlayerInventoryData_C") == o1);
  CHECK(arr.find("PalPlayerInventoryData") == 0);  // base name misses the subclass

  // IsA mode: SuperStruct chain lets the base class name find the BP instance,
  // and CDOs are still skipped.
  layout.super_offset = kSuperOff;
  palmod::ObjectArray arr_isa(layout, names);
  CHECK(arr_isa.is_a(o1, "PalPlayerInventoryData"));   // BP -> base
  CHECK(arr_isa.is_a(o0, "PalPlayerInventoryData"));   // CDO is-a base too
  CHECK(!arr_isa.is_a(o2, "PalPlayerInventoryData"));  // unrelated class
  CHECK(arr_isa.find("PalPlayerInventoryData") == o1); // finds live, skips CDO

  // A predicate narrows further (e.g. correlate to a specific player).
  CHECK(arr_isa.find("PalPlayerInventoryData",
                     [&](std::uint64_t o) { return o == o1; }) == o1);
  CHECK(arr_isa.find("PalPlayerInventoryData",
                     [](std::uint64_t) { return false; }) == 0);
}

std::uint64_t g_ai_this = 0;
std::uint64_t g_ai_fname = 0;
std::int32_t g_ai_count = 0;
bool g_ai_assign = false;
bool g_ai_notify = false;
float g_ai_delay = 0.0F;
int g_ai_calls = 0;
bool fake_add_item(void* t, std::uint64_t fname, std::int32_t count, bool a, bool b, float f) {
  g_ai_this = va_of(t);
  g_ai_fname = fname;
  g_ai_count = count;
  g_ai_assign = a;
  g_ai_notify = b;
  g_ai_delay = f;
  ++g_ai_calls;
  return false;  // AddItem returns an enum; 0/false observed on a successful add
}


void test_player_auth() {
  // Synthetic object graph mirroring the live layout: a PalPlayerController whose
  // PlayerState (@ps_off) carries a 16-byte PlayerUId (@uid_off); admin state is
  // bAdmin (@badmin_off). Sender is matched by Guid, then bAdmin is read.
  struct Pool { std::uint32_t current_block; std::uint32_t cursor; std::uint64_t blocks[4]; };
  alignas(2) std::array<std::uint8_t, 0x80> nb{};
  std::size_t noff = 0;
  auto add_name = [&](std::string_view s) -> std::uint32_t {
    const std::uint16_t hdr = static_cast<std::uint16_t>(s.size() << 6);
    std::memcpy(nb.data() + noff, &hdr, 2);
    std::memcpy(nb.data() + noff + 2, s.data(), s.size());
    const std::uint32_t idx = static_cast<std::uint32_t>(noff >> 1);
    noff += 2 + s.size();
    noff = (noff + 1) & ~static_cast<std::size_t>(1);
    return idx;
  };
  add_name("None");
  const std::uint32_t i_ctrl = add_name("PalPlayerController");
  const std::uint32_t i_inst = add_name("BP_PalPlayerController_C");
  Pool pm{};
  pm.current_block = 0;
  pm.cursor = static_cast<std::uint32_t>(noff);
  pm.blocks[0] = va_of(nb.data());
  __asm__ __volatile__("" : : "r"(nb.data()), "r"(&pm) : "memory");
  palmod::FNamePool names(va_of(&pm.blocks[0]));

  constexpr std::size_t kClassOff = 0x10, kNameOff = 0x18, kSuperOff = 0x40;
  constexpr std::size_t kPsOff = 0x298, kUidOff = 0x590, kBadminOff = 0x850;
  // Classes: BP subclass -> native base (so IsA finds it). Sized past SuperStruct.
  alignas(8) std::array<std::uint8_t, 0x50> cls_base{};
  alignas(8) std::array<std::uint8_t, 0x50> cls_bp{};
  std::memcpy(cls_base.data() + kNameOff, &i_ctrl, 4);
  std::memcpy(cls_bp.data() + kNameOff, &i_inst, 4);
  const std::uint64_t base_va = va_of(cls_base.data());
  std::memcpy(cls_bp.data() + kSuperOff, &base_va, 8);

  const std::array<std::uint8_t, 16> uid = {0x6d, 0xe2, 0xfc, 0xea, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0};
  alignas(8) std::array<std::uint8_t, 0x600> state{};
  std::memcpy(state.data() + kUidOff, uid.data(), 16);
  alignas(8) std::array<std::uint8_t, 0x900> ctrl{};
  const std::uint64_t cls_bp_va = va_of(cls_bp.data());
  std::memcpy(ctrl.data() + kClassOff, &cls_bp_va, 8);
  std::memcpy(ctrl.data() + kNameOff, &i_inst, 4);
  const std::uint64_t state_va = va_of(state.data());
  std::memcpy(ctrl.data() + kPsOff, &state_va, 8);
  ctrl[kBadminOff] = 1;  // admin
  __asm__ __volatile__("" : : "r"(cls_base.data()), "r"(cls_bp.data()),
                       "r"(state.data()), "r"(ctrl.data()) : "memory");

  alignas(8) std::array<std::uint8_t, 24> chunk{};
  const std::uint64_t ctrl_va = va_of(ctrl.data());
  std::memcpy(chunk.data(), &ctrl_va, 8);
  alignas(8) std::array<std::uint64_t, 4> chunk_array{};
  chunk_array[0] = va_of(chunk.data());
  alignas(8) std::array<std::uint8_t, 0x20> objects_field{};
  const std::uint64_t ca = va_of(chunk_array.data());
  std::memcpy(objects_field.data(), &ca, 8);
  const std::int32_t num = 1;
  std::memcpy(objects_field.data() + 0x14, &num, 4);
  __asm__ __volatile__("" : : "r"(chunk.data()), "r"(chunk_array.data()),
                       "r"(objects_field.data()) : "memory");

  palmod::ObjectArrayLayout olayout;
  olayout.objects_va = va_of(objects_field.data());
  olayout.class_offset = kClassOff;
  olayout.name_offset = kNameOff;
  olayout.super_offset = kSuperOff;
  palmod::ObjectArray objects(olayout, names);

  palmod::AdminLayout alayout;
  alayout.controller_class = "PalPlayerController";
  alayout.player_state_offset = kPsOff;
  alayout.player_uid_offset = kUidOff;
  alayout.badmin_offset = kBadminOff;

  // Matching sender + bAdmin=1 -> Admin.
  CHECK(palmod::resolve_player_auth(objects, alayout, uid.data()) == palmod::AuthState::Admin);
  // Same sender but bAdmin=0 -> Player.
  ctrl[kBadminOff] = 0;
  CHECK(palmod::resolve_player_auth(objects, alayout, uid.data()) == palmod::AuthState::Player);
  // Unknown sender Guid -> Unknown (fail closed).
  const std::array<std::uint8_t, 16> other = {0xff};
  CHECK(palmod::resolve_player_auth(objects, alayout, other.data()) == palmod::AuthState::Unknown);
  // Unconfigured layout -> Unknown.
  CHECK(palmod::resolve_player_auth(objects, {}, uid.data()) == palmod::AuthState::Unknown);
}

void test_object_walk() {
  // Synthetic object graph: player -> (ptr @ 0x30) component -> (ptr @ 0x18) data.
  // follow_pointer_chain reaches `data` using only the reflected offsets.
  alignas(8) std::array<std::uint8_t, 0x40> data{};
  alignas(8) std::array<std::uint8_t, 0x40> component{};
  alignas(8) std::array<std::uint8_t, 0x40> player{};
  std::uint64_t data_va = 0;
  void* data_ptr = data.data();
  std::memcpy(&data_va, &data_ptr, sizeof(data_va));
  std::uint64_t component_va = 0;
  void* component_ptr = component.data();
  std::memcpy(&component_va, &component_ptr, sizeof(component_va));
  std::memcpy(component.data() + 0x18, &data_va, sizeof(data_va));
  std::memcpy(player.data() + 0x30, &component_va, sizeof(component_va));
  __asm__ __volatile__("" : : "r"(player.data()), "r"(component.data()) : "memory");

  std::uint64_t player_va = 0;
  void* player_ptr = player.data();
  std::memcpy(&player_va, &player_ptr, sizeof(player_va));

  CHECK(palmod::follow_pointer_chain(player_va, {0x30, 0x18}) == data_va);
  // An empty chain returns the start unchanged.
  CHECK(palmod::follow_pointer_chain(player_va, {}) == player_va);
  // A null link on the path yields 0 (fail closed).
  CHECK(palmod::follow_pointer_chain(player_va, {0x08, 0x18}) == 0);
  CHECK(palmod::follow_pointer_chain(0, {0x30}) == 0);
}

void test_parms_encode() {
  // The write-side inverse of decode: encode typed values into a Parms buffer
  // using the reflection layout, then decode it back and confirm a round trip.
  // This is the AddItem_ServerInternal shape (recovered from reflection).
  const std::vector<palmod::ParamSpec> params = {
      {"StaticItemId", "NameProperty", 0x00},
      {"Count", "IntProperty", 0x08},
      {"IsAssignPassive", "BoolProperty", 0x0c},
      {"LogDelay", "FloatProperty", 0x10},
  };
  std::vector<palmod::ParamInput> inputs(3);
  inputs[0].name = "StaticItemId";
  inputs[0].is_text = true;
  inputs[0].text = "PalSphere";
  inputs[1].name = "Count";
  inputs[1].number = 5;
  inputs[2].name = "LogDelay";
  inputs[2].number = 1.5;

  // A tiny two-way name table stands in for the live FName pool.
  const std::uint32_t kPalSphere = 0x4321;
  auto encode = [&](const std::string& s) -> std::uint32_t {
    return s == "PalSphere" ? kPalSphere : 0;
  };
  auto resolve = [&](std::uint32_t index) -> std::string {
    return index == kPalSphere ? "PalSphere" : "";
  };

  const auto buffer = palmod::encode_parms(0x18, params, inputs, encode);
  CHECK(buffer.size() == 0x18);
  const auto decoded = palmod::decode_parms(buffer.data(), params, resolve);
  const auto* item = find_arg(decoded, "StaticItemId");
  CHECK(item && item->is_text && item->text == "PalSphere");
  const auto* count = find_arg(decoded, "Count");
  CHECK(count && count->number == 5.0);
  const auto* delay = find_arg(decoded, "LogDelay");
  CHECK(delay && delay->number == 1.5);
  // An input with no matching parameter is ignored; absent params stay zeroed.
  const auto* passive = find_arg(decoded, "IsAssignPassive");
  CHECK(passive && passive->number == 0.0);
}

void test_parms_encode_containers() {
  // FString + nested struct + array-of-strings: encode from a value tree, then
  // decode it back and confirm the whole tree round-trips (the FPalChatMessage
  // shape the generic call path needs — no bespoke per-struct code).
  const std::vector<palmod::ParamSpec> params = {
      {"Message", "StrProperty", 0x00, "", 0, {}},
      {"Inner", "StructProperty", 0x10, "", 0, {{"Value", "IntProperty", 0x00, "", 0, {}}}},
      {"Tags", "ArrayProperty", 0x18, "StrProperty", 0x10, {}},
  };
  std::vector<palmod::ParamInput> inputs(3);
  inputs[0].name = "Message";
  inputs[0].is_text = true;
  inputs[0].text = "hello";
  inputs[1].name = "Inner";
  inputs[1].is_struct = true;
  inputs[1].items.push_back({"Value", false, "", 42.0, false, false, {}});
  inputs[2].name = "Tags";
  inputs[2].is_array = true;
  inputs[2].items.push_back({"", true, "a", 0.0, false, false, {}});
  inputs[2].items.push_back({"", true, "b", 0.0, false, false, {}});

  const auto encoded = palmod::encode_parms(0x28, params, inputs);
  CHECK(encoded.size() == 0x28);
  const auto decoded = palmod::decode_parms(encoded.data(), params);
  const auto* msg = find_arg(decoded, "Message");
  CHECK(msg && msg->is_text && msg->text == "hello");
  const auto* inner = find_arg(decoded, "Inner");
  CHECK(inner && inner->is_struct && inner->items.size() == 1);
  CHECK(inner && !inner->items.empty() && inner->items[0].number == 42.0);
  const auto* tags = find_arg(decoded, "Tags");
  CHECK(tags && tags->is_array && tags->items.size() == 2);
  CHECK(tags && tags->items.size() == 2 && tags->items[0].text == "a" &&
        tags->items[1].text == "b");
}

int g_generic_orig_a = 0;
int g_generic_orig_b = 0;
void fake_generic_thunk_a(void*, void*, void*) { ++g_generic_orig_a; }
void fake_generic_thunk_b(void*, void*, void*) { ++g_generic_orig_b; }

// Build a synthetic UFunction {vtable @ 0, Func thunk @ func_offset} so the
// ReflectionResolver can find its Func slot by scanning for the thunk pointer.
std::unique_ptr<std::array<std::uint8_t, 0xE0>> make_ufunction(
    std::uint64_t vtable, std::uint64_t thunk_va, std::size_t func_offset) {
  auto obj = std::make_unique<std::array<std::uint8_t, 0xE0>>();
  obj->fill(0);
  std::memcpy(obj->data(), &vtable, sizeof(vtable));
  std::memcpy(obj->data() + func_offset, &thunk_va, sizeof(thunk_va));
  __asm__ __volatile__("" : : "r"(obj->data()) : "memory");
  return obj;
}

void test_generic_hook() {
  // Two distinct functions hooked at once: the stub pool must route each call
  // back to its own entry, decode that function's params, and chain its original.
  constexpr std::uint64_t kVtable = 0x0BADF00DDEAD0001ULL;
  constexpr std::size_t kOffset = 0xd8;
  using ThunkFn = void (*)(void*, void*, void*);

  std::uint64_t va_a = 0;
  std::uint64_t va_b = 0;
  ThunkFn ta = &fake_generic_thunk_a;
  ThunkFn tb = &fake_generic_thunk_b;
  std::memcpy(&va_a, &ta, sizeof(va_a));
  std::memcpy(&va_b, &tb, sizeof(va_b));
  auto ufunc_a = make_ufunction(kVtable, va_a, kOffset);
  auto ufunc_b = make_ufunction(kVtable, va_b, kOffset);

  // Synthetic Parms + FFrame for each: FuncA takes an int Count, FuncB a str Name.
  alignas(8) std::array<std::uint8_t, 0x40> parms_a{};
  const std::int32_t count = 7;
  std::memcpy(parms_a.data(), &count, sizeof(count));
  alignas(8) std::array<std::uint8_t, 0x40> parms_b{};
  const std::u16string label = u"Sword";
  write_fstring(parms_b.data(), 0x00, label.c_str(), 6, 8);

  alignas(8) std::array<std::uint8_t, 0x40> fframe_a{};
  alignas(8) std::array<std::uint8_t, 0x40> fframe_b{};
  void* locals_a = parms_a.data();
  void* locals_b = parms_b.data();
  std::memcpy(fframe_a.data() + 0x18, &locals_a, sizeof(locals_a));
  std::memcpy(fframe_b.data() + 0x18, &locals_b, sizeof(locals_b));

  palmod::ReflectionResolver resolver{kOffset, kVtable};
  palmod::GenericHookTable table;

  palmod::GenericEvent got_a;
  palmod::GenericEvent got_b;
  int deliveries_a = 0;
  int deliveries_b = 0;

  palmod::GenericHookSpec spec_a;
  spec_a.thunk_va = va_a;
  spec_a.name = "FuncA";
  spec_a.params = {{"Count", "IntProperty", 0x00}};
  palmod::GenericHookSpec spec_b;
  spec_b.thunk_va = va_b;
  spec_b.name = "FuncB";
  spec_b.params = {{"Name", "StrProperty", 0x00}};

  std::string error;
  const int id_a = table.install(spec_a, resolver, {},
                                 [&](const palmod::GenericEvent& e) {
                                   got_a = e;
                                   ++deliveries_a;
                                 },
                                 error);
  CHECK(id_a >= 0);
  CHECK(error.empty());
  const int id_b = table.install(spec_b, resolver, {},
                                 [&](const palmod::GenericEvent& e) {
                                   got_b = e;
                                   ++deliveries_b;
                                 },
                                 error);
  CHECK(id_b >= 0);
  CHECK(id_b != id_a);
  CHECK(table.active_count() == 2);

  // Fire FuncA's installed slot: only hook A delivers; its original chains.
  g_generic_orig_a = 0;
  g_generic_orig_b = 0;
  ThunkFn installed_a = nullptr;
  std::memcpy(&installed_a, ufunc_a->data() + kOffset, sizeof(installed_a));
  installed_a(reinterpret_cast<void*>(0x1), fframe_a.data(),
              reinterpret_cast<void*>(0x2));
  CHECK(deliveries_a == 1);
  CHECK(deliveries_b == 0);
  CHECK(got_a.name == "FuncA");
  CHECK(got_a.args.size() == 1);
  CHECK(got_a.args[0].name == "Count");
  CHECK(!got_a.args[0].is_text && got_a.args[0].number == 7.0);
  CHECK(g_generic_orig_a == 1);
  CHECK(g_generic_orig_b == 0);

  // Fire FuncB's slot: routed independently to hook B.
  ThunkFn installed_b = nullptr;
  std::memcpy(&installed_b, ufunc_b->data() + kOffset, sizeof(installed_b));
  installed_b(reinterpret_cast<void*>(0x1), fframe_b.data(),
              reinterpret_cast<void*>(0x2));
  CHECK(deliveries_b == 1);
  CHECK(got_b.name == "FuncB");
  CHECK(got_b.args.size() == 1);
  CHECK(got_b.args[0].is_text && got_b.args[0].text == "Sword");
  CHECK(g_generic_orig_b == 1);

  // Uninstall restores both slots exactly.
  table.uninstall(id_a);
  table.uninstall(id_b);
  CHECK(table.active_count() == 0);
  ThunkFn restored_a = nullptr;
  ThunkFn restored_b = nullptr;
  std::memcpy(&restored_a, ufunc_a->data() + kOffset, sizeof(restored_a));
  std::memcpy(&restored_b, ufunc_b->data() + kOffset, sizeof(restored_b));
  CHECK(restored_a == &fake_generic_thunk_a);
  CHECK(restored_b == &fake_generic_thunk_b);
}

void test_reflection_generic_hook() {
  // The backend's by-name path: install() builds a resolver from profile facts,
  // then install_generic_hook resolves a UFunction, swaps it, and delivers the
  // decoded call as a PluginEvent through callbacks.on_event.
  constexpr std::uint64_t kVtable = 0x0BADF00DDEAD0042ULL;
  constexpr std::size_t kOffset = 0xd8;
  using ThunkFn = void (*)(void*, void*, void*);
  std::uint64_t va = 0;
  ThunkFn t = &fake_generic_thunk_a;
  std::memcpy(&va, &t, sizeof(va));
  auto ufunc = make_ufunction(kVtable, va, kOffset);

  // Synthetic FNamePool so a NameProperty arg resolves to a string.
  alignas(8) std::array<std::uint8_t, 0x100> name_block{};
  const std::uint16_t name_header = static_cast<std::uint16_t>((8u << 6) | 0u);
  std::memcpy(name_block.data() + 4, &name_header, sizeof(name_header));
  std::memcpy(name_block.data() + 6, "BerryRed", 8);
  __asm__ __volatile__("" : : "r"(name_block.data()) : "memory");
  std::array<std::uint64_t, 4> name_blocks{};
  std::uint64_t name_block_va = 0;
  void* name_block_ptr = name_block.data();
  std::memcpy(&name_block_va, &name_block_ptr, sizeof(name_block_va));
  name_blocks[0] = name_block_va;
  std::uint64_t name_blocks_va = 0;
  void* name_blocks_ptr = name_blocks.data();
  std::memcpy(&name_blocks_va, &name_blocks_ptr, sizeof(name_blocks_va));
  __asm__ __volatile__("" : : "r"(name_blocks.data()) : "memory");

  alignas(8) std::array<std::uint8_t, 0x40> parms{};
  const std::int32_t count = 99;
  std::memcpy(parms.data(), &count, sizeof(count));
  const std::uint32_t item_index = 4 / 2;  // resolves to "BerryRed"
  std::memcpy(parms.data() + 8, &item_index, sizeof(item_index));
  alignas(8) std::array<std::uint8_t, 0x40> fframe{};
  void* locals = parms.data();
  std::memcpy(fframe.data() + 0x18, &locals, sizeof(locals));

  // An injected tick slot gives install() at least one hook so it succeeds.
  g_reflection_original_calls = 0;
  using TickFn = void (*)(void*, float, bool);
  TickFn tick_slot = &fake_original_tick;
  palmod::ReflectionLayout layout;
  layout.tick_slot = reinterpret_cast<void**>(&tick_slot);
  palmod::ReflectionHookBackend backend(layout);

  palmod::PluginEvent captured;
  int deliveries = 0;
  palmod::HookCallbacks callbacks;
  callbacks.on_event = [&](const palmod::PluginEvent& e) {
    captured = e;
    ++deliveries;
  };
  palmod::BuildProfile profile;
  profile.reflection_func_offset = kOffset;
  profile.reflection_vtable_va = kVtable;
  profile.reflection_fname_pool_blocks_va = name_blocks_va;
  std::string error;
  CHECK(backend.install(profile, std::move(callbacks), error));
  CHECK(error.empty());

  // Point the hook at the UFunction's Func slot directly. Production resolves the
  // slot live via find_function (UFunction + func_offset); a pre-resolved
  // func_slot_va exercises that swap+decode path without the resolver's
  // process-memory scan, which is sensitive to the optimizer.
  std::uint64_t slot_va = 0;
  void* slot_ptr = ufunc->data() + kOffset;
  std::memcpy(&slot_va, &slot_ptr, sizeof(slot_va));
  palmod::GenericHookSpec spec;
  spec.name = "AddItem_ServerInternal";
  spec.func_slot_va = slot_va;
  spec.fframe_locals_offset = 0x18;
  spec.params = {{"Count", "IntProperty", 0x00},
                 {"StaticItemId", "NameProperty", 0x08}};
  CHECK(backend.install_generic_hook(spec, error));
  CHECK(error.empty());

  g_generic_orig_a = 0;
  ThunkFn installed = nullptr;
  std::memcpy(&installed, ufunc->data() + kOffset, sizeof(installed));
  installed(reinterpret_cast<void*>(0x1), fframe.data(), reinterpret_cast<void*>(0x2));
  CHECK(deliveries == 1);
  CHECK(captured.kind == "AddItem_ServerInternal");
  CHECK(captured.args.size() == 2);
  CHECK(captured.args[0].name == "Count");
  CHECK(!captured.args[0].is_text && captured.args[0].number == 99.0);
  // The NameProperty resolved through the profile's FName pool to a string.
  CHECK(captured.args[1].name == "StaticItemId");
  CHECK(captured.args[1].is_text && captured.args[1].text == "BerryRed");
  CHECK(g_generic_orig_a == 1);  // original chained

  backend.uninstall();
  ThunkFn restored = nullptr;
  std::memcpy(&restored, ufunc->data() + kOffset, sizeof(restored));
  CHECK(restored == &fake_generic_thunk_a);  // slot restored

  // A backend without reflection facts (no resolver) fails closed.
  palmod::ReflectionHookBackend bare(layout);
  palmod::HookCallbacks bare_callbacks;
  bare_callbacks.on_event = [](const palmod::PluginEvent&) {};
  CHECK(bare.install(palmod::BuildProfile{}, std::move(bare_callbacks), error));
  CHECK(!bare.install_generic_hook(spec, error));
  CHECK(!error.empty());
  bare.uninstall();
}

void test_chat_command_routing() {
  // End-to-end: a `!`-prefixed chat command from an admin is recognized on the
  // game thread, the sender's admin status is resolved from their Guid, the
  // command is routed (with `!`->`/`), and the broadcast is suppressed.
  struct Pool { std::uint32_t current_block; std::uint32_t cursor; std::uint64_t blocks[4]; };
  alignas(2) std::array<std::uint8_t, 0x80> nb{};
  std::size_t noff = 0;
  auto add_name = [&](std::string_view s) -> std::uint32_t {
    const std::uint16_t hdr = static_cast<std::uint16_t>(s.size() << 6);
    std::memcpy(nb.data() + noff, &hdr, 2);
    std::memcpy(nb.data() + noff + 2, s.data(), s.size());
    const std::uint32_t idx = static_cast<std::uint32_t>(noff >> 1);
    noff += 2 + s.size();
    noff = (noff + 1) & ~static_cast<std::size_t>(1);
    return idx;
  };
  add_name("None");
  const std::uint32_t i_ctrl = add_name("PalPlayerController");
  const std::uint32_t i_inst = add_name("BP_PalPlayerController_C");
  Pool pm{};
  pm.current_block = 0;
  pm.cursor = static_cast<std::uint32_t>(noff);
  pm.blocks[0] = va_of(nb.data());
  const std::uint64_t blocks_va = va_of(&pm.blocks[0]);

  constexpr std::size_t kClassOff = 0x10, kNameOff = 0x18, kSuperOff = 0x40;
  constexpr std::size_t kPsOff = 0x298, kUidOff = 0x590, kBadminOff = 0x850;
  alignas(8) std::array<std::uint8_t, 0x50> cls_base{}, cls_bp{};
  std::memcpy(cls_base.data() + kNameOff, &i_ctrl, 4);
  std::memcpy(cls_bp.data() + kNameOff, &i_inst, 4);
  const std::uint64_t base_va = va_of(cls_base.data());
  std::memcpy(cls_bp.data() + kSuperOff, &base_va, 8);
  const std::array<std::uint8_t, 16> admin_uid = {0x6d, 0xe2, 0xfc, 0xea};
  alignas(8) std::array<std::uint8_t, 0x600> state{};
  std::memcpy(state.data() + kUidOff, admin_uid.data(), 16);
  alignas(8) std::array<std::uint8_t, 0x900> ctrl{};
  const std::uint64_t cls_bp_va = va_of(cls_bp.data());
  std::memcpy(ctrl.data() + kClassOff, &cls_bp_va, 8);
  std::memcpy(ctrl.data() + kNameOff, &i_inst, 4);
  const std::uint64_t state_va = va_of(state.data());
  std::memcpy(ctrl.data() + kPsOff, &state_va, 8);
  ctrl[kBadminOff] = 1;  // admin
  alignas(8) std::array<std::uint8_t, 24> chunk{};
  const std::uint64_t ctrl_va = va_of(ctrl.data());
  std::memcpy(chunk.data(), &ctrl_va, 8);
  alignas(8) std::array<std::uint64_t, 4> chunk_array{};
  chunk_array[0] = va_of(chunk.data());
  alignas(8) std::array<std::uint8_t, 0x20> objects_field{};
  const std::uint64_t ca = va_of(chunk_array.data());
  std::memcpy(objects_field.data(), &ca, 8);
  const std::int32_t num = 1;
  std::memcpy(objects_field.data() + 0x14, &num, 4);

  // Synthetic BroadcastChatMessage UFunction + a chat message + FFrame.
  constexpr std::uint64_t kVtable = 0x0BADF00DDEAD1234ULL;
  constexpr std::size_t kOffset = 0xd8;
  using ThunkFn = void (*)(void*, void*, void*);
  std::uint64_t thunk_va = 0;
  ThunkFn thunk = &fake_generic_thunk_a;
  std::memcpy(&thunk_va, &thunk, sizeof(thunk_va));
  auto ufunc = make_ufunction(kVtable, thunk_va, kOffset);
  const std::u16string sender = u"Admin";
  const std::u16string cmd_text = u"!echo hi";
  alignas(8) std::array<std::uint8_t, 0x40> message{};
  write_fstring(message.data(), 0x08, sender.c_str(), 6, 8);
  std::memcpy(message.data() + 0x18, admin_uid.data(), 16);   // SenderPlayerUId
  write_fstring(message.data(), 0x28, cmd_text.c_str(), 9, 16);
  alignas(8) std::array<std::uint8_t, 0x40> fframe{};
  void* locals = message.data();
  std::memcpy(fframe.data() + 0x18, &locals, sizeof(locals));
  __asm__ __volatile__("" : : "r"(nb.data()), "r"(&pm), "r"(cls_base.data()),
                       "r"(cls_bp.data()), "r"(state.data()), "r"(ctrl.data()),
                       "r"(chunk.data()), "r"(chunk_array.data()),
                       "r"(objects_field.data()), "r"(ufunc->data()),
                       "r"(message.data()) : "memory");

  // Profile facts wiring the synthetics (image_base 0 so rva == va).
  palmod::BuildProfile profile;
  profile.image_base = 0;
  profile.reflection_func_offset = kOffset;
  profile.reflection_vtable_va = kVtable;
  profile.reflection_fname_pool_blocks_va = blocks_va;
  profile.chat_broadcast_thunk_rva = thunk_va;
  profile.chat_fframe_locals_offset = 0x18;
  profile.chat_sender_offset = 0x08;
  profile.chat_text_offset = 0x28;
  profile.reflection_guobjectarray_objects_va = va_of(objects_field.data());
  profile.reflection_super_struct_offset = kSuperOff;
  profile.reflection_admin_controller_class = "PalPlayerController";
  profile.reflection_admin_player_state_offset = kPsOff;
  profile.reflection_admin_player_uid_offset = kUidOff;
  profile.reflection_admin_badmin_offset = kBadminOff;
  profile.reflection_admin_sender_uid_offset = 0x18;

  std::string routed_command;
  int routed_auth = -1;
  int route_calls = 0;
  palmod::HookCallbacks callbacks;
  callbacks.on_chat = [&](std::string_view text, std::string, std::uint64_t, int auth) {
    routed_command = std::string(text);
    routed_auth = auth;
    ++route_calls;
    return true;  // recognized command -> suppress
  };
  int events = 0;
  callbacks.on_event = [&](const palmod::PluginEvent&) { ++events; };

  palmod::ReflectionHookBackend backend;
  std::string error;
  CHECK(backend.install(profile, std::move(callbacks), error));

  // Fire the installed chat trampoline as the VM would.
  g_generic_orig_a = 0;
  ThunkFn installed = nullptr;
  std::memcpy(&installed, ufunc->data() + kOffset, sizeof(installed));
  installed(reinterpret_cast<void*>(0x1), fframe.data(), reinterpret_cast<void*>(0x2));

  CHECK(events == 1);                       // observed as a chat event
  CHECK(route_calls == 1);                  // recognized the `!` command
  CHECK(routed_command == "/echo hi");      // `!` translated to `/`
  CHECK(routed_auth == 2);                  // sender resolved to Admin (bAdmin=1)
  CHECK(g_generic_orig_a == 0);             // suppressed: original NOT chained

  backend.uninstall();
}

void test_generic_call() {
  // The write-side capstone: resolve a UFunction by its exec thunk (shared with
  // the hook path), encode its Parms, and dispatch on a target object through a
  // fake ProcessEvent — the whole encode -> resolve -> invoke chain, offline.
  constexpr std::uint64_t kVtable = 0x0BADF00DDEAD0099ULL;
  constexpr std::size_t kOffset = 0xd8;
  using ThunkFn = void (*)(void*, void*, void*);
  std::uint64_t thunk_va = 0;
  ThunkFn thunk = &fake_generic_thunk_a;
  std::memcpy(&thunk_va, &thunk, sizeof(thunk_va));
  auto ufunc = make_ufunction(kVtable, thunk_va, kOffset);
  std::uint64_t ufunc_base = 0;  // the UFunction object = slot - kOffset = buffer base
  void* ufunc_ptr = ufunc->data();
  std::memcpy(&ufunc_base, &ufunc_ptr, sizeof(ufunc_base));

  // Target object whose vtable slot 68 is our fake ProcessEvent.
  using PEFn = void (*)(void*, void*, void*);
  alignas(8) std::array<std::uint64_t, 80> vtable{};
  PEFn pe = &fake_process_event;
  std::uint64_t pe_va = 0;
  std::memcpy(&pe_va, &pe, sizeof(pe_va));
  vtable[68] = pe_va;
  alignas(8) std::array<std::uint8_t, 0x20> target{};
  std::uint64_t vtable_va = 0;
  void* vtable_ptr = vtable.data();
  std::memcpy(&vtable_va, &vtable_ptr, sizeof(vtable_va));
  std::memcpy(target.data(), &vtable_va, sizeof(vtable_va));
  __asm__ __volatile__("" : : "r"(vtable.data()), "r"(target.data()),
                       "r"(ufunc->data()) : "memory");
  std::uint64_t target_va = 0;
  void* target_ptr = target.data();
  std::memcpy(&target_va, &target_ptr, sizeof(target_va));

  palmod::ReflectionResolver resolver{kOffset, kVtable};
  palmod::GenericCallSpec spec;
  spec.thunk_va = thunk_va;
  spec.parms_size = 0x18;
  spec.params = {{"StaticItemId", "NameProperty", 0x00}, {"Count", "IntProperty", 0x08}};

  std::vector<palmod::ParamInput> inputs(2);
  inputs[0].name = "StaticItemId";
  inputs[0].is_text = true;
  inputs[0].text = "PalSphere";
  inputs[1].name = "Count";
  inputs[1].number = 3;
  const std::uint32_t kIndex = 0x9911;
  auto encode = [&](const std::string& s) -> std::uint32_t {
    return s == "PalSphere" ? kIndex : 0;
  };

  g_pe_calls = 0;
  g_pe_parms_copy = {};
  std::string error;
  CHECK(palmod::call_ufunction(spec, resolver, target_va, 68, inputs, encode, error));
  CHECK(error.empty());
  CHECK(g_pe_calls == 1);
  CHECK(g_pe_target == target.data());
  std::uint64_t seen_function = 0;
  std::memcpy(&seen_function, &g_pe_function, sizeof(seen_function));
  CHECK(seen_function == ufunc_base);  // resolved UFunction object (slot - kOffset)
  // The forwarded Parms decode back to the inputs.
  auto resolve = [&](std::uint32_t i) -> std::string {
    return i == kIndex ? "PalSphere" : "";
  };
  const auto decoded = palmod::decode_parms(g_pe_parms_copy.data(), spec.params, resolve);
  const auto* id = find_arg(decoded, "StaticItemId");
  CHECK(id && id->is_text && id->text == "PalSphere");
  const auto* count = find_arg(decoded, "Count");
  CHECK(count && count->number == 3.0);

  // Fail closed: a vtable slot with no ProcessEvent yields no call.
  g_pe_calls = 0;
  CHECK(!palmod::call_ufunction(spec, resolver, target_va, 79, inputs, encode, error));
  CHECK(!error.empty());
  CHECK(g_pe_calls == 0);
}

void test_plugin_events() {
  if (!palmod::PluginRuntime::lua_available()) return;
  namespace fs = std::filesystem;
  const auto root = fs::temp_directory_path() /
      ("palmod-events-" + std::to_string(getpid()));
  const auto plugin_dir = root / "event_echo";
  std::error_code ec;
  fs::create_directories(plugin_dir, ec);
  {
    std::ofstream manifest(plugin_dir / "manifest.json");
    manifest << R"({"schema_version":1,"id":"palmod.event_echo","version":"0.1.0",)"
             << R"("entrypoint":"main.lua","commands":[]})";
    std::ofstream lua(plugin_dir / "main.lua");
    lua << "palmod.on_event('chat', function(e)\n"
        << "  palmod.call('/Script/Test.Echo:Say', { message = 'echo:' .. e.text })\n"
        << "end)\n";
  }

  palmod::ActionQueue actions;
  palmod::CommandRouter commands;
  palmod::PluginRuntime plugins(actions);
  CHECK(plugins.load_directory(root, commands) == 1);

  palmod::PluginEvent event;
  event.kind = "chat";
  event.source = "Alice";
  event.text = "hello";
  CHECK(plugins.deliver_event(event) == 1);
  CHECK(plugins.wait_idle(std::chrono::seconds(2)));

  actions.bind_game_thread();
  std::vector<palmod::SemanticAction> executed;
  CHECK(actions.drain([&](const palmod::SemanticAction& a) {
    executed.push_back(a);
  }) == 1);
  if (!executed.empty()) {
    CHECK(executed[0].kind == palmod::ActionKind::CallFunction);
    CHECK(executed[0].function_path == "/Script/Test.Echo:Say");
    const palmod::ParamInput* message = nullptr;
    for (const auto& arg : executed[0].call_args) {
      if (arg.name == "message") message = &arg;
    }
    CHECK(message != nullptr && message->text == "echo:hello");
    CHECK(executed[0].actor == "Alice");
  }

  // An event kind nobody subscribed to reaches zero plugins.
  palmod::PluginEvent unrelated;
  unrelated.kind = "player.join";
  CHECK(plugins.deliver_event(unrelated) == 0);

  plugins.stop();
  fs::remove_all(root, ec);
}

void test_plugin_stdlib() {
  if (!palmod::PluginRuntime::lua_available()) return;
  namespace fs = std::filesystem;
  const auto root = fs::temp_directory_path() /
      ("palmod-stdlib-" + std::to_string(getpid()));
  const auto plugin_dir = root / "stdlib_probe";
  std::error_code ec;
  fs::create_directories(plugin_dir, ec);
  {
    std::ofstream manifest(plugin_dir / "manifest.json");
    manifest << R"({"schema_version":1,"id":"palmod.stdlib_probe","version":"0.1.0",)"
             << R"("entrypoint":"main.lua","commands":[]})";
    // The stdlib preamble runs before the plugin body: its helpers must already
    // be present, and paginate must split deterministically (pure Lua). A failed
    // assert aborts init, so the plugin would not count as loaded.
    std::ofstream lua(plugin_dir / "main.lua");
    lua << "assert(type(palmod.reply) == 'function', 'reply missing')\n"
        << "assert(type(palmod.broadcast) == 'function', 'broadcast missing')\n"
        << "assert(type(palmod.inventory_of) == 'function', 'inventory_of missing')\n"
        << "assert(type(palmod.paginate) == 'function', 'paginate missing')\n"
        << "local p = palmod.paginate({'aa', 'bb', 'cc'}, 3)\n"
        << "assert(#p == 3, 'expected 3 pages, got ' .. #p)\n"
        << "assert(p[1] == 'aa', 'page1 was ' .. p[1])\n"
        << "local one = palmod.paginate({'aa', 'bb'}, 80)\n"
        << "assert(#one == 1 and one[1] == 'aa, bb', 'joined page was ' .. one[1])\n";
  }

  palmod::ActionQueue actions;
  palmod::CommandRouter commands;
  palmod::PluginRuntime plugins(actions);
  // A missing stdlib or a failed assert would report 0 loaded.
  CHECK(plugins.load_directory(root, commands) == 1);
  plugins.stop();
  fs::remove_all(root, ec);
}

void test_generic_hook_lua() {
  if (!palmod::PluginRuntime::lua_available()) return;
  namespace fs = std::filesystem;
  const auto root = fs::temp_directory_path() /
      ("palmod-hook-" + std::to_string(getpid()));
  const auto plugin_dir = root / "hook_echo";
  std::error_code ec;
  fs::create_directories(plugin_dir, ec);
  {
    std::ofstream manifest(plugin_dir / "manifest.json");
    manifest << R"({"schema_version":1,"id":"palmod.hook_echo","version":"0.1.0",)"
             << R"("entrypoint":"main.lua","commands":[]})";
    // palmod.hook by function name; read decoded params from event.args.
    std::ofstream lua(plugin_dir / "main.lua");
    lua << "palmod.hook('AddItem_ServerInternal', function(e)\n"
        << "  local sum = 0\n"
        << "  for _, v in ipairs(e.args.Scores) do sum = sum + v end\n"
        << "  local msg = string.format('%s:%d:%d:%d', e.args.StaticItemId,\n"
        << "                            e.args.Count, sum, e.args.Where.X)\n"
        << "  palmod.call('/Script/Test.Echo:Say', { message = 'got:' .. msg })\n"
        << "end)\n";
  }

  palmod::ActionQueue actions;
  palmod::CommandRouter commands;
  palmod::PluginRuntime plugins(actions);
  CHECK(plugins.load_directory(root, commands) == 1);
  // pal.hook registered a subscription the runtime would install a hook for.
  CHECK(plugins.subscribed_event_kinds().contains("additem_serverinternal"));

  // Deliver a decoded generic-hook call (as ReflectionHookBackend would).
  palmod::PluginEvent event;
  event.kind = "AddItem_ServerInternal";
  event.source = "system";
  palmod::EventArg item;
  item.name = "StaticItemId";
  item.is_text = true;
  item.text = "BerryRed";
  palmod::EventArg count;
  count.name = "Count";
  count.number = 5;
  palmod::EventArg scores;  // array arg -> a Lua table the plugin sums
  scores.name = "Scores";
  scores.is_array = true;
  for (double v : {10.0, 20.0, 30.0}) {
    palmod::EventArg element;
    element.number = v;
    scores.items.push_back(element);
  }
  palmod::EventArg where;  // struct arg -> a keyed Lua table {X = 7}
  where.name = "Where";
  where.is_struct = true;
  palmod::EventArg where_x;
  where_x.name = "X";
  where_x.number = 7;
  where.items.push_back(where_x);
  event.args = {item, count, scores, where};
  CHECK(plugins.deliver_event(event) == 1);
  CHECK(plugins.wait_idle(std::chrono::seconds(2)));

  actions.bind_game_thread();
  std::vector<palmod::SemanticAction> executed;
  CHECK(actions.drain([&](const palmod::SemanticAction& a) {
    executed.push_back(a);
  }) == 1);
  if (!executed.empty()) {
    // "got:<name>:<count>:<sum of Scores array>:<Where.X struct field>"
    CHECK(executed[0].kind == palmod::ActionKind::CallFunction);
    const palmod::ParamInput* message = nullptr;
    for (const auto& arg : executed[0].call_args) {
      if (arg.name == "message") message = &arg;
    }
    CHECK(message != nullptr && message->text == "got:BerryRed:5:60:7");
    CHECK(executed[0].actor == "system");
  }

  plugins.stop();
  fs::remove_all(root, ec);
}

void test_utf16_to_utf8() {
  auto u16 = [](std::initializer_list<char16_t> units) {
    return std::u16string(units);
  };
  // ASCII (the chat text we captured live).
  auto ascii = u16({0x0050, 0x0041, 0x004c, 0x004d, 0x004f, 0x0044});  // "PALMOD"
  CHECK(palmod::utf16_to_utf8(ascii.data(), ascii.size()) == "PALMOD");
  // 2-byte (U+00E9 é) and 3-byte (U+20AC €).
  auto latin = u16({0x00e9});
  CHECK(palmod::utf16_to_utf8(latin.data(), latin.size()) == "\xc3\xa9");
  auto euro = u16({0x20ac});
  CHECK(palmod::utf16_to_utf8(euro.data(), euro.size()) == "\xe2\x82\xac");
  // Surrogate pair (U+1F600 😀) -> 4-byte UTF-8.
  auto emoji = u16({0xd83d, 0xde00});
  CHECK(palmod::utf16_to_utf8(emoji.data(), emoji.size()) == "\xf0\x9f\x98\x80");
  // Lone high surrogate -> U+FFFD.
  auto lone = u16({0xd83d});
  CHECK(palmod::utf16_to_utf8(lone.data(), lone.size()) == "\xef\xbf\xbd");
  // Bounds and null.
  CHECK(palmod::utf16_to_utf8(nullptr, 0).empty());
  CHECK(palmod::utf16_to_utf8(ascii.data(), 0).empty());
}

void test_profile_reflection() {
  const auto fp = palmod::fingerprint_self();
  CHECK(fp.fingerprint.has_value());
  if (!fp.fingerprint) return;
  std::string error;
  auto with = palmod::BuildProfile::parse_json(
      profile_json(*fp.fingerprint, "validated", "\"inventory.give\"",
                   ",\"reflection\":{\"ufunction_func_offset\":216,"
                   "\"ufunction_vtable_va\":27557912,"
                   "\"chat\":{\"broadcast_thunk_rva\":109582752,"
                   "\"fframe_locals_offset\":24,\"message_sender_offset\":8,"
                   "\"message_text_offset\":40}}"),
      error);
  CHECK(with.has_value());
  CHECK(with && with->has_reflection());
  CHECK(with && with->reflection_func_offset == 0xd8);
  CHECK(with && with->reflection_vtable_va == 0x1a48018);
  CHECK(with && with->has_chat_hook());
  CHECK(with && with->chat_broadcast_thunk_rva == 0x68819a0);
  CHECK(with && with->chat_sender_offset == 0x08);
  CHECK(with && with->chat_text_offset == 0x28);

  // Absent reflection is allowed, and implies no chat hook.
  auto without = palmod::BuildProfile::parse_json(profile_json(*fp.fingerprint), error);
  CHECK(without.has_value());
  CHECK(without && !without->has_reflection());
  CHECK(without && !without->has_chat_hook());

  // An out-of-range offset is rejected.
  auto bad = palmod::BuildProfile::parse_json(
      profile_json(*fp.fingerprint, "validated", "\"inventory.give\"",
                   ",\"reflection\":{\"ufunction_func_offset\":0,"
                   "\"ufunction_vtable_va\":1}"),
      error);
  CHECK(!bad.has_value());
}


void test_reflection_resolver_from_profile() {
  const auto fp = palmod::fingerprint_self();
  CHECK(fp.fingerprint.has_value());
  if (!fp.fingerprint) return;
  std::string error;
  auto profile = palmod::BuildProfile::parse_json(
      profile_json(*fp.fingerprint, "validated", "\"inventory.give\"",
                   ",\"reflection\":{\"ufunction_func_offset\":216,"
                   "\"ufunction_vtable_va\":27557912}"),
      error);
  CHECK(profile.has_value());
  if (!profile) return;
  auto resolver = palmod::make_reflection_resolver(*profile);
  CHECK(resolver.has_value());
  CHECK(resolver && resolver->func_offset == 0xd8);
  CHECK(resolver && resolver->vtable_va == 0x1a48018);

  // A profile without reflection facts yields no resolver (fail closed).
  auto bare = palmod::BuildProfile::parse_json(profile_json(*fp.fingerprint), error);
  CHECK(bare.has_value());
  CHECK(bare && !palmod::make_reflection_resolver(*bare).has_value());
}

void test_reflection_resolver() {
  // Build a synthetic UFunction on the heap: [vtable] ... [Func = thunk] at 0xd8.
  constexpr std::uint64_t kVtable = 0xABCDEF0011223344ULL;
  constexpr std::uint64_t kThunk = 0x0000000006C6E980ULL;  // a plausible thunk VA
  constexpr std::size_t kOffset = 0xd8;
  auto object = std::make_unique<std::array<std::uint8_t, kOffset + 8>>();
  object->fill(0);
  std::memcpy(object->data(), &kVtable, sizeof(kVtable));
  std::memcpy(object->data() + kOffset, &kThunk, sizeof(kThunk));
  // The resolver reads this object through an opaque raw memory scan the
  // optimizer cannot see, so force the synthetic writes to be kept.
  __asm__ __volatile__("" : : "r"(object->data()) : "memory");

  palmod::ReflectionResolver resolver{kOffset, kVtable};
  std::string error;
  void** slot = resolver.resolve(kThunk, error);
  CHECK(slot != nullptr);
  CHECK(error.empty());
  if (slot != nullptr) {
    CHECK(reinterpret_cast<std::uintptr_t>(slot) ==
          reinterpret_cast<std::uintptr_t>(object->data() + kOffset));
  }

  // A thunk value present without the matching vtable header is not resolved.
  error.clear();
  palmod::ReflectionResolver wrong_vtable{kOffset, kVtable ^ 0x1ULL};
  CHECK(wrong_vtable.resolve(kThunk, error) == nullptr);
  CHECK(!error.empty());

  // A thunk value that is not present at all is not resolved.
  error.clear();
  CHECK(resolver.resolve(0xDEADBEEFDEADBEEFULL, error) == nullptr);
  CHECK(!error.empty());
}

}  // namespace

int main() {
  test_sha256();
  test_fingerprint_and_profile();
  test_handles();
  test_player_directory();
  test_reflection_hook_backend();
  test_reflection_resolver();
  test_reflection_resolver_from_profile();
  test_utf16_to_utf8();
  test_chat_decode();
  test_chat_hook();
  test_parms_decode();
  test_parms_encode();
  test_parms_encode_containers();
  test_object_walk();
  test_object_array();
  test_player_auth();
  test_invoke();
  test_fname_pool();
  test_fname_lookup();
  test_generic_hook();
  test_reflection_generic_hook();
  test_chat_command_routing();
  test_generic_call();
  test_plugin_events();
  test_plugin_stdlib();
  test_generic_hook_lua();
  test_profile_reflection();
  test_command_parser();
  test_control_socket();
  test_environment_contract();
  test_lua_give_item();
  test_sealed_profile_runtime();
  if (failures != 0) {
    std::cerr << failures << " native test(s) failed\n";
    return 1;
  }
  std::cout << "all native tests passed\n";
  return 0;
}
