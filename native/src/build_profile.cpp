#include "palmod/build_profile.hpp"

#include "palmod/json.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>

namespace palmod {
namespace {

std::optional<std::string> require_string(const json::Object& object,
                                          std::string_view key,
                                          std::string& error) {
  const auto* value = json::get(object, key);
  if (!value || !value->string() || value->string()->empty()) {
    error = "profile field '" + std::string(key) + "' must be a non-empty string";
    return std::nullopt;
  }
  return *value->string();
}

std::optional<std::uint64_t> unsigned_value(const json::Value& value) {
  if (const auto* integer = value.integer(); integer && *integer >= 0) {
    return static_cast<std::uint64_t>(*integer);
  }
  if (const auto* text = value.string()) {
    std::string_view token = *text;
    int base = 10;
    if (token.starts_with("0x") || token.starts_with("0X")) {
      token.remove_prefix(2);
      base = 16;
    }
    std::uint64_t parsed = 0;
    const auto converted = std::from_chars(token.data(), token.data() + token.size(), parsed, base);
    if (converted.ec == std::errc{} && converted.ptr == token.data() + token.size()) return parsed;
  }
  return std::nullopt;
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool require_exact_string(const json::Object& object, std::string_view key,
                          std::string_view expected, std::string& error) {
  auto value = require_string(object, key, error);
  if (!value) return false;
  if (*value != expected) {
    error = "profile field '" + std::string(key) + "' must equal '" +
            std::string(expected) + "'";
    return false;
  }
  return true;
}

}  // namespace

std::optional<BuildProfile> BuildProfile::parse_json(std::string_view text,
                                                     std::string& error) {
  auto parsed = json::parse(text);
  if (!parsed.value) {
    error = "invalid profile JSON: " + parsed.error;
    return std::nullopt;
  }
  const auto* root = parsed.value->object();
  if (!root) {
    error = "profile root must be an object";
    return std::nullopt;
  }

  BuildProfile profile;
  const auto* schema = json::get(*root, "schema");
  if (!schema || !schema->integer() || *schema->integer() != 1) {
    error = "profile schema must be 1";
    return std::nullopt;
  }
  profile.schema = 1;
  auto status = require_string(*root, "status", error);
  auto id = require_string(*root, "profile_id", error);
  auto steam_build_id = require_string(*root, "steam_build_id", error);
  if (!status || !id || !steam_build_id) return std::nullopt;
  profile.status = *status;
  profile.profile_id = *id;
  profile.steam_build_id = *steam_build_id;

  const auto* elf_value = json::get(*root, "elf");
  const auto* elf = elf_value ? elf_value->object() : nullptr;
  if (!elf) {
    error = "profile elf field must be an object";
    return std::nullopt;
  }
  auto sha = require_string(*elf, "sha256", error);
  auto build_id = require_string(*elf, "build_id", error);
  auto elf_type = require_string(*elf, "elf_type", error);
  if (!sha || !build_id || !elf_type ||
      !require_exact_string(*elf, "machine", "x86_64", error) ||
      !require_exact_string(*elf, "endian", "little", error)) return std::nullopt;
  const auto* bits = json::get(*elf, "bits");
  const auto* image_base = json::get(*elf, "image_base");
  const auto* file_size = json::get(*elf, "file_size");
  if (!bits || !bits->integer() || *bits->integer() != 64 || !image_base || !file_size) {
    error = "profile elf bits/image_base/file_size are missing or malformed";
    return std::nullopt;
  }
  auto parsed_base = unsigned_value(*image_base);
  auto parsed_size = unsigned_value(*file_size);
  if (!parsed_base || !parsed_size) {
    error = "profile elf image_base/file_size must be unsigned integers";
    return std::nullopt;
  }
  if (*elf_type != "ET_EXEC") {
    error = "only ET_EXEC server profiles are supported";
    return std::nullopt;
  }
  profile.sha256 = lower(*sha);
  profile.elf_build_id = lower(*build_id);
  profile.elf_type = *elf_type;
  profile.image_base = *parsed_base;
  profile.executable_size = *parsed_size;
  if (profile.sha256.size() != 64 || profile.elf_build_id.empty()) {
    error = "profile has malformed SHA-256 or ELF build-id";
    return std::nullopt;
  }

  const auto* anchors_value = json::get(*root, "anchors");
  const auto* anchors = anchors_value ? anchors_value->object() : nullptr;
  if (!anchors || anchors->empty()) {
    error = "validated profile must contain at least one anchor";
    return std::nullopt;
  }
  for (const auto& [name, value] : *anchors) {
    const auto* anchor = value.object();
    if (!anchor) {
      error = "anchor '" + name + "' must be an object";
      return std::nullopt;
    }
    const auto* rva = json::get(*anchor, "rva");
    auto expected = require_string(*anchor, "expected_bytes", error);
    const auto* validators = json::get(*anchor, "validators");
    if (!rva || !expected || !validators || !validators->array()) {
      if (error.empty()) error = "anchor '" + name + "' is missing critical fields";
      return std::nullopt;
    }
    auto parsed_rva = unsigned_value(*rva);
    if (!parsed_rva || expected->empty()) {
      error = "anchor '" + name + "' has invalid rva/expected_bytes";
      return std::nullopt;
    }
    for (const auto& validator : *validators->array()) {
      if (!validator.string()) {
        error = "anchor '" + name + "' validators must be strings";
        return std::nullopt;
      }
    }
    profile.hooks.emplace(name, HookProfile{name, *parsed_rva, *expected});
  }


  if (const auto* reflection_value = json::get(*root, "reflection")) {
    const auto* reflection = reflection_value->object();
    if (!reflection) {
      error = "profile reflection must be an object";
      return std::nullopt;
    }
    const auto* offset = json::get(*reflection, "ufunction_func_offset");
    const auto* vtable = json::get(*reflection, "ufunction_vtable_va");
    if (!offset || !vtable) {
      error = "reflection requires ufunction_func_offset and ufunction_vtable_va";
      return std::nullopt;
    }
    auto offset_value = unsigned_value(*offset);
    auto vtable_value = unsigned_value(*vtable);
    if (!offset_value || !vtable_value || *offset_value == 0 ||
        *offset_value > 0x1000 || *vtable_value == 0) {
      error = "reflection facts are out of the expected range";
      return std::nullopt;
    }
    profile.reflection_func_offset = *offset_value;
    profile.reflection_vtable_va = *vtable_value;

    if (const auto* chat_value = json::get(*reflection, "chat")) {
      const auto* chat = chat_value->object();
      if (!chat) {
        error = "reflection.chat must be an object";
        return std::nullopt;
      }
      const auto* thunk_v = json::get(*chat, "broadcast_thunk_rva");
      const auto* locals_v = json::get(*chat, "fframe_locals_offset");
      const auto* sender_v = json::get(*chat, "message_sender_offset");
      const auto* text_v = json::get(*chat, "message_text_offset");
      if (!thunk_v || !locals_v || !sender_v || !text_v) {
        error = "reflection.chat requires broadcast_thunk_rva and the offsets";
        return std::nullopt;
      }
      const auto thunk = unsigned_value(*thunk_v);
      const auto locals = unsigned_value(*locals_v);
      const auto sender = unsigned_value(*sender_v);
      const auto text_off = unsigned_value(*text_v);
      if (!thunk || !locals || !sender || !text_off || *thunk == 0) {
        error = "reflection.chat offsets must be unsigned integers";
        return std::nullopt;
      }
      profile.chat_broadcast_thunk_rva = *thunk;
      profile.chat_fframe_locals_offset = *locals;
      profile.chat_sender_offset = *sender;
      profile.chat_text_offset = *text_off;
    }

    // The FFrame Locals (Parms) offset is a per-build constant shared by every
    // exec-thunk; generic by-name hooks read it here (default 0x18).
    if (const auto* locals_v = json::get(*reflection, "fframe_locals_offset")) {
      const auto locals = unsigned_value(*locals_v);
      if (!locals || *locals > 0x1000) {
        error = "reflection.fframe_locals_offset must be a small unsigned integer";
        return std::nullopt;
      }
      profile.reflection_fframe_locals_offset = *locals;
    }
    if (const auto* pool_v = json::get(*reflection, "fname_pool_blocks_va")) {
      const auto pool = unsigned_value(*pool_v);
      if (!pool || *pool == 0) {
        error = "reflection.fname_pool_blocks_va must be a nonzero unsigned integer";
        return std::nullopt;
      }
      profile.reflection_fname_pool_blocks_va = *pool;
    }
    if (const auto* pe_v = json::get(*reflection, "process_event_vtable_slot")) {
      const auto slot = unsigned_value(*pe_v);
      if (!slot || *slot > 0x1000) {
        error = "reflection.process_event_vtable_slot must be a small unsigned integer";
        return std::nullopt;
      }
      profile.reflection_process_event_slot = *slot;
    }
    if (const auto* objs_v = json::get(*reflection, "guobjectarray_objects_va")) {
      const auto objs = unsigned_value(*objs_v);
      if (!objs || *objs == 0) {
        error = "reflection.guobjectarray_objects_va must be a nonzero unsigned integer";
        return std::nullopt;
      }
      profile.reflection_guobjectarray_objects_va = *objs;
    }
    if (const auto* super_v = json::get(*reflection, "super_struct_offset")) {
      const auto super = unsigned_value(*super_v);
      if (!super || *super > 0x1000) {
        error = "reflection.super_struct_offset must be a small unsigned integer";
        return std::nullopt;
      }
      profile.reflection_super_struct_offset = *super;
    }

    // Optional game-thread drain pump (GEngine::Tick vtable swap).
    if (const auto* tick_value = json::get(*reflection, "engine_tick")) {
      const auto* tick = tick_value->object();
      if (!tick) {
        error = "reflection.engine_tick must be an object";
        return std::nullopt;
      }
      const auto* gengine_v = json::get(*tick, "gengine_global_va");
      const auto* slot_v = json::get(*tick, "tick_vtable_slot");
      if (!gengine_v || !slot_v) {
        error = "reflection.engine_tick requires gengine_global_va and tick_vtable_slot";
        return std::nullopt;
      }
      const auto gengine = unsigned_value(*gengine_v);
      const auto slot = unsigned_value(*slot_v);
      if (!gengine || *gengine == 0 || !slot || *slot > 0x1000) {
        error = "reflection.engine_tick values are out of the expected range";
        return std::nullopt;
      }
      profile.reflection_gengine_global_va = *gengine;
      profile.reflection_engine_tick_vtable_slot = *slot;
    }

    // Optional server-side admin check facts.
    if (const auto* admin_value = json::get(*reflection, "admin")) {
      const auto* admin = admin_value->object();
      if (!admin) {
        error = "reflection.admin must be an object";
        return std::nullopt;
      }
      auto klass = require_string(*admin, "controller_class", error);
      const auto* ps_v = json::get(*admin, "player_state_offset");
      const auto* uid_v = json::get(*admin, "player_uid_offset");
      const auto* badmin_v = json::get(*admin, "badmin_offset");
      const auto* sender_v = json::get(*admin, "sender_player_uid_offset");
      if (!klass || !ps_v || !uid_v || !badmin_v || !sender_v) {
        error = "reflection.admin requires controller_class + the four offsets";
        return std::nullopt;
      }
      const auto ps = unsigned_value(*ps_v);
      const auto uid = unsigned_value(*uid_v);
      const auto badmin = unsigned_value(*badmin_v);
      const auto sender = unsigned_value(*sender_v);
      if (!ps || !uid || !badmin || !sender || *badmin == 0) {
        error = "reflection.admin offsets must be valid unsigned integers";
        return std::nullopt;
      }
      profile.reflection_admin_controller_class = std::move(*klass);
      profile.reflection_admin_player_state_offset = *ps;
      profile.reflection_admin_player_uid_offset = *uid;
      profile.reflection_admin_badmin_offset = *badmin;
      profile.reflection_admin_sender_uid_offset = *sender;
    }
  }

  return profile;
}

bool BuildProfile::exactly_matches(const BuildFingerprint& actual,
                                   std::string& reason) const {
  if (status != "validated") {
    reason = "profile is not validated (status=" + status + ")";
    return false;
  }
  if (sha256 != lower(actual.sha256)) {
    reason = "executable SHA-256 mismatch";
    return false;
  }
  if (elf_build_id != lower(actual.elf_build_id)) {
    reason = "ELF build-id mismatch";
    return false;
  }
  if (executable_size != actual.size) {
    reason = "executable size mismatch";
    return false;
  }
  return true;
}

}  // namespace palmod
