#pragma once

#include "palmod/fingerprint.hpp"
#include "palmod/parms_decode.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace palmod {

struct HookProfile {
  std::string name;
  std::uint64_t rva{0};
  std::string expected_bytes;
};

struct BuildProfile {
  std::uint32_t schema{0};
  std::string profile_id;
  std::string status;
  std::string steam_build_id;
  std::string sha256;
  std::string elf_build_id;
  std::string elf_type;
  std::uint64_t image_base{0};
  std::uintmax_t executable_size{0};
  std::map<std::string, HookProfile, std::less<>> hooks;
  // Dynamically observed Unreal reflection layout (0 = absent). Used by the
  // reflection hook backend to locate UFunction::Func slots at runtime.
  std::uint64_t reflection_func_offset{0};
  std::uint64_t reflection_vtable_va{0};
  // FFrame Locals (Parms) offset shared by every exec-thunk on this build.
  std::uint64_t reflection_fframe_locals_offset{0x18};
  // VA of FNamePool.Blocks (0 = absent). Lets generic hooks resolve NameProperty
  // arguments to strings instead of raw indices.
  std::uint64_t reflection_fname_pool_blocks_va{0};
  // Inventory adapter facts (0/empty = absent): the AddItem_ServerInternal impl
  // Object-array walker facts: the GUObjectArray Objects-field VA (to find objects
  // and functions by name in-process) and the UStruct::SuperStruct offset (for the
  // IsA class-chain check). Used by the generic call path + the admin check.
  std::uint64_t reflection_guobjectarray_objects_va{0};
  std::uint64_t reflection_super_struct_offset{0};
  // Game-thread drain pump (0 = absent): the GEngine global-pointer VA and the
  // UEngine::Tick vtable slot index. Swapping that entry drains the action queue
  // once per frame on the game thread (UE4SS's EngineTick method).
  std::uint64_t reflection_gengine_global_va{0};
  std::uint64_t reflection_engine_tick_vtable_slot{0};
  // UObject::ProcessEvent vtable slot — the build-wide dispatch entry used to call
  // any UFunction generically (read from the target object's own vtable). 0 = the
  // generic call path is unavailable.
  std::uint64_t reflection_process_event_slot{0};
  // Server-side admin check (empty/0 = absent): honor Palworld's admin login by
  // reading PalPlayerController.bAdmin, correlated to the chat SenderPlayerUId.
  std::string reflection_admin_controller_class;
  std::uint64_t reflection_admin_player_state_offset{0};
  std::uint64_t reflection_admin_player_uid_offset{0};
  std::uint64_t reflection_admin_badmin_offset{0};
  std::uint64_t reflection_admin_sender_uid_offset{0};
  // Chat hook facts (0 = absent): BroadcastChatMessage exec-thunk RVA, the
  // FFrame Locals offset, and the FPalChatMessage sender/text FString offsets.
  std::uint64_t chat_broadcast_thunk_rva{0};
  std::uint64_t chat_fframe_locals_offset{0};
  std::uint64_t chat_sender_offset{0};
  std::uint64_t chat_text_offset{0};

  bool has_reflection() const {
    return reflection_func_offset != 0 && reflection_vtable_va != 0;
  }
  bool has_chat_hook() const {
    return has_reflection() && chat_broadcast_thunk_rva != 0;
  }

  static std::optional<BuildProfile> parse_json(std::string_view json,
                                                std::string& error);
  bool exactly_matches(const BuildFingerprint& actual,
                       std::string& reason) const;
};

}  // namespace palmod
