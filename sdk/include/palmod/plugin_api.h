#ifndef PALMOD_PLUGIN_API_H
#define PALMOD_PLUGIN_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PALMOD_PLUGIN_ABI_VERSION 1u

typedef uint64_t palmod_handle_t;

typedef enum palmod_auth_state {
  PALMOD_AUTH_UNKNOWN = 0,
  PALMOD_AUTH_PLAYER = 1,
  PALMOD_AUTH_ADMIN = 2
} palmod_auth_state;

typedef enum palmod_action_kind {
  PALMOD_ACTION_INVALID = 0,
  PALMOD_ACTION_GIVE_ITEM = 1,
  PALMOD_ACTION_SEND_MESSAGE = 2
} palmod_action_kind;

/*
 * The native ABI is deliberately opaque. Plugins never receive Unreal Engine
 * pointers. Handles encode an index and generation and are invalidated by the
 * host when the referenced object leaves scope.
 */
typedef struct palmod_plugin_descriptor {
  uint32_t abi_version;
  const char *id;
  const char *version;
} palmod_plugin_descriptor;

#ifdef __cplusplus
}
#endif

#endif
