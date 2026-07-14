#!/usr/bin/env python3
"""Derive the runtime's build-specific facts from the reflection dump.

Closes the dump -> config loop: instead of hardcoding "chat Sender @ 0x08,
Message @ 0x28" or the inventory ABI in C++, we read them from our own generated
mappings. Emits a JSON facts blob and cross-checks the values the native runtime
currently hardcodes, so drift is caught. No server needed.

    python reverse/bin/gen_facts.py [--dump path] [--check]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib.schema import Schema  # noqa: E402

DEFAULT_DUMP = REVERSE_ROOT.parent / "build" / "palworld-24088465-reflection.json"

# What the native runtime currently hardcodes — keep these in sync with the dump.
EXPECTED = {
    "chat.sender_offset": 0x08,
    "chat.message_offset": 0x28,
}


def derive(schema: Schema) -> dict:
    facts: dict = {"build": "palworld-linux-24088465", "chat": {}, "inventory": {}}
    sender = schema.field_offset("PalChatMessage", "Sender")
    message = schema.field_offset("PalChatMessage", "Message")
    facts["chat"] = {"struct": "PalChatMessage",
                     "sender_offset": sender, "message_offset": message}
    params = schema.function_params("AddItem_ServerInternal")
    if params:
        facts["inventory"] = {
            "function": "AddItem_ServerInternal",
            "params": [{"name": p.name, "type": p.type, "offset": p.offset}
                       for p in params],
        }
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=Path, default=DEFAULT_DUMP)
    parser.add_argument("--check", action="store_true",
                        help="verify derived facts match the runtime's hardcoded values")
    args = parser.parse_args()
    if not args.dump.exists():
        print(f"no dump at {args.dump}; run `make lab-dump` first", file=sys.stderr)
        return 2

    schema = Schema.load(args.dump)
    facts = derive(schema)
    print(json.dumps(facts, indent=1))

    if args.check:
        actual = {
            "chat.sender_offset": facts["chat"]["sender_offset"],
            "chat.message_offset": facts["chat"]["message_offset"],
        }
        bad = {k: (EXPECTED[k], actual.get(k)) for k in EXPECTED
               if actual.get(k) != EXPECTED[k]}
        if bad:
            print(f"\nDRIFT: dump disagrees with hardcoded runtime facts: {bad}",
                  file=sys.stderr)
            return 1
        print("\ncheck: dump matches the runtime's hardcoded facts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
