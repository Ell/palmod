#!/usr/bin/env python3
"""Query a generated reflection dump. No server needed — reads the JSON.

    python reverse/bin/schema_query.py <struct-or-function-name> [--dump path]
    python reverse/bin/schema_query.py --find Chat [--dump path]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib.schema import Schema  # noqa: E402

DEFAULT_DUMP = REVERSE_ROOT.parent / "build" / "palworld-24088465-reflection.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", help="struct/function to describe")
    parser.add_argument("--find", help="list names containing this substring")
    parser.add_argument("--dump", type=Path, default=DEFAULT_DUMP)
    args = parser.parse_args()

    if not args.dump.exists():
        print(f"no dump at {args.dump}; run `make lab-dump` first", file=sys.stderr)
        return 2
    schema = Schema.load(args.dump)
    print(f"# {len(schema)} structs loaded from {args.dump.name}")

    if args.find:
        for name in schema.find(args.find):
            print(f"  [{schema.kind(name)}] {name}")
        return 0
    if not args.name:
        parser.print_help()
        return 2

    kind = schema.kind(args.name)
    if kind is None:
        print(f"'{args.name}' not found (try --find)")
        return 1
    print(f"\n{args.name} [{kind}]")
    for f in schema.fields(args.name):
        inner = f" <{f.inner}>" if f.inner else ""
        print(f"  +{f.offset:<5} {f.name} ({f.type}{inner}) elem={f.elem_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
