"""Live UE 5.1 reflection reader for Palworld build 24088465.

All constants below were recovered live and confirmed stable via
reverse/bin/find_reflection.py (see docs/design/reflection-mappings.md). This
reads a running server's reflection out of /proc/<pid>/mem to enumerate every
UStruct/UClass/UFunction and its properties with authoritative memory offsets —
the basis for generating our own mappings.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Fixed globals (VA).
IMAGE_BASE = 0x200000
GUOBJECTARRAY_OBJECTS = 0x0c11d888  # FChunkedFixedUObjectArray.Objects (FUObjectItem**)
FNAMEPOOL_BLOCKS = 0x0c07b0c0       # FNamePool.Blocks (uint8*[])
UFUNCTION_FUNC_OFFSET = 0xd8        # UFunction::Func (exec thunk pointer)
IMAGE_END = 0x0d000000             # crude upper bound of the binary image
FUNCTION_KINDS = {"Function", "DelegateFunction", "SparseDelegateFunction"}

# FUObjectArray / chunked array.
FUOBJECTITEM_SIZE = 24              # {UObject* Object, i32 Flags, i32 ClusterRoot, i32 Serial}
NUM_ELEMENTS_OFFSET = 0x14         # FChunkedFixedUObjectArray.NumElements, rel. to Objects field
ELEMENTS_PER_CHUNK = 64 * 1024

# UObjectBase.
UOBJ_CLASS = 0x10                  # ClassPrivate (UClass*)
UOBJ_NAME = 0x18                   # NamePrivate (FName cmp index, i32)
UOBJ_OUTER = 0x20                  # OuterPrivate (UObject*)

# UStruct / FField / FProperty.
USTRUCT_CHILDPROPS = 0x50          # ChildProperties (FField*)
FFIELD_CLASS = 0x08                # FFieldClass* (has FName at +0x00)
FFIELD_NEXT = 0x20
FFIELD_NAME = 0x28
FPROP_ELEMSIZE = 0x38              # ElementSize (e.g. 16 = sizeof FString)
FPROP_OFFSET = 0x4c               # Offset_Internal (the memory offset)
FPROP_INNER = 0x78                # StructProperty.Struct / ArrayProperty.Inner /
                                  # ObjectProperty.PropertyClass / EnumProperty.Enum

# Properties whose inner reference at +0x78 is a UObject (name via NamePrivate).
_UOBJECT_INNER = {"StructProperty", "ObjectProperty", "ClassProperty",
                  "SoftObjectProperty", "SoftClassProperty", "WeakObjectProperty",
                  "LazyObjectProperty", "InterfaceProperty", "EnumProperty",
                  "ByteProperty"}
_CONTAINER = {"ArrayProperty", "SetProperty"}

# Object classes whose instances are UStructs with a ChildProperties chain.
STRUCT_CLASS_NAMES = {"Class", "ScriptStruct", "Function", "DelegateFunction",
                      "SparseDelegateFunction"}


class Mem:
    """Persistent reader over /proc/<pid>/mem (fast repeated preads)."""

    def __init__(self, pid: int):
        self._f = open(f"/proc/{pid}/mem", "rb", buffering=0)

    def read(self, va: int, n: int) -> bytes | None:
        try:
            self._f.seek(va)
            return self._f.read(n)
        except (OSError, ValueError, OverflowError):
            return None

    def u64(self, va: int) -> int | None:
        b = self.read(va, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def i32(self, va: int) -> int | None:
        b = self.read(va, 4)
        return struct.unpack("<i", b)[0] if b and len(b) == 4 else None

    def close(self):
        self._f.close()


class FNames:
    def __init__(self, mem: Mem, blocks_va: int = FNAMEPOOL_BLOCKS):
        self._mem = mem
        self._blocks = blocks_va
        self._cache: dict[int, str | None] = {}

    def get(self, cmp_index: int | None) -> str | None:
        if cmp_index is None or cmp_index <= 0:
            return None
        if cmp_index in self._cache:
            return self._cache[cmp_index]
        blk = self._mem.u64(self._blocks + (cmp_index >> 16) * 8)
        value = None
        if blk:
            entry = blk + (cmp_index & 0xFFFF) * 2
            header = self._mem.read(entry, 2)
            if header:
                hdr = struct.unpack("<H", header)[0]
                length, wide = hdr >> 6, hdr & 1
                raw = self._mem.read(entry + 2, length * (2 if wide else 1))
                if raw is not None:
                    value = raw.decode("utf-16-le" if wide else "latin-1", "replace")
        self._cache[cmp_index] = value
        return value


@dataclass(slots=True)
class Property:
    name: str | None
    type: str | None
    offset: int | None
    elem_size: int | None
    inner: str | None = None      # target struct/class/enum, or container element type
    inner_size: int | None = None  # for containers: element FProperty ElementSize


@dataclass(slots=True)
class Struct:
    name: str | None
    kind: str | None          # class name of the object: Class/ScriptStruct/Function/...
    va: int
    func_rva: int | None = None   # for functions: UFunction::Func (exec thunk) RVA
    path: str | None = None       # full UE path, e.g. /Script/Pal.PalPlayerState:AddItem
    properties: list[Property] = field(default_factory=list)


def object_name(mem: Mem, names: FNames, obj: int) -> str | None:
    return names.get(mem.i32(obj + UOBJ_NAME))


def _is_package(mem: Mem, names: FNames, obj: int,
                pkg_cache: dict[int, bool]) -> bool:
    cached = pkg_cache.get(obj)
    if cached is not None:
        return cached
    cls = mem.u64(obj + UOBJ_CLASS)
    result = bool(cls) and object_name(mem, names, cls) == "Package"
    pkg_cache[obj] = result
    return result


def object_path(mem: Mem, names: FNames, obj: int,
                pkg_cache: dict[int, bool]) -> str | None:
    """The full UE object path (UObjectBaseUtility::GetPathName).

    Walks the Outer chain outward to the package. Between an object and its
    outer the separator is ':' when the outer is a non-package whose own outer
    is a package (the class->function boundary), else '.'. Blueprint packages
    (/Game/...) work identically to native /Script ones. Returns None if any
    name in the chain is unreadable."""
    chain: list[int] = []
    cur = obj
    depth = 0
    while cur and cur >> 40 == 0x7f and depth < 16:
        chain.append(cur)
        cur = mem.u64(cur + UOBJ_OUTER)
        depth += 1
    if not chain:
        return None
    outermost = object_name(mem, names, chain[-1])
    if not outermost:
        return None
    path = outermost
    for i in range(len(chain) - 2, -1, -1):
        name = object_name(mem, names, chain[i])
        if not name:
            return None
        outer = chain[i + 1]
        outer_outer = mem.u64(outer + UOBJ_OUTER)
        sep = ":" if (not _is_package(mem, names, outer, pkg_cache)
                      and outer_outer
                      and _is_package(mem, names, outer_outer, pkg_cache)) else "."
        path += sep + name
    return path


def enumerate_objects(mem: Mem):
    """Yield (index, object_va) for every live UObject."""
    chunk_array = mem.u64(GUOBJECTARRAY_OBJECTS)
    num = mem.i32(GUOBJECTARRAY_OBJECTS + NUM_ELEMENTS_OFFSET)
    if not chunk_array or not num or num < 0 or num > 5_000_000:
        return
    for index in range(num):
        chunk_i, within = divmod(index, ELEMENTS_PER_CHUNK)
        chunk = mem.u64(chunk_array + chunk_i * 8)
        if not chunk:
            continue
        obj = mem.u64(chunk + within * FUOBJECTITEM_SIZE)
        if obj:
            yield index, obj


def _inner_type(mem: Mem, names: FNames, fld: int, ptype: str | None) -> str | None:
    if ptype in _UOBJECT_INNER:
        ref = mem.u64(fld + FPROP_INNER)  # UScriptStruct / UClass / UEnum
        return names.get(mem.i32(ref + UOBJ_NAME)) if ref and ref >> 40 == 0x7f else None
    if ptype in _CONTAINER:
        ref = mem.u64(fld + FPROP_INNER)  # inner FProperty
        if not ref or ref >> 40 != 0x7f:
            return None
        fc = mem.u64(ref + FFIELD_CLASS)
        elem = names.get(mem.i32(fc)) if fc else None
        if elem == "StructProperty":
            sref = mem.u64(ref + FPROP_INNER)
            inner = names.get(mem.i32(sref + UOBJ_NAME)) if sref and sref >> 40 == 0x7f else None
            return f"StructProperty<{inner}>" if inner else elem
        return elem
    return None


def _inner_size(mem: Mem, fld: int, ptype: str | None) -> int | None:
    """Element ElementSize for a container FProperty (needed to stride an array)."""
    if ptype not in _CONTAINER:
        return None
    ref = mem.u64(fld + FPROP_INNER)  # inner FProperty
    if not ref or ref >> 40 != 0x7f:
        return None
    return mem.i32(ref + FPROP_ELEMSIZE)


def read_properties(mem: Mem, names: FNames, struct_va: int) -> list[Property]:
    props: list[Property] = []
    fld = mem.u64(struct_va + USTRUCT_CHILDPROPS)
    seen = 0
    while fld and fld >> 40 == 0x7f and seen < 512:
        fclass = mem.u64(fld + FFIELD_CLASS)
        ptype = names.get(mem.i32(fclass)) if fclass else None
        props.append(Property(
            name=names.get(mem.i32(fld + FFIELD_NAME)),
            type=ptype,
            offset=mem.i32(fld + FPROP_OFFSET),
            elem_size=mem.i32(fld + FPROP_ELEMSIZE),
            inner=_inner_type(mem, names, fld, ptype),
            inner_size=_inner_size(mem, fld, ptype),
        ))
        fld = mem.u64(fld + FFIELD_NEXT)
        seen += 1
    return props


def dump_structs(mem: Mem, names: FNames):
    """Yield a Struct for every UStruct-derived object (with properties)."""
    class_name_cache: dict[int, str | None] = {}
    pkg_cache: dict[int, bool] = {}
    for _index, obj in enumerate_objects(mem):
        cls = mem.u64(obj + UOBJ_CLASS)
        if not cls:
            continue
        kind = class_name_cache.get(cls)
        if kind is None:
            kind = object_name(mem, names, cls)
            class_name_cache[cls] = kind
        if kind not in STRUCT_CLASS_NAMES:
            continue
        func_rva = None
        path = None
        if kind in FUNCTION_KINDS:
            func = mem.u64(obj + UFUNCTION_FUNC_OFFSET)
            if func and IMAGE_BASE <= func < IMAGE_END:
                func_rva = func - IMAGE_BASE
            # Path is what the profile catalog keys hooks on; functions only.
            path = object_path(mem, names, obj, pkg_cache)
        yield Struct(
            name=object_name(mem, names, obj),
            kind=kind,
            va=obj,
            func_rva=func_rva,
            path=path,
            properties=read_properties(mem, names, obj),
        )
