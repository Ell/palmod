"""Tests for the reflection-dump query layer (dependency-free, synthetic data)."""
from __future__ import annotations

import unittest

from palrevlib.schema import Schema

DUMP = [
    {"name": "PalChatMessage", "kind": "ScriptStruct", "properties": [
        {"name": "Category", "type": "EnumProperty", "offset": 0, "elem_size": 1},
        {"name": "Sender", "type": "StrProperty", "offset": 8, "elem_size": 16},
        {"name": "Message", "type": "StrProperty", "offset": 40, "elem_size": 16},
    ]},
    {"name": "AddItem_ServerInternal", "kind": "Function", "func_rva": 0x6a5ecf0,
     "path": "/Script/Pal.PalPlayerState:AddItem_ServerInternal",
     "properties": [
        {"name": "StaticItemId", "type": "NameProperty", "offset": 0, "elem_size": 8},
        {"name": "Count", "type": "IntProperty", "offset": 8, "elem_size": 4},
    ]},
    {"name": "PalPlayerState", "kind": "Class", "properties": []},
]


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = Schema(DUMP)

    def test_field_offset(self):
        self.assertEqual(self.schema.field_offset("PalChatMessage", "Sender"), 8)
        self.assertEqual(self.schema.field_offset("PalChatMessage", "Message"), 40)
        self.assertIsNone(self.schema.field_offset("PalChatMessage", "Nope"))
        self.assertIsNone(self.schema.field_offset("Missing", "x"))

    def test_field_type(self):
        f = self.schema.field("PalChatMessage", "Sender")
        self.assertIsNotNone(f)
        self.assertEqual(f.type, "StrProperty")
        self.assertEqual(f.elem_size, 16)

    def test_function_params(self):
        params = self.schema.function_params("AddItem_ServerInternal")
        self.assertEqual([p.name for p in params], ["StaticItemId", "Count"])
        # A non-function is not treated as a parameter list.
        self.assertIsNone(self.schema.function_params("PalChatMessage"))
        self.assertIsNone(self.schema.function_params("PalPlayerState"))

    def test_function_thunk_rva(self):
        # The by-name hook's swap target.
        self.assertEqual(self.schema.function_thunk_rva("AddItem_ServerInternal"),
                         0x6a5ecf0)
        # Not a function, or missing.
        self.assertIsNone(self.schema.function_thunk_rva("PalChatMessage"))
        self.assertIsNone(self.schema.function_thunk_rva("Missing"))

    def test_function_path_and_names(self):
        self.assertEqual(self.schema.function_path("AddItem_ServerInternal"),
                         "/Script/Pal.PalPlayerState:AddItem_ServerInternal")
        self.assertIsNone(self.schema.function_path("PalChatMessage"))
        self.assertEqual(self.schema.function_names(), ["AddItem_ServerInternal"])

    def test_kind_and_find(self):
        self.assertEqual(self.schema.kind("PalChatMessage"), "ScriptStruct")
        self.assertEqual(self.schema.find("Pal"),
                         ["PalChatMessage", "PalPlayerState"])
        self.assertEqual(len(self.schema), 3)


if __name__ == "__main__":
    unittest.main()
