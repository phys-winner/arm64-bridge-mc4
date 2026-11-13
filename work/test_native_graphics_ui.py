"""Check the packaged native movie and execute its AS3 menu logic with UI stubs.

The source-method fixture removes AS3 type annotations only; production array,
recycling and event-refresh code runs in Node. Device AVM2/render QA is separate.
Run: python -B work/test_native_graphics_ui.py
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import unittest

from build_native_graphics_ui import MOVIES, ROOT, movie_tags, original_movie, verify_overlay

AS3 = ROOT / "arm64_bridge/ui/MenuAdvanced.as"
STAGING = os.environ.get("MC4_GRAPHICS_UI_DIR")
OVERLAY_DIR = Path(STAGING) if STAGING else ROOT / "app/assets/native_ui"


class Abc:
    """Read ABC framing to compare original method bodies without decompilation."""
    def __init__(self, movie):
        abc_tags = [record for code, record in movie_tags(movie) if code == 82]
        assert len(abc_tags) == 1
        tag = abc_tags[0]
        start = 6 if struct.unpack_from("<H", tag)[0] & 63 == 63 else 2
        self.data = tag[tag.index(b"\0", start + 4) + 1:]
        self.at = 4
        self.strings = [""]
        for _ in range(2):
            for _ in range(self.u() - 1):
                self.u()
        doubles = self.u()
        self.at += max(0, doubles - 1) * 8
        for _ in range(self.u() - 1):
            size = self.u()
            self.strings.append(self.take(size).decode("utf-8"))
        self.namespaces = [(0, 0)]
        for _ in range(self.u() - 1):
            self.namespaces.append((self.byte(), self.u()))
        for _ in range(self.u() - 1):
            for _ in range(self.u()):
                self.u()
        self.names = [""]
        for _ in range(self.u() - 1):
            kind = self.byte()
            name = ""
            if kind in (7, 13):
                ns, local = self.u(), self.u()
                name = self.strings[self.namespaces[ns][1]] + "." + self.strings[local]
            elif kind in (15, 16, 27, 28):
                self.u()
            elif kind in (9, 14):
                self.u(); self.u()
            elif kind == 29:
                self.u()
                for _ in range(self.u()):
                    self.u()
            elif kind not in (17, 18):
                raise AssertionError(f"Unknown multiname kind {kind}")
            self.names.append(name)
        method_count = self.u()
        for _ in range(method_count):
            count = self.u()
            for _ in range(count + 2):
                self.u()
            flags = self.byte()
            if flags & 8:
                for _ in range(self.u()):
                    self.u(); self.byte()
            if flags & 128:
                for _ in range(count):
                    self.u()
        for _ in range(self.u()):
            self.u()
            for _ in range(self.u() * 2):
                self.u()
        classes = self.u()
        self.owned = set()
        menu_class = None
        for i in range(classes):
            name, _super = self.u(), self.u()
            flags = self.byte()
            if flags & 8:
                self.u()
            for _ in range(self.u()):
                self.u()
            init = self.u()
            methods, _ = self.traits()
            if self.names[name] == "scriptsMC4.singleplayer.settings.MenuAdvanced":
                menu_class = i
                self.owned.update(methods | {init})
        assert menu_class is not None
        for i in range(classes):
            init = self.u()
            methods, _ = self.traits()
            if i == menu_class:
                self.owned.update(methods | {init})
        for _ in range(self.u()):
            init = self.u()
            methods, references = self.traits()
            if menu_class in references:
                self.owned.update(methods | {init})
        self.bodies = {}
        for _ in range(self.u()):
            method = self.u()
            begin = self.at
            for _ in range(4):
                self.u()
            self.take(self.u())
            for _ in range(self.u() * 5):
                self.u()
            self.traits()
            self.bodies[method] = self.data[begin:self.at]
        assert self.at == len(self.data)

    def byte(self):
        return self.take(1)[0]

    def take(self, count):
        end = self.at + count
        assert end <= len(self.data)
        result = self.data[self.at:end]
        self.at = end
        return result

    def u(self):
        result = 0
        for shift in range(0, 35, 7):
            value = self.byte()
            result |= (value & 127) << shift
            if value < 128:
                return result
        raise AssertionError("Invalid U30")

    def traits(self):
        methods, classes = set(), set()
        for _ in range(self.u()):
            self.u()
            kind = self.byte()
            if kind & 15 in (0, 6):
                self.u(); self.u()
                if self.u():
                    self.byte()
            elif kind & 15 in (1, 2, 3, 5):
                self.u()
                methods.add(self.u())
            elif kind & 15 == 4:
                self.u()
                classes.add(self.u())
            else:
                raise AssertionError("Invalid trait")
            if kind & 64:
                for _ in range(self.u()):
                    self.u()
        return methods, classes


def js_method(source, name):
    match = re.search(r"function " + name + r"\([^)]*\)\s*:\s*\w+\s*\{", source)
    if not match:
        raise AssertionError(f"No method {name}")
    begin, cursor, depth = match.end(), match.end(), 1
    while depth:
        char = source[cursor]
        depth += (char == "{") - (char == "}")
        cursor += 1
    body = source[begin:cursor - 1]
    body = re.sub(r"\bvar (\w+):\w+", r"var \1", body)
    body = re.sub(r"(?<![.\w])stage\.", "this.stage.", body)
    body = re.sub(r"(this\._opts\[param1.index\]\.options) is Array", r"Array.isArray(\1)", body)
    parameters = match.group().split("(", 1)[1].split(")", 1)[0]
    parameters = re.sub(r":\w+", "", parameters)
    return f"{name}: function({parameters}) {{ {body} }}"


class NativeGraphicsMovie(unittest.TestCase):
    def test_only_menu_advanced_code_changes(self):
        for name in MOVIES:
            with self.subTest(movie=name):
                original, overlay = original_movie(name), (OVERLAY_DIR / name).read_bytes()
                verify_overlay(original, overlay)
                before, after = Abc(original), Abc(overlay)
                self.assertEqual(after.strings[:len(before.strings)], before.strings)
                self.assertEqual(after.names[:len(before.names)], before.names)
                self.assertEqual(after.namespaces[:len(before.namespaces)], before.namespaces)
                # FFDec removes the old contiguous methods, then appends replacements.
                first, last = min(before.owned), max(before.owned)
                self.assertEqual(before.owned, set(range(first, last + 1)))
                mapped = set()
                for method, body in before.bodies.items():
                    if method in before.owned:
                        continue
                    new = method - (len(before.owned) if method > last else 0)
                    mapped.add(new)
                    self.assertEqual(after.bodies[new], body, f"Unrelated method {method} changed")
                self.assertEqual(set(after.bodies) - mapped, after.owned)
                self.assertIn("NativeGraphicsState", after.strings)

    def test_packaged_fingerprints(self):
        path = OVERLAY_DIR / "mc4_graphics_ui_asset.h" if STAGING else ROOT / "arm64_bridge/src/mc4_graphics_ui_asset.h"
        metadata = path.read_text(encoding="utf-8")
        as3, = re.findall(r'kGraphicsUiAs3Sha = "([0-9a-f]+)"', metadata)
        self.assertEqual(hashlib.sha256(AS3.read_bytes()).hexdigest(), as3)
        rows = re.findall(r'\{"(\d+\.sobfs)", (\d+), 0x([0-9a-f]+)u, "([0-9a-f]+)", (\d+), 0x([0-9a-f]+)u, "([0-9a-f]+)"\}', metadata)
        self.assertEqual({row[0] for row in rows}, MOVIES.keys())
        for name, _size, _crc, source_sha, size, _out_crc, sha in rows:
            blob = (OVERLAY_DIR / name).read_bytes()
            self.assertEqual(len(blob), int(size))
            self.assertEqual(hashlib.sha256(blob).hexdigest(), sha)
            self.assertEqual(source_sha, MOVIES[name])

    def test_apk_store_contract(self):
        if STAGING:
            self.skipTest("Staging artifacts are outside the in-progress APK package")
        config = (ROOT / "app/apktool.yml").read_text()
        for name in MOVIES:
            self.assertIn("- assets/native_ui/" + name, config)

    def test_production_menu_methods_with_recycled_ui(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Existing Node runtime is required for the source-method fixture")
        source = AS3.read_text(encoding="utf-8")
        names = ("onDataReady", "graphicsState", "appendGraphicsOptions", "onListItemSet", "onComboItemSet", "onComboValueChange")
        methods = ",\n".join(js_method(source, name) for name in names)
        fixture = Path(__file__).with_name("native_graphics_ui_fixture.js").read_text(encoding="utf-8")
        result = subprocess.run([node, "-"], input=fixture.replace("/* PRODUCTION_METHODS */", methods),
                                text=True, encoding="utf-8", capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
