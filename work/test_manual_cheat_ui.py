"""Guard the original native shop/settings, input and bounded media route.
Run: python -B work/test_manual_cheat_ui.py
"""
from pathlib import Path
import hashlib
import re
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SMALI = ROOT / "app/smali/com/gameloft/android/ANMP/GloftM4HM"

def method_body(source: str, name: str) -> str:
    match = re.search(r"(?m)^\.method [^\n]*" + re.escape(name) + r"\(", source)
    if match is None:
        raise AssertionError(f"method {name} not found")
    end = source.find(".end method", match.end())
    if end < 0:
        raise AssertionError(f"method {name} has no end")
    return source[match.start():end + len(".end method")]


class RestorationContract(unittest.TestCase):
    def test_qa_persistence_fields_match_original_setters(self):
        source = (ROOT / "arm64_bridge/src/mc4_phase3.cpp").read_text(encoding="utf-8")
        hints = source[source.index("static QaHint kQaHints[]"):]
        hints = hints[:hints.index("\n};")]
        offsets = {int(i): int(offset, 16) for i, offset in
                   re.findall(r'\{(\d+), (0x[0-9a-f]+), "', hints)}
        stores = {18: 0x89e9b4, 19: 0x75bd94, 20: 0x89d4c0, 21: 0x75bf6c,
                  23: 0x75bfac, 24: 0x75bfcc, 25: 0x75bfec, 26: 0x75c00c,
                  27: 0x75c02c, 28: 0x75c04c, 29: 0x75c06c, 30: 0x75c08c,
                  31: 0x75c0ac}
        self.assertEqual(offsets.keys(), stores.keys())
        guest = (ROOT / "app/assets/guest_libs/libModernCombat4.so").read_bytes()
        for option, store in stores.items():
            instruction, = struct.unpack_from("<I", guest, store)
            self.assertEqual(instruction & 0xfff, offsets[option], option)
        mask, = re.findall(r"kQaOptionMask = (0x[0-9a-f]+)", source)
        self.assertEqual(int(mask, 16), sum(1 << (option - 18) for option in stores))

    def test_audio_object_abi_includes_original_mix_state_call(self):
        guest = (ROOT / "app/assets/guest_libs/libModernCombat4.so").read_bytes()
        # Original _InitOSL performs mix->GetState at slot2 before creating PCM.
        self.assertEqual(struct.unpack_from("<II", guest, 0xf1f7fc),
                         (0xe5933008, 0xe12fff33))
        source = (ROOT / "arm64_bridge/src/thunks_opensles.cpp").read_text(encoding="utf-8")
        for object_name in ("Engine", "OutputMix", "Player"):
            entries = dict(re.findall(
                r'MemoryWrite32\(g_guest' + object_name +
                r'VtblAddr \+ (\d+) \* 4, [^\n]+GetOrCreateThunkAddress\("([^"]+)"\)', source))
            self.assertEqual(entries.get("2"), "SLObject_GetState", object_name)

    def test_gate_literal_branches_reach_code_addresses(self):
        source = (ROOT / "arm64_bridge/src/mc4_phase3.cpp").read_text(encoding="utf-8")
        body = source[source.index("static bool InstallCheatGate"):source.index("static bool InstallTouchResponse")]
        words = {int(i): int(word, 16) for i, word in re.findall(r"stub\[(\d+)\] = (0x[0-9a-f]+)u", body)}
        words.update({14: 0x2000, 15: 0x75bac0, 16: 0x75bc10, 17: 0x75bbec})
        # Decode the actual stub words; a second dereference would jump to an opcode.
        for option, allowed, destination in [(0, True, 0x75bbec), (18, True, 0x75bac0),
                                              (22, False, 0x75bc10), (32, False, 0x75bc10),
                                              (33, True, 0x75bac0)]:
            r0 = ip = pc = 0
            equal = False
            for _ in range(20):
                op = words[pc]
                if op == 0xe1a00004: r0 = option
                elif op & 0xfffff000 == 0xe59fc000: ip = words[pc + 2 + (op & 0xfff) // 4]
                elif op == 0xe12fff3c: r0 = int(allowed)
                elif op == 0xe3500000: equal = r0 == 0
                elif op == 0xe3540000: equal = option == 0
                elif op & 0xff000000 == 0x0a000000:
                    if equal:
                        pc += 2 + (op & 0xffffff)
                        continue
                elif op == 0xe12fff1c:
                    self.assertEqual(ip, destination)
                    break
                else: self.fail(f"unsupported gate instruction {op:08x}")
                pc += 1
            else: self.fail("gate did not return to original code")

    def test_native_patch_preimages_and_pack_whitelist(self):
        source = (ROOT / "arm64_bridge/src/mc4_phase3.cpp").read_text(encoding="utf-8")
        guest = (ROOT / "app/assets/guest_libs/libModernCombat4.so").read_bytes()
        self.assertEqual(hashlib.sha256(guest).hexdigest(),
                         "f5bcb8e6071cc1b0e09d200922dd2914e971ccbf5002981e8416481fe5b45ba1")
        runtime = bytearray(guest)
        loader = (ROOT / "arm64_bridge/src/dynarmic_host.cpp").read_text(encoding="utf-8")
        probes = loader[loader.index("// [GSETBOUND]"):loader.index("// [STAGE-1] diagnostics")]
        for address, expected in re.findall(r'\{"(?:ctor|load)", (0x[0-9A-F]+)u, (0x[0-9A-F]+)u\}', probes):
            offset = int(address, 16) - 0x40000000
            self.assertEqual(struct.unpack_from("<I", guest, offset)[0], int(expected, 16))
            struct.pack_into("<I", runtime, offset, 0xef000123)
        for offset, words in re.findall(r"GuardWords\(host, (0x[0-9a-f]+), \{([^}]+)\}\)", source):
            expected = [int(word.strip(), 16) for word in words.split(",")]
            actual = list(struct.unpack_from("<" + "I" * len(expected), runtime, int(offset, 16)))
            self.assertEqual(actual, expected, offset)
        patches = source[source.index("const Patch patches[]"):source.index("if (!GuardWords(host", source.index("const Patch patches[]"))]
        for offset, before, after in re.findall(r"\{(0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+)\}", patches):
            self.assertEqual(struct.unpack_from("<I", guest, int(offset, 16))[0], int(before, 16), offset)
        self.assertEqual(struct.unpack_from("<II", guest, 0x5658a4), (0xe3a0304b, 0xe581303c))
        packs = re.findall(r'\{"(mc4\.offline\.credits\.\d+)", (\d+)\}', source)
        self.assertEqual(len(packs), 6)
        self.assertEqual(len({item for item, _ in packs}), 6)
        for item, amount in packs:
            self.assertEqual(int(item.rsplit(".", 1)[1]), int(amount))
            self.assertGreater(int(amount), 0)
            self.assertEqual(int(amount) % 50, 0)
        self.assertNotIn("phase3_open_catalog", source)
        self.assertIn("GuestString(host, id_string)", source)

    def test_original_settings_are_not_reenabled_on_resume(self):
        activity = (SMALI / "MC4.smali").read_text(encoding="utf-8")
        self.assertNotIn("OfflineCatalog;->applyOwned()", activity)
        self.assertNotIn("OfflineCatalog;->scheduleRetry()", activity)
        availability = method_body((SMALI / "OfflineCatalog.smali").read_text(encoding="utf-8"), "allowNativeMenu")
        self.assertNotIn("owned_", availability)
        self.assertIn("->gateReady()", availability)

    def test_touch_history_keeps_pointer_ids_and_current_sample(self):
        activity = (ROOT / "app/smali/com/gameloft/glf/GL2JNIActivity.smali").read_text(encoding="utf-8")
        current = method_body(activity, "onTouchEvent")
        history = method_body(activity, "dispatchTouchHistory")
        self.assertNotIn("0x190", current)
        self.assertIn("->requestUnbufferedDispatch", current)
        self.assertIn("->getPointerId(I)I", history)
        self.assertIn("->getHistoricalX(II)F", history)
        self.assertIn("->getHistoricalY(II)F", history)
        self.assertEqual(current.count("->dispatchTouchHistory("), 1)
        timer = (ROOT / "app/smali/com/gameloft/glf/d.smali").read_text(encoding="utf-8")
        self.assertNotIn("GL2JNILib;->touchEvent", timer)

    def test_subtitle_retry_selects_english_and_discards_partial_cues(self):
        video = (SMALI / "MyVideoView.smali").read_text(encoding="utf-8")
        loader = video[video.index(".method private b(I)V"):]
        loader = loader[:loader.index(".end method")]
        retry = loader.index("if-nez p1, :cond_2")
        language = loader.index("MyVideoView;->s:Ljava/lang/String;")
        self.assertLess(retry, language)
        self.assertNotIn("move p1, v0", loader[:loader.index(":goto_1")])
        reset = loader[loader.index(":goto_0"):loader.index("Ljava/util/Locale;->getDefault")]
        self.assertEqual(reset.count("Ljava/util/ArrayList;->clear()V"), 3)
        for field in ("i", "j", "k"):
            self.assertIn(f"MyVideoView;->{field}:Ljava/util/ArrayList;", reset)
        self.assertIn('const-string v2, "_English.srt"', loader)

    def test_player_uses_bounded_provider_and_closes_failed_subtitles(self):
        video = (SMALI / "MyVideoView.smali").read_text(encoding="utf-8")
        self.assertNotIn("Intro video permanently disabled", method_body(video, "onCreate"))
        # The subtitle loader's overload is the only method with this cleanup label.
        self.assertIn("openInputStream(Landroid/net/Uri;)", video)
        self.assertIn(":try_start_subtitle_cleanup", video)
        provider = method_body((SMALI / "ZipFileContentProvider.smali").read_text(encoding="utf-8"), "openAssetFile")
        self.assertIn("openEmbeddedMedia", provider)
        self.assertIn("Game media is read-only", provider)
        metadata = method_body((SMALI / "ZipFileContentProvider.smali").read_text(encoding="utf-8"), "query")
        self.assertIn("MatrixCursor", metadata)
        self.assertNotIn("invoke-super", metadata)
        native = (ROOT / "arm64_bridge/src/mc4_phase3.cpp").read_text(encoding="utf-8")
        media = native[native.index("int Phase3OpenMedia("):native.index("static off64_t HandleSize")]
        self.assertIn('"/proc/self/fd/%d"', media)
        self.assertIn("open(fd_path, O_RDONLY | O_CLOEXEC)", media)
        self.assertNotIn("F_DUPFD", media)


if __name__ == "__main__":
    unittest.main(verbosity=2)
