"""Exercise the actual bounded QA id reader and original compact native array.
Run: python -B work/test_qa_ui.py
The Windows reader fixture uses the same installed NDK as build_arm64.ps1.
"""
import ctypes
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "arm64_bridge/src/mc4_phase3.cpp").read_text(encoding="utf-8")


def function(name):
    start = SOURCE.index(name)
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


class QaContracts(unittest.TestCase):
    def test_original_cheat_array_has_all_13_contiguous_rows(self):
        guest = bytearray((ROOT / "app/assets/guest_libs/libModernCombat4.so").read_bytes())
        start = SOURCE.index("const Patch patches[]")
        patches = SOURCE[start:SOURCE.index("if (!GuardWords(host", start)]
        for offset, before, after in re.findall(
                r"\{(0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+)\}", patches):
            offset = int(offset, 16)
            self.assertEqual(struct.unpack_from("<I", guest, offset)[0], int(before, 16))
            struct.pack_into("<I", guest, offset, int(after, 16))
        rows = []
        for offset in range(0x76e5a0, 0x76fcdc, 4):
            word, = struct.unpack_from("<I", guest, offset)
            if word >> 24 != 0xeb:
                continue
            delta = word & 0xffffff
            if delta & 0x800000:
                delta -= 0x1000000
            if offset + 8 + delta * 4 == 0x1010bb0:
                index, = struct.unpack_from("<I", guest, offset - 8)
                self.assertEqual(index & 0xffffff00, 0xe3a01000)
                rows.append(index & 0xff)
        self.assertEqual(rows, list(range(13)))
        self.assertNotIn('"mc4_qa_dynamic_member"', SOURCE)
        self.assertIn('"QA: 13, листайте"', SOURCE)
        self.assertIn('"QA: 13, scroll"', SOURCE)


class QaInfoReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "nt":
            raise unittest.SkipTest("Windows host fixture requires the installed Android NDK")
        wrapper = (ROOT / "arm64_bridge/build_arm64.ps1").read_text(encoding="utf-8")
        version = re.search(r"\$NdkVersion = '([^']+)'", wrapper).group(1)
        sdk = Path(os.environ.get("ANDROID_SDK_ROOT", Path(os.environ["LOCALAPPDATA"]) / "Android/Sdk"))
        llvm = sdk / "ndk" / version / "toolchains/llvm/prebuilt/windows-x86_64/bin"
        if not (llvm / "clang++.exe").is_file():
            raise unittest.SkipTest(f"Reader fixture requires existing NDK {version}")
        temporary = tempfile.TemporaryDirectory(prefix="mc4-qa-reader-")
        cls.addClassCleanup(temporary.cleanup)
        path = Path(temporary.name)
        cpp = r"""
extern "C" int _fltused = 0;
using uint8_t = unsigned char;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;
using size_t = unsigned long long;
struct String {
    const char* data = nullptr; size_t length = 0;
    String() = default;
    String(const char* p, size_t n) : data(p), length(n) {}
    bool operator!=(const char* other) const {
        size_t i = 0;
        while (i < length && other[i] && data[i] == other[i]) ++i;
        return i != length || other[i] != 0;
    }
};
namespace std {
using string = String;
inline bool isfinite(double value) { return __builtin_isfinite(value); }
inline void memcpy(void* dst, const void* src, size_t n) {
    for (size_t i = 0; i < n; ++i)
        static_cast<uint8_t*>(dst)[i] = static_cast<const uint8_t*>(src)[i];
}
}
size_t strnlen(const char* p, size_t n) {
    size_t i = 0; while (i < n && p[i]) ++i; return i;
}
struct DynarmicHost {
    uint8_t* bytes; uint32_t size; bool invalid = false;
    uint32_t text_probe = 0;
    struct Loader { uint32_t GetBaseAddress() const { return 0; } };
    struct Thunks {
        uint32_t address;
        uint32_t FindThunkAddress(const char*) const { return address; }
    };
    Loader GetElfLoader() { return {}; }
    Thunks GetThunkManager() { return {text_probe}; }
    uint8_t* GetGuestMemoryBase() { return bytes; }
    uint32_t GetGuestMemorySize() { return size; }
    uint8_t MemoryRead8(uint32_t p) {
        if (p >= size) { invalid = true; return 0; } return bytes[p];
    }
    uint32_t MemoryRead32(uint32_t p) {
        if (uint64_t(p) + 4 > size) { invalid = true; return 0; }
        return uint32_t(bytes[p]) | uint32_t(bytes[p+1]) << 8 |
               uint32_t(bytes[p+2]) << 16 | uint32_t(bytes[p+3]) << 24;
    }
};
"""
        mask = re.search(r"static constexpr uint32_t kQaOptionMask = (0x[0-9a-f]+);", SOURCE).group(1)
        cpp += f"static constexpr uint32_t kQaOptionMask = {mask};\n"
        cpp += function("static bool GuestRange")
        cpp += function("static std::string GuestAsString")
        cpp += function("static int QaInfoOption")
        start = SOURCE.index("static bool InstallIapRoute")
        prefix = SOURCE[start:SOURCE.index("    struct Patch", start)]
        cpp += "\n#define LOGE(...)\n" + prefix + "    return true;\n}\n"
        cpp += r"""
extern "C" __declspec(dllexport) int qa_info(uint8_t* bytes, uint32_t size,
                                             uint32_t row, uint32_t* invalid) {
    DynarmicHost host{bytes, size};
    const int option = QaInfoOption(host, row);
    *invalid = host.invalid;
    return option;
}
extern "C" __declspec(dllexport) int qa_text_guard(uint8_t* bytes, uint32_t size,
                                                   uint32_t probe, uint32_t* invalid) {
    DynarmicHost host{bytes, size};
    host.text_probe = probe;
    const bool allowed = InstallIapRoute(host);
    *invalid = host.invalid;
    return allowed;
}
"""
        (path / "reader.cpp").write_text(cpp, encoding="utf-8")
        subprocess.run([str(llvm / "clang++.exe"), "--target=x86_64-pc-windows-msvc",
                        "-std=c++20", "-O2", "-fno-builtin", "-fno-exceptions", "-fno-rtti",
                        "-c", str(path / "reader.cpp"), "-o", str(path / "reader.obj")],
                       check=True, timeout=30)
        subprocess.run([str(llvm / "ld.lld.exe"), "-flavor", "link", "/dll", "/noentry",
                        "/nodefaultlib", "/machine:x64", str(path / "reader.obj"),
                        f"/out:{path / 'reader.dll'}"],
                       check=True, timeout=30)
        library = ctypes.CDLL(str(path / "reader.dll"))
        cls.read = library.qa_info
        cls.read.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                             ctypes.POINTER(ctypes.c_uint32)]
        cls.read.restype = ctypes.c_int
        cls.guard = library.qa_text_guard
        cls.guard.argtypes = cls.read.argtypes
        cls.guard.restype = ctypes.c_int
        from _ctypes import FreeLibrary
        cls.addClassCleanup(FreeLibrary, library._handle)

    def fixture(self, option=18, slot=2, size=4096, capacity=4):
        memory = bytearray(size)
        struct.pack_into("<I", memory, 0x40 + 0xc, 0x100)
        struct.pack_into("<II", memory, 0x100, 1, capacity - 1)
        for i in range(capacity):
            struct.pack_into("<I", memory, 0x108 + i * 24, 0xfffffffe)
        entry = 0x108 + slot * 24
        struct.pack_into("<III", memory, entry, 0xffffffff, 0x697, size - 32)
        memory[size - 32:size - 28] = b"\x03id\0"
        memory[entry + 12] = 2
        struct.pack_into("<d", memory, entry + 16, option)
        return memory, entry

    def result(self, memory, row=0x40):
        array = (ctypes.c_ubyte * len(memory)).from_buffer(memory)
        invalid = ctypes.c_uint32()
        option = self.read(array, len(memory), row, ctypes.byref(invalid))
        self.assertEqual(invalid.value, 0, "reader attempted an out-of-range memory access")
        return option

    def test_all_hints_and_recycled_row_use_actual_option_id(self):
        for option in [18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31]:
            memory, entry = self.fixture(option)
            self.assertEqual(self.result(memory), option)
            struct.pack_into("<d", memory, entry + 16, 31)
            self.assertEqual(self.result(memory), 31)
        memory, _ = self.fixture(31, slot=1023, size=30000, capacity=1024)
        self.assertEqual(self.result(memory), 31)

    def test_unknown_fractional_non_numeric_and_non_finite_ids_fail_closed(self):
        for value in [17, 22, 32, 21.5, math.nan, math.inf, -math.inf]:
            self.assertEqual(self.result(self.fixture(value)[0]), 0)
        for tag in [0, 1, 5, 7, 255]:
            memory, entry = self.fixture()
            memory[entry + 12] = tag
            self.assertEqual(self.result(memory), 0)

    def test_missing_corrupt_and_truncated_tables_fail_without_bad_reads(self):
        for mask in [4, 5, 1024, 0xffffffff]:
            memory, _ = self.fixture()
            struct.pack_into("<I", memory, 0x104, mask)
            self.assertEqual(self.result(memory), 0)
        for table in [0, 4092, 0xffffffff]:
            memory, _ = self.fixture()
            struct.pack_into("<I", memory, 0x4c, table)
            self.assertEqual(self.result(memory), 0)
        memory, entry = self.fixture()
        struct.pack_into("<I", memory, entry + 8, 0xffffffff)
        self.assertEqual(self.result(memory), 0)
        self.assertEqual(self.result(memory[:0x140]), 0)
        self.assertEqual(self.result(memory, row=0xfffffff8), 0)

    def test_text_setter_accepts_only_original_or_exact_registered_loader_probe(self):
        memory = bytearray((ROOT / "app/assets/guest_libs/libModernCombat4.so").read_bytes())
        array = (ctypes.c_ubyte * len(memory)).from_buffer(memory)
        invalid = ctypes.c_uint32()
        self.assertEqual(self.guard(array, len(memory), 0, ctypes.byref(invalid)), 1)
        for entry, registered, thunk in [(0xef000123, 0, 0xef000123),
                                          (0xef000123, 0x100, 0xef000124),
                                          (0xe12fff1e, 0x100, 0xe12fff1e),
                                          (0xef000123, 0x100, 0xef000123)]:
            struct.pack_into("<I", memory, 0xff4728, entry)
            struct.pack_into("<I", memory, 0x100, thunk)
            expected = int(registered != 0 and entry == thunk and entry >> 24 == 0xef)
            self.assertEqual(self.guard(array, len(memory), registered, ctypes.byref(invalid)), expected)
            self.assertEqual(invalid.value, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
