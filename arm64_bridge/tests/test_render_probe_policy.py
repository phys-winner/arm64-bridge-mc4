"""Execute production observer installation with release/debug compile policies."""
from pathlib import Path
import os
import re
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/dynarmic_host.cpp").read_text(encoding="utf-8")
START = SOURCE.index("#if MC4_ENABLE_NATIVE_LOGGING\n        // Observational probes")
END = SOURCE.index("#endif // Font and text rendering observers", START)
BODY = SOURCE[START:END + len("#endif // Font and text rendering observers")]
# Includes LOCBOUND: its QA string override is intentionally always installed.
SITES = [tuple(int(value, 16) for value in pair) for pair in re.findall(
    r'\{"[^"\n]+",\s*(0x[0-9a-fA-F]+)u?,\s*(0x[0-9a-fA-F]+)u?(?:,|\})', BODY)]
SITES.append((0x40FBB744, 0xE59A6004))
FUNCTIONAL_SITES = {0x40589788, 0x404FDBB0, 0x404FD4A4, 0x404FDBD4}


PRELUDE = r"""
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "arm32_push.h"
#define LOGI(...) do {} while (0)
#define LOGE(...) do {} while (0)
namespace Dynarmic::A32 {
struct Jit {
    std::array<uint32_t, 16> regs{};
    auto& Regs() { return regs; }
};
}
class DynarmicHost;
namespace mc4 {
uint32_t Phase3SettingsStringOverride(DynarmicHost&, uint32_t, uint32_t, uint32_t);
}
struct Entry {
    std::string name;
    uint32_t trampoline;
    std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> handler;
};
struct MockManager {
    DynarmicHost& host;
    std::vector<Entry> entries;
    uint32_t RegisterThunk(const char* name,
        std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> handler);
};
std::vector<std::pair<uint32_t, uint32_t>> g_probe_rewrites;
void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "%s\n", message); std::_Exit(1); }
}
class DynarmicHost {
public:
    MockManager manager{*this};
    MockManager* m_thunk_manager = &manager;
    std::unordered_map<uint32_t, uint32_t> words;
    std::vector<std::pair<uint32_t, uint32_t>> invalidations;
    uint32_t override_result = 0;
    std::array<uint32_t, 3> override_args{};
    uint32_t MemoryRead32(uint32_t address) { return words[address]; }
    uint8_t MemoryRead8(uint32_t address) {
        return static_cast<uint8_t>(words[address & ~3u] >> ((address & 3u) * 8));
    }
    void MemoryWrite32(uint32_t address, uint32_t value) { words[address] = value; }
    void InvalidateGuestCode(uint32_t address, uint32_t size) {
        invalidations.push_back({address, size});
    }
    Entry& entryAt(uint32_t address) {
        const uint32_t opcode = MemoryRead32(address);
        require((opcode & 0xff000000u) == 0xef000000u, "site is not an SVC");
        const auto index = (opcode & 0xffffffu) - 1u;
        require(index < manager.entries.size(), "unknown callback index");
        return manager.entries[index];
    }
    bool install() {
"""


POSTLUDE = r"""
        return true;
    }
};
uint32_t MockManager::RegisterThunk(const char* name,
    std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> handler) {
    const uint32_t id = static_cast<uint32_t>(entries.size()) + 1u;
    const uint32_t address = 0x10000u + id * 8u;
    entries.push_back({name, address, std::move(handler)});
    host.MemoryWrite32(address, 0xef000000u | id);
    return address;
}
uint32_t mc4::Phase3SettingsStringOverride(DynarmicHost& host, uint32_t manager,
                                         uint32_t id, uint32_t caller) {
    host.override_args = {manager, id, caller};
    return host.override_result;
}
void verifyOriginalInstruction(DynarmicHost& host, uint32_t address, uint32_t opcode) {
    Dynarmic::A32::Jit jit;
    for (unsigned i = 0; i < 16; ++i) jit.Regs()[i] = 0x60000000u + i * 0x1000u;
    jit.Regs()[13] = 0x7efff000u;
    jit.Regs()[14] = 0x40080000u;
    host.MemoryWrite32(jit.Regs()[0] + 8, 0x11223344);
    host.MemoryWrite32(jit.Regs()[0] + 0xa4, 0xaabbcc5a);
    host.MemoryWrite32(jit.Regs()[1] + 0xa4, 0x3344556b);
    host.MemoryWrite32(jit.Regs()[4] + 0xec, 0x2468);
    host.MemoryWrite32(jit.Regs()[4] + 0x20, 0x61234500);
    host.MemoryWrite32(jit.Regs()[10] + 4, 0x1357);
    host.MemoryWrite32(jit.Regs()[13] + 0x34, 0xface1234);
    host.MemoryWrite32(jit.Regs()[5], 0x876543f2);
    host.MemoryWrite32(address + 8 + 0x330, 0xa1b2c3d4);
    auto expected = jit.Regs();
    std::vector<std::pair<uint32_t, uint32_t>> expected_stack;
    if ((opcode & 0xffff0000u) == 0xe92d0000u) {
        const auto mask = opcode & 0xffffu;
        unsigned count = 0;
        for (unsigned i = 0; i < 16; ++i) count += (mask >> i) & 1u;
        expected[13] -= count * 4u;
        uint32_t stack = expected[13];
        for (unsigned i = 0; i < 16; ++i) if (mask & (1u << i)) {
            expected_stack.push_back({stack, jit.Regs()[i]}); stack += 4;
        }
    } else if ((opcode & 0xfff00000u) == 0xe5900000u) {
        const uint32_t reg = (opcode >> 16) & 15u;
        const uint32_t base = reg == 15 ? address + 8 : jit.Regs()[reg];
        expected[(opcode >> 12) & 15u] = host.MemoryRead32(base + (opcode & 0xfffu));
    } else if ((opcode & 0xfff00000u) == 0xe5d00000u) {
        expected[(opcode >> 12) & 15u] = host.MemoryRead8(
            jit.Regs()[(opcode >> 16) & 15u] + (opcode & 0xfffu));
    } else if (opcode == 0xe3a00001u || opcode == 0xe3a00000u) {
        expected[0] = opcode & 0xffu;
    } else if (opcode == 0xe1a0000au || opcode == 0xe1a00004u) {
        expected[0] = jit.Regs()[opcode & 15u];
    } else if (opcode == 0xe52de004u) {
        expected[13] -= 4;
        expected_stack.push_back({expected[13], jit.Regs()[14]});
    } else if (opcode == 0xe28dd014u) {
        expected[13] += 20;
    } else if (opcode == 0xe1d530d0u) {
        expected[3] = static_cast<uint32_t>(static_cast<int32_t>(
            static_cast<int8_t>(host.MemoryRead8(jit.Regs()[5]))));
    } else require(false, "oracle does not cover original opcode");
    host.entryAt(address).handler(jit, host);
    require(jit.Regs() == expected, "observer changes original register semantics");
    for (const auto& [at, value] : expected_stack)
        require(host.MemoryRead32(at) == value, "observer changes original PUSH semantics");
}
int main() {
    DynarmicHost host;
    for (const auto& site : sites) host.words[site.first] = site.second;
    require(host.install(), "production installation failed");
    const size_t expected_count = MC4_ENABLE_NATIVE_LOGGING ? 33 : 4;
    require(host.manager.entries.size() == expected_count, "wrong installed callback count");
    require(g_probe_rewrites.size() == expected_count, "wrong restoration ledger count");
    require(host.invalidations.size() == expected_count, "wrong invalidated site count");
    for (const auto& [address, opcode] : sites) {
        const bool functional = address == 0x40589788 || address == 0x404fdbb0 ||
                                address == 0x404fd4a4 || address == 0x404fdbd4;
        if (!MC4_ENABLE_NATIVE_LOGGING && !functional)
            require(host.MemoryRead32(address) == opcode, "release changed observer-only guest bytes");
        else verifyOriginalInstruction(host, address, opcode);
    }
    // Functional localization must still supply QA strings in release.
    Dynarmic::A32::Jit jit;
    jit.Regs()[0] = 0x60000000; jit.Regs()[1] = 22; jit.Regs()[14] = 0x405897d0;
    host.override_result = 0x60001000;
    host.entryAt(0x404fdbb0).handler(jit, host);
    require(host.override_args == std::array<uint32_t, 3>{0x60000000, 22, 0x405897d0},
            "QA string override arguments changed");
    require(jit.Regs()[0] == 0x60001000 && jit.Regs()[15] == jit.Regs()[14],
            "release disabled functional QA localization");
    // Exact preimage guard remains active for functional hooks.
    DynarmicHost stale;
    for (const auto& site : sites) stale.words[site.first] = site.second;
    stale.words[0x404fdbb0] = 0;
    require(!stale.install(), "functional hook accepted an unsupported preimage");
    std::puts("render probe policy contract passed");
}
"""


class RenderProbePolicy(unittest.TestCase):
    def test_production_installation_and_original_instruction_semantics(self):
        self.assertEqual(len(SITES), 33)
        self.assertEqual(len(set(address for address, _ in SITES)), 33)
        guest = (ROOT.parent / "app/assets/guest_libs/libModernCombat4.so").read_bytes()
        for address, expected in SITES:
            self.assertEqual(struct.unpack_from("<I", guest, address - 0x40000000)[0],
                             expected, hex(address))
        initializers = ",\n".join(f"{{0x{address:x}u, 0x{word:x}u}}" for address, word in SITES)
        cpp = PRELUDE + BODY + POSTLUDE
        cpp = cpp.replace("int main() {", "const std::pair<uint32_t,uint32_t> sites[] = {\n" +
                          initializers + "\n};\nint main() {")
        with tempfile.TemporaryDirectory(prefix="mc4-render-probes-") as directory:
            temporary = Path(directory)
            (temporary / "contract.cpp").write_text(cpp, encoding="utf-8")
            vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            installation = subprocess.check_output(
                [str(vswhere), "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"], text=True,
            ).strip()
            self.assertTrue(installation, "local MSVC C++ toolchain is required")
            vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
            for logging in (0, 1):
                with self.subTest(logging=logging):
                    command = (f'call "{vcvars}" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /O2 '
                               f'/DMC4_ENABLE_NATIVE_LOGGING={logging} /I"{ROOT / "src"}" '
                               'contract.cpp /Fe:contract.exe')
                    result = subprocess.run(command, shell=True, cwd=temporary,
                                            capture_output=True, text=True, timeout=45)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    result = subprocess.run([str(temporary / "contract.exe")], cwd=temporary,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertIn("render probe policy contract passed", result.stdout)

    def test_corrective_hooks_remain_outside_observer_policy(self):
        self.assertNotIn("probe_asvguard", BODY)
        self.assertNotIn("probe_traitsfix", BODY)
        self.assertNotIn("probe_doinit", BODY)
        self.assertNotIn("SHADER-NULL", BODY)
        iap = (ROOT / "src/mc4_phase3.cpp").read_text(encoding="utf-8")
        # The QA route supports both original PUSH and an installed observer.
        self.assertIn("if (text_entry != 0xe92d4ff0 &&", iap)


if __name__ == "__main__":
    unittest.main(verbosity=2)
