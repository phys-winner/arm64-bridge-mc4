"""Compile the production graphics backend and execute its installed hooks."""
from pathlib import Path
import os
import re
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/mc4_graphics.cpp").read_text(encoding="utf-8")
GUARD_BODY = SOURCE.split("constexpr Guard guards[] = {", 1)[1].split("};", 1)[0]
GUARDS = [(int(offset.replace("kLateInit", "0x88d158").replace("kDeretinated", "0x7b7e9c"), 16),
           int(word, 16)) for offset, word in re.findall(
    r'\{(kLateInit|kDeretinated|0x[0-9a-f]+),\s*(0x[0-9a-f]+)u\}', GUARD_BODY)]


FIXTURE = r"""
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "mc4_graphics.h"
void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
namespace Dynarmic::A32 {
class Jit {
public:
    std::array<uint32_t, 16> registers{};
    std::array<uint32_t, 64> fpu{};
    uint32_t status = 0xA0000010, fpscr = 0x12345678;
    auto& Regs() { return registers; }
    uint32_t Cpsr() { return status; }
    void SetCpsr(uint32_t value) { status = value; }
};
}
class DynarmicHost;
struct MockLoader { uint32_t GetBaseAddress() { return 0; } };
struct Entry {
    std::string name;
    uint32_t address;
    std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> handler;
};
struct MockManager {
    DynarmicHost& host;
    std::vector<Entry> entries;
    uint32_t FindThunkAddress(const char* name) {
        for (const auto& entry : entries) if (entry.name == name) return entry.address;
        return 0;
    }
    uint32_t RegisterThunk(const char* name,
        std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> handler);
};
class DynarmicHost {
public:
    static constexpr uint32_t app = 0x200000, settings = 0x300000;
    std::vector<uint8_t> memory = std::vector<uint8_t>(0x1800000, 0xA6);
    struct Write { uint32_t address, bytes; };
    std::vector<Write> writes;
    std::vector<uint32_t> invalidations;
    MockLoader loader;
    MockManager manager{*this};
    uint32_t MemoryRead32(uint32_t address) {
        require(uint64_t(address) + 4 <= memory.size(), "guest read outside memory");
        uint32_t value; std::memcpy(&value, memory.data() + address, 4); return value;
    }
    void MemoryWrite32(uint32_t address, uint32_t value) {
        require(uint64_t(address) + 4 <= memory.size(), "guest write outside memory");
        std::memcpy(memory.data() + address, &value, 4); writes.push_back({address, 4});
    }
    void MemoryWrite8(uint32_t address, uint8_t value) {
        require(address < memory.size(), "guest byte write outside memory");
        memory[address] = value; writes.push_back({address, 1});
    }
    size_t GetGuestMemorySize() { return memory.size(); }
    MockLoader& GetElfLoader() { return loader; }
    MockManager& GetThunkManager() { return manager; }
    void InvalidateGuestCode(uint32_t address, size_t size) {
        require(size == 4, "unexpected cache invalidation range"); invalidations.push_back(address);
    }
    void Invoke(const char* name, Dynarmic::A32::Jit& jit) {
        for (const auto& entry : manager.entries) if (entry.name == name) {
            entry.handler(jit, *this); return;
        }
        require(false, "production hook was not registered");
    }
};
uint32_t MockManager::RegisterThunk(const char* name,
    std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> handler) {
    const uint32_t address = 0x1000 + uint32_t(entries.size()) * 8;
    host.MemoryWrite32(address, 0xEF000001 + uint32_t(entries.size()));
    host.MemoryWrite32(address + 4, 0xE12FFF1E);
    entries.push_back({name, address, std::move(handler)});
    return address;
}
constexpr int ANDROID_LOG_INFO = 4, ANDROID_LOG_ERROR = 6;
template <typename... T> int __android_log_print(int, const char*, const char*, T...) { return 0; }
"""


CHECKS = r"""
void FillGuest(DynarmicHost& host) {
    for (const auto& guard : guards) host.MemoryWrite32(guard[0], guard[1]);
    host.MemoryWrite32(0x5369FC, 0xE92D43F0);
    host.MemoryWrite32(0x536A00, 0xE24DD014);
    host.MemoryWrite32(0x536A04, 0xE1A06000);
    host.MemoryWrite32(0x17B7D88, host.app);
    host.memory[host.settings + 0x11] = 1; // Existing saved ForceRetina is on.
    host.writes.clear();
}
Dynarmic::A32::Jit Registers() {
    Dynarmic::A32::Jit jit;
    for (unsigned i = 0; i < 16; ++i) jit.registers[i] = 0x11223300 + i;
    for (unsigned i = 0; i < jit.fpu.size(); ++i) jit.fpu[i] = 0x44556600 + i;
    jit.registers[4] = DynarmicHost::app;
    jit.registers[13] = 0x9000;
    jit.registers[14] = 0x123400;
    return jit;
}
void CheckPreferences() {
    using namespace mc4;
    require(Phase3GraphicsLoad(0) && Phase3GraphicsPacked() == 0x10000,
            "unset preference did not preserve Auto");
    for (unsigned resolution = 0; resolution < 4; ++resolution)
        for (unsigned details = 0; details < 81; ++details) {
            uint32_t packed = 0x10000 | resolution, rest = details;
            for (unsigned shift = 2; shift <= 8; shift += 2) {
                packed |= (rest % 3) << shift; rest /= 3;
            }
            require(Phase3GraphicsLoad(packed) && Phase3GraphicsPacked() == packed,
                    "valid independent selections did not round-trip");
        }
    for (uint32_t invalid : {1u, 0xffffffffu, 0x20000u, 0x10400u, 0x1000cu,
                             0x10030u, 0x100c0u, 0x10300u}) {
        require(!Phase3GraphicsLoad(invalid) && Phase3GraphicsPacked() == 0x10000,
                "invalid preferences escaped fail-closed Auto");
    }
    constexpr uint32_t presets[] = {0x10000, 0x10155, 0x1015A, 0x102AB};
    for (int index = 0; index < 4; ++index) {
        require(Phase3GraphicsSetOption(200, index) && Phase3GraphicsPacked() == presets[index] &&
                Phase3GraphicsOptionValue(200) == index, "preset values or derived label changed");
    }
    require(Phase3GraphicsSetOption(201, 2) && Phase3GraphicsOptionValue(200) == 4,
            "independent edit did not produce Custom");
    const uint32_t before = Phase3GraphicsPacked();
    require(Phase3GraphicsSetOption(200, 4) && Phase3GraphicsPacked() == before,
            "selecting Custom changed independent controls");
    for (int id = 201; id <= 205; ++id)
        require(Phase3GraphicsOptionValue(id) == int((before >> ((id - 201) * 2)) & 3),
                "row getter differs from persisted word");
    for (auto [id, value] : {std::pair{199, 1}, {206, 1}, {200, -1}, {200, 5},
                             {201, 4}, {202, 3}, {203, 3}, {204, 3}, {205, 3}})
        require(!Phase3GraphicsSetOption(id, value) && Phase3GraphicsPacked() == before,
                "invalid UI option changed preferences");
    require(Phase3GraphicsOptionValue(105) == -1, "graphics aliases the native save/QA option range");
}
void CheckHooks() {
    using namespace mc4;
    DynarmicHost host; FillGuest(host);
    require(Phase3GraphicsLoad(0) && Phase3GraphicsInstall(host), "graphics installation failed");
    constexpr unsigned hook_count = MC4_ENABLE_NATIVE_LOGGING ? 3 : 2;
    require(host.manager.entries.size() == hook_count && host.invalidations.size() == hook_count,
            "unexpected hook count or code invalidation");
    require(Phase3GraphicsInstall(host) && host.manager.entries.size() == hook_count,
            "installation is not idempotent");
    host.writes.clear();
    auto jit = Registers(); const auto before = jit;
    host.Invoke("mc4_graphics_late_init", jit);
    require(host.writes.empty(), "Auto modified the authored profile");
    auto expected = before.registers; expected[13] += 0x6C; expected[15] = 0x88D15C;
    require(jit.registers == expected && jit.fpu == before.fpu &&
            jit.status == before.status && jit.fpscr == before.fpscr,
            "Init return did not preserve exact register/FPU/flags semantics");
    jit = Registers(); host.Invoke("mc4_graphics_deretinated", jit);
    require(jit.registers[13] == 0x8FF8 && jit.registers[15] == 0x7B7EA0 &&
            host.MemoryRead32(0x8FF8) == before.registers[3] &&
            host.MemoryRead32(0x8FFC) == before.registers[14], "Auto did not emulate original PUSH");
    require(jit.status == before.status && jit.fpu == before.fpu, "Auto altered FPU/flags");
#if MC4_ENABLE_NATIVE_LOGGING
    jit = Registers(); host.writes.clear();
    host.Invoke("mc4_graphics_first_material", jit);
    require(jit.registers[13] == 0x8FE4 && jit.registers[15] == 0x536A00 &&
            jit.status == before.status && jit.fpu == before.fpu && jit.fpscr == before.fpscr,
            "material ordering observer changed ARM/FPU/flags");
    unsigned at = 0x8FE4;
    for (unsigned reg : {4, 5, 6, 7, 8, 9, 14}) {
        require(host.MemoryRead32(at) == before.registers[reg], "material observer PUSH order changed");
        at += 4;
    }
    require(host.writes.size() == 7, "material observer wrote outside its PUSH frame");
#endif
    host.writes.clear();
    require(Phase3GraphicsSetOption(200, 3) && host.writes.empty(), "menu change applied before restart");
    jit = Registers(); host.Invoke("mc4_graphics_late_init", jit);
    require(host.writes.empty(), "pending High changed the existing Auto session");
    require(host.memory[host.settings + 0x11] == 1, "legacy ForceRetina changed");
}
void CheckRestartAndWriteBoundary() {
    using namespace mc4;
    for (int preset : {1, 2, 3}) {
        require(Phase3GraphicsSetOption(200, preset), "preset selection failed");
        DynarmicHost host; FillGuest(host);
        require(Phase3GraphicsInstall(host), "fresh-session install failed");
        const auto memory_before = host.memory;
        host.writes.clear(); auto jit = Registers();
        host.Invoke("mc4_graphics_late_init", jit);
        constexpr uint32_t allowed[] = {0x390, 0x3AB, 0x3C5, 0x3B0, 0x38A};
        require(host.writes.size() == 5, "preset did not write exactly five graphic fields");
        for (unsigned index = 0; index < host.writes.size(); ++index)
            require(host.writes[index].address == host.app + allowed[index] &&
                    host.writes[index].bytes == (index == 0 ? 4u : 1u), "nonvisual/profile pointer write");
        auto oracle = memory_before;
        const uint32_t scales[] = {0, 0x3F000000, 0x3F400000, 0x3F800000};
        std::memcpy(oracle.data() + host.app + 0x390, &scales[preset], 4);
        oracle[host.app + 0x3AB] = preset == 1 ? 0 : 1;
        for (auto offset : {0x3C5, 0x3B0, 0x38A}) oracle[host.app + offset] = preset == 3;
        require(host.memory == oracle, "audio/cadence/ForceRetina/other memory changed");
        host.writes.clear();
        require(Phase3GraphicsSetOption(200, 0), "pending Auto selection failed");
        for (uint32_t lr : {0x123400u, 0x123401u}) {
            jit = Registers(); jit.registers[14] = lr; const auto before = jit;
            host.Invoke("mc4_graphics_deretinated", jit);
            auto expected = before.registers;
            expected[0] = preset < 3; expected[15] = lr & ~1u;
            require(jit.registers == expected && jit.status == ((before.status & ~0x20u) | ((lr & 1) ? 0x20u : 0)),
                    "active custom resolution/ARM-Thumb return changed");
            require(jit.fpu == before.fpu && jit.fpscr == before.fpscr && host.writes.empty(),
                    "custom resolution touched stack/FPU/saved ForceRetina");
        }
    }
    // One detail override keeps the original render-scale/ForceRetina path.
    Phase3GraphicsLoad(0); Phase3GraphicsSetOption(202, 1);
    DynarmicHost host; FillGuest(host); require(Phase3GraphicsInstall(host), "sparse install failed");
    host.writes.clear(); auto jit = Registers(); host.Invoke("mc4_graphics_late_init", jit);
    require(host.writes.size() == 1 && host.writes[0].address == host.app + 0x3AB,
            "detail Auto fields were overwritten");
    host.writes.clear(); jit = Registers(); host.Invoke("mc4_graphics_deretinated", jit);
    require(jit.registers[15] == 0x7B7EA0, "Auto resolution ignored legacy native preference");
}
void CheckGuards() {
    using namespace mc4;
    for (const auto& guard : guards) {
        DynarmicHost host; FillGuest(host); host.MemoryWrite32(guard[0], guard[1] ^ 1);
        host.writes.clear();
        require(!Phase3GraphicsInstall(host) && host.writes.empty() && host.manager.entries.empty(),
                "unexpected guest preimage was patched");
    }
    DynarmicHost host; FillGuest(host); Phase3GraphicsSetOption(200, 3);
    require(Phase3GraphicsInstall(host), "guard test install failed");
    host.MemoryWrite32(0x17B7D88, host.app + 8); host.writes.clear();
    auto jit = Registers(); host.Invoke("mc4_graphics_late_init", jit);
    require(host.writes.empty(), "wrong Application receiver modified guest memory");
    jit = Registers(); host.Invoke("mc4_graphics_deretinated", jit);
    require(jit.registers[15] == 0x7B7EA0, "invalid Init receiver activated override");
#if MC4_ENABLE_NATIVE_LOGGING
    for (uint32_t offset : {0x5369FC, 0x536A00, 0x536A04}) {
        DynarmicHost changed; FillGuest(changed);
        const uint32_t word = changed.MemoryRead32(offset) ^ 1;
        changed.MemoryWrite32(offset, word);
        require(Phase3GraphicsInstall(changed) && changed.manager.entries.size() == 2 &&
                changed.MemoryRead32(offset) == word, "observer stale preimage changed production hooks");
    }
#endif
}
int main() {
    CheckPreferences(); CheckHooks(); CheckRestartAndWriteBoundary(); CheckGuards();
    std::puts("graphics production contract passed");
}
"""


class GraphicsContract(unittest.TestCase):
    def test_immutable_profile_consumers_and_hook_preimages(self):
        guest = (ROOT.parent / "app/assets/guest_libs/libModernCombat4.so").read_bytes()
        self.assertEqual(15, len(GUARDS))
        for offset, word in GUARDS + [(0x5369FC, 0xE92D43F0), (0x536A00, 0xE24DD014),
                                     (0x536A04, 0xE1A06000)]:
            with self.subTest(offset=hex(offset)):
                self.assertEqual(word, struct.unpack_from("<I", guest, offset)[0])

    def test_production_settings_and_installed_hooks(self):
        source = SOURCE
        for include in ("dynarmic_host.h", "elf_loader.h", "thunk_manager.h"):
            source = source.replace(f'#include "{include}"', "")
        source = source.replace("#include <android/log.h>", "")
        initializers = ",\n".join(f"{{0x{offset:X}, 0x{word:X}}}" for offset, word in GUARDS)
        cpp = FIXTURE + source + f"\nconstexpr uint32_t guards[][2] = {{{initializers}}};\n" + CHECKS
        with tempfile.TemporaryDirectory(prefix="mc4-graphics-contract-") as directory:
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
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertIn("graphics production contract passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
