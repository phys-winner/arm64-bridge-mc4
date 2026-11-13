"""Execute production thunk profiling: TLS isolation, timing and bounded dumps."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/thunk_manager.cpp").read_text(encoding="utf-8")


def function(signature):
    start = SOURCE.index(signature)
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


FIXTURE = r"""
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
namespace Dynarmic::A32 {
class Jit { public: std::array<uint32_t, 16> regs{}; auto& Regs() { return regs; } };
}
class DynarmicHost {};
#define private public
#include "thunk_manager.h"
#undef private
int capture(const char* format, ...);
#define LOGI(...) capture(__VA_ARGS__)
#define LOGE(...) capture(__VA_ARGS__)
bool track_allocations = false;
unsigned allocations = 0;
void* operator new(size_t size) {
    if (track_allocations) ++allocations;
    if (void* value = std::malloc(size)) return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, size_t) noexcept { std::free(value); }
void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "%s\n", message); std::_Exit(1); }
}
template <typename T> concept HasProfile = requires { typename T::ProfileCounter; };
static_assert(HasProfile<ThunkManager> == bool(MC4_ENABLE_NATIVE_LOGGING));
"""


CHECKS = r"""
std::array<std::array<char, 256>, 20> output{};
size_t lines = 0;
bool exception_recorded_before_log = false;
int capture(const char* format, ...) {
#if MC4_ENABLE_NATIVE_LOGGING
    if (std::strstr(format, "THUNK-EXC"))
        exception_recorded_before_log = ThunkManager::s_thread_profile[15].calls == 1 &&
            ThunkManager::s_thread_profile[15].nanoseconds > 0;
#endif
    require(lines < output.size(), "unbounded diagnostic output");
    va_list args; va_start(args, format);
    std::vsnprintf(output[lines++].data(), output[0].size(), format, args);
    va_end(args);
    return 0;
}
int main() {
    DynarmicHost host;
    ThunkManager manager(host);
    Dynarmic::A32::Jit jit;
    for (unsigned i = 1; i <= 15; ++i) {
        auto entry = std::make_unique<ThunkManager::FastThunkEntry>();
        entry->name = "thunk" + std::to_string(i);
        entry->handler = [](auto& core, auto&) { ++core.Regs()[0]; };
        manager.m_fast_thunks[i].store(entry.get());
        manager.m_fast_thunk_storage.push_back(std::move(entry));
    }
    const auto& fast = manager.m_fast_thunk_storage[0]->handler;
    manager.DispatchThunkEntry(1, "thunk1", fast, jit); // Warm TLS/runtime.
    manager.DumpThreadProfile(); lines = 0;
    track_allocations = true;
    for (unsigned i = 0; i < 128; ++i) manager.DispatchThunkEntry(1, "thunk1", fast, jit);
    track_allocations = false;
    require(allocations == 0 && jit.Regs()[0] == 129, "profiling allocates or alters handler execution");
#if MC4_ENABLE_NATIVE_LOGGING
    require(ThunkManager::s_thread_profile[1].calls == 128 &&
            ThunkManager::s_thread_profile[1].nanoseconds > 0, "handler count/time missing");
    std::thread worker([&] {
        Dynarmic::A32::Jit core;
        for (unsigned i = 0; i < 7; ++i) manager.DispatchThunkEntry(4, "worker", fast, core);
        require(ThunkManager::s_thread_profile[4].calls == 7 &&
                ThunkManager::s_thread_profile[1].calls == 0, "profile is not thread-local");
        manager.DumpThreadProfile();
    });
    worker.join(); lines = 0;
    require(ThunkManager::s_thread_profile[1].calls == 128 &&
            ThunkManager::s_thread_profile[4].calls == 0, "worker dump reset main profile");
    manager.DumpThreadProfile();
    require(lines == 2 && std::strstr(output[1].data(), "thunk1 count=128"), "wrong current-thread dump");
    lines = 0; manager.DumpThreadProfile();
    require(lines == 1 && std::strstr(output[0].data(), "total_calls=0"), "profile did not reset");
    ThunkHandler throwing = [](auto&, auto&) {
        for (volatile unsigned i = 0; i < 1000; ++i) {}
        throw 7;
    };
    lines = 0; manager.DispatchThunkEntry(15, "throwing", throwing, jit);
    require(jit.Regs()[0] == 0 && exception_recorded_before_log, "exception timing/containment changed");
    manager.DispatchThunkEntry(ThunkManager::kFastThunkCapacity, "overflow", fast, jit);
    require(ThunkManager::s_thread_profile_overflow == 1, "out-of-range thunk corrupted profile array");
    lines = 0; manager.DumpThreadProfile();
    require(std::strstr(output[0].data(), "overflow=1"), "overflow not reported");
    require(ThunkManager::s_thread_profile_overflow == 0, "overflow did not reset");
    // Rank oracle:14 samples, top12 descending inclusive time; dump adds no calls.
    for (uint32_t id = 1; id <= 14; ++id)
        ThunkManager::s_thread_profile[id] = {id, id * 1000u};
    lines = 0; manager.DumpThreadProfile();
    require(lines == 13 && std::strstr(output[0].data(), "total_calls=105 inclusive_us=105"),
            "dump is not bounded or counts its own diagnostics");
    for (unsigned rank = 1; rank <= 12; ++rank) {
        char expected[64]; std::snprintf(expected, sizeof(expected), "thunk%u count=%u us=%u",
                                         15 - rank, 15 - rank, 15 - rank);
        require(std::strstr(output[rank].data(), expected), "top-handler ranking wrong");
    }
#else
    manager.DumpThreadProfile();
    require(lines == 0, "release includes diagnostic profiling output");
#endif
    std::puts("thunk profile contract passed");
}
"""


class ThunkProfileContract(unittest.TestCase):
    def test_production_dispatch_and_profile_in_both_build_modes(self):
        start = SOURCE.index("static std::atomic<const char*> g_last_thunk_name")
        state = SOURCE[start:SOURCE.index("uint32_t ThunkManager::CopyRecentThunkNames", start)]
        cpp = FIXTURE + function("ThunkManager::ThunkManager(")
        cpp += "\nThunkManager::~ThunkManager() = default;\n" + state
        cpp += function("void ThunkManager::DispatchThunkEntry(") + CHECKS
        with tempfile.TemporaryDirectory(prefix="mc4-thunk-profile-") as directory:
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
                    self.assertIn("thunk profile contract passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
