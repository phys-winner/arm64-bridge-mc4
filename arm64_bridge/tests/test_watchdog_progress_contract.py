"""Execute the production watchdog loop with a simulated one-second clock."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/dynarmic_host.cpp").read_text(encoding="utf-8")


FIXTURE = r"""
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>
namespace Dynarmic { enum class HaltReason { UserDefined1 }; }
void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
struct FakeJit {
    std::array<uint32_t, 16> regs{};
    unsigned halts = 0, clears = 0;
    auto& Regs() { return regs; }
    void ClearCache() { ++clears; }
    void HaltExecution(Dynarmic::HaltReason reason) {
        require(reason == Dynarmic::HaltReason::UserDefined1, "recovery halt reason changed");
        ++halts;
    }
};
class DynarmicHost {
public:
    static std::atomic<DynarmicHost*> s_live_host;
    std::unique_ptr<FakeJit> m_jit = std::make_unique<FakeJit>();
    struct Worker { std::unique_ptr<FakeJit> jit = std::make_unique<FakeJit>(); };
    std::mutex m_worker_cores_mutex;
    std::array<Worker, 2> m_worker_cores;
    std::atomic<bool> m_watchdog_active{true};
    std::atomic<uint32_t> m_watchdog_pc{0x40001000};
    bool m_fast_pool_recharge = true;
    uint32_t m_fast_pool_table = 0x100, m_heap_current = 0x200000;
    std::array<uint8_t, 4096> memory{};
    size_t m_memory_size = memory.size();
    unsigned recharges = 0;
    uint8_t* GetGuestMemoryBase() { return memory.data(); }
    FakeJit* GetJitForDiagnostics() { return m_jit.get(); }
    uint32_t GuestAlloc(uint32_t size, uint32_t alignment) {
        require(size == (384u << 20) && alignment == 0x1000,
                "fast-pool recharge size/alignment changed");
        ++recharges;
        return m_heap_current;
    }
};
std::atomic<DynarmicHost*> DynarmicHost::s_live_host{nullptr};
std::atomic<uint64_t> g_alloc_buckets[32]{};
std::atomic<int64_t> g_alloc_live{0};
std::atomic<uint64_t> g_alloc_frees{0}, g_free_magic_miss{0};
unsigned heap_reports = 0;
template <typename... T> void LogInfo(const char*, T...) {}
template <typename... T> void LogHeap(const char*, T...) { ++heap_reports; }
#define LOGI(...) LogInfo(__VA_ARGS__)
#define LOGE(...) LogHeap(__VA_ARGS__)
const char* LastThunkName() { return "mock"; }
uint64_t dispatches = 123;
uint64_t ThunkDispatchCount() { return dispatches; }
unsigned ticks = 0, limit = 0;
bool advancing = false, resume_at_50 = false;
struct Finished {};
void NextPoll() {
    if (ticks == limit) throw Finished{};
    ++ticks;
    if (advancing || (resume_at_50 && ticks == 50)) ++dispatches;
    auto* host = DynarmicHost::s_live_host.load();
    // Pool maintenance must still run on the original cadence, independently
    // of whether dispatches are moving or frozen.
    require(host->recharges == (ticks > 31 ? 1u : 0u), "pool recharge cadence changed");
    require(heap_reports == (ticks - 2) / 60 || ticks == 1,
            "heap diagnostic cadence changed");
}
"""


CHECKS = r"""
int main(int argc, char** argv) {
    require(argc >= 2, "scenario missing");
    DynarmicHost host;
    DynarmicHost::s_live_host.store(&host);
    host.m_jit->regs[13] = 0x200;
    host.m_jit->regs[15] = argc > 2 ? static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 0))
                                  : 0x40002000;
    const uint32_t cur = 0x8E00, end = 0x9000;
    std::memcpy(host.memory.data() + host.m_fast_pool_table, &cur, 4);
    std::memcpy(host.memory.data() + host.m_fast_pool_table + 4, &end, 4);
    unsigned expected_halts = 0;
    if (std::strcmp(argv[1], "healthy") == 0) { advancing = true; limit = 270; }
    else if (std::strcmp(argv[1], "frozen") == 0) { limit = 75; expected_halts = 1; }
    else if (std::strcmp(argv[1], "parse") == 0) { limit = 120; }
    else if (std::strcmp(argv[1], "resumed") == 0) { limit = 95; resume_at_50 = true; }
    else require(false, "unknown scenario");
    try { RunWatchdog(); } catch (const Finished&) {}
    require(host.m_jit->halts == expected_halts, "watchdog frozen-spin recovery changed");
    require(host.m_jit->clears == expected_halts, "healthy/parse watchdog purged the JIT cache");
    for (const auto& worker : host.m_worker_cores)
        require(worker.jit->clears == 0 && worker.jit->halts == 0,
                "watchdog invalidated a worker unrelated to the frozen main core");
    require(host.recharges == 1 && heap_reports == (limit - 1) / 60,
            "pool/heap maintenance stopped");
    uint32_t fresh = 0, fresh_end = 0;
    std::memcpy(&fresh, host.memory.data() + host.m_fast_pool_table, 4);
    std::memcpy(&fresh_end, host.memory.data() + host.m_fast_pool_table + 4, 4);
    require(fresh == host.m_heap_current && fresh_end - fresh == (384u << 20),
            "pool recharge no longer updates both guest pointers");
    std::puts("watchdog contract passed");
}
"""


class WatchdogProgressContract(unittest.TestCase):
    def test_healthy_frames_frozen_recovery_and_maintenance(self):
        start = SOURCE.index("            int seconds = 0;", SOURCE.index("uint32_t DynarmicHost::RunFunctionAt("))
        body = SOURCE[start:SOURCE.index("        }).detach();", start)]
        sleep = "std::this_thread::sleep_for(std::chrono::seconds(1));"
        self.assertEqual(1, body.count(sleep))
        # Only substitute the clock; all production sampling, recovery and
        # allocator code below executes without rewriting its conditions.
        body = body.replace(sleep, "NextPoll();")
        cpp = FIXTURE + "\nvoid RunWatchdog() {\n"
        cpp += "auto& s_live_host = DynarmicHost::s_live_host;\n" + body + "\n}\n" + CHECKS
        with tempfile.TemporaryDirectory(prefix="mc4-watchdog-contract-") as directory:
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
            command = (f'call "{vcvars}" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /O2 '
                       'contract.cpp /Fe:contract.exe')
            result = subprocess.run(command, shell=True, cwd=temporary,
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            scenarios = [("healthy",), ("frozen",), ("resumed",)]
            # Every original long archive-parse region remains exempt.
            for first, end in ((0x41339FB8, 0x4133A120), (0x4132D834, 0x4132DD38),
                               (0x4134E09C, 0x4134F2C0), (0x40571224, 0x40571300)):
                scenarios.extend((("parse", hex(first)), ("parse", hex(end - 4)),
                                  ("frozen", hex(end))))
            for scenario in scenarios:
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(temporary / "contract.exe"), *scenario],
                                            cwd=temporary, capture_output=True, text=True, timeout=5)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertIn("watchdog contract passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
