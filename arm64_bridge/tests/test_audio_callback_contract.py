"""Execute production audio pumping, destruction and PCM copying with real locks.

The host/JIT and Android HAL are deterministic stand-ins; guest instructions are
checked separately against the immutable ARM32 input. Device timing/audibility
still require the real game.
"""

from pathlib import Path
import os
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/thunks_opensles.cpp").read_text(encoding="utf-8")


def function(signature: str) -> str:
    start = SOURCE.index(signature)
    end = SOURCE.index("\n}\n", start) + len("\n}\n")
    return SOURCE[start:end]


def thunk(name: str) -> str:
    start = SOURCE.index(f'manager.RegisterThunk("{name}",')
    end = SOURCE.index("\n    });", start) + len("\n    });")
    return SOURCE[start:end]


PRELUDE = r"""
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "thunk_types.h"
using namespace std::chrono_literals;
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
using SLresult = uint32_t; using SLuint32 = uint32_t; using SLmillibel = int16_t;
constexpr SLresult SL_RESULT_SUCCESS = 0, SL_RESULT_PRECONDITIONS_VIOLATED = 1;
constexpr SLresult SL_RESULT_PARAMETER_INVALID = 2, SL_RESULT_RESOURCE_ERROR = 4;
constexpr SLresult SL_RESULT_BUFFER_INSUFFICIENT = 7;
struct QueueApi; using SLAndroidSimpleBufferQueueItf = QueueApi**;
struct ObjectApi; using SLObjectItf = ObjectApi**;
struct VolumeApi; using SLVolumeItf = VolumeApi**;
using SLEngineItf = void*; using SLPlayItf = void*;
struct SLAndroidSimpleBufferQueueState { SLuint32 count{}, index{}; };
struct QueueApi {
    SLresult (*Enqueue)(SLAndroidSimpleBufferQueueItf, const void*, SLuint32);
    SLresult (*Clear)(SLAndroidSimpleBufferQueueItf);
    SLresult (*GetState)(SLAndroidSimpleBufferQueueItf, SLAndroidSimpleBufferQueueState*);
};
struct ObjectApi { void (*Destroy)(SLObjectItf); };
struct VolumeApi { SLresult (*SetVolumeLevel)(SLVolumeItf, SLmillibel); };
void Require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::_Exit(1); }
}
bool CanLock(std::mutex& mutex) {
    bool available = false;
    std::thread([&] {
        if (mutex.try_lock()) { available = true; mutex.unlock(); }
    }).join();
    return available;
}
constexpr uint32_t callback_pc = 0x40f1fa60, mix_pc = 0x40f1f634;
constexpr uint32_t driver = 0x100, native_mutex = 0x280, pcm = 0x800;
std::atomic<bool> mixing{false};
struct DynarmicHost {
    std::array<uint8_t, 0x4000> memory{};
    std::array<uint32_t, 2> callback_code{0xe3510000, 0x012fff1e};
    std::mutex driver_mutex;
    std::atomic<unsigned> worker_calls{0};
    bool pool_busy = false;
    std::function<void()> before_worker, mix, release_tls;
    uint8_t* GetGuestMemoryBase() { return memory.data(); }
    size_t GetGuestMemorySize() { return memory.size(); }
    uint32_t MemoryRead32(uint32_t address) {
        if (address == callback_pc || address == callback_pc + 4)
            return callback_code[(address - callback_pc) / 4];
        Require(uint64_t(address) + 4 <= memory.size(), "guest read outside fixture");
        uint32_t value; std::memcpy(&value, memory.data() + address, 4); return value;
    }
    void MemoryWrite32(uint32_t address, uint32_t value) {
        Require(uint64_t(address) + 4 <= memory.size(), "guest write outside fixture");
        std::memcpy(memory.data() + address, &value, 4);
    }
    int GuestMutexTryLock(uint32_t address) {
        Require(address == native_mutex, "must dereference the driver's Mutex member");
        return driver_mutex.try_lock() ? 0 : EBUSY;
    }
    int GuestMutexUnlock(uint32_t address) {
        Require(address == native_mutex, "unlock must use the actual pthread word");
        driver_mutex.unlock(); return 0;
    }
    bool TryRunWorkerFunction(uint32_t address, const std::vector<uint32_t>& arguments) {
        ++worker_calls;
        Require(address == mix_pc && arguments == std::vector<uint32_t>{driver},
                "mix must call DoCallbackOSL(driver), bypassing the locking wrapper");
        Require(!CanLock(driver_mutex), "driver mutex must protect the guest mixer");
        if (before_worker) before_worker();
        if (pool_busy) return false;
        struct MixLifetime {
            MixLifetime() { mixing = true; }
            ~MixLifetime() { mixing = false; }
        } lifetime;
        if (mix) mix();
        return true;
    }
    void ReleaseGuestThreadTls() { if (release_tls) release_tls(); }
};
struct ThunkManager {
    using Handler = std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)>;
    std::unordered_map<std::string, Handler> handlers;
    void RegisterThunk(const char* name, Handler handler) { handlers[name] = handler; }
};
uint32_t Invoke(ThunkManager& manager, DynarmicHost& host, const char* name,
                std::initializer_list<uint32_t> arguments) {
    Dynarmic::A32::Jit jit;
    unsigned index = 0;
    for (uint32_t value : arguments) jit.Regs()[index++] = value;
    manager.handlers.at(name)(jit, host);
    return jit.Regs()[0];
}
int pthread_setname_np(int, const char*) { return 0; }
int pthread_self() { return 0; }
"""

FIXTURE = r"""
std::vector<const uint8_t*> queued;
SLresult state_result = SL_RESULT_SUCCESS, enqueue_result = SL_RESULT_SUCCESS;
std::atomic<unsigned> destroyed{0};
SLmillibel seen_volume = 0;
SLresult GetState(SLAndroidSimpleBufferQueueItf, SLAndroidSimpleBufferQueueState* state) {
    if (state_result == SL_RESULT_SUCCESS) state->count = static_cast<SLuint32>(queued.size());
    return state_result;
}
SLresult Enqueue(SLAndroidSimpleBufferQueueItf, const void* bytes, SLuint32) {
    if (enqueue_result == SL_RESULT_SUCCESS) queued.push_back(static_cast<const uint8_t*>(bytes));
    return enqueue_result;
}
SLresult Clear(SLAndroidSimpleBufferQueueItf) { queued.clear(); return SL_RESULT_SUCCESS; }
void Destroy(SLObjectItf) {
    Require(!mixing.load(), "player Destroy raced the guest mixer");
    ++destroyed;
    // Android may finish one HAL callback during Destroy; production must clear it again.
    HostBqPlayerCallback(g_hostPlayerBufferQueue, nullptr);
}
SLresult SetVolume(SLVolumeItf, SLmillibel level) { seen_volume = level; return SL_RESULT_SUCCESS; }
QueueApi queue_api{Enqueue, Clear, GetState}; QueueApi* queue_table = &queue_api;
ObjectApi object_api{Destroy}; ObjectApi* object_table = &object_api;
VolumeApi volume_api{SetVolume}; VolumeApi* volume_table = &volume_api;
void Prepare(DynarmicHost& host) {
    Require(!g_audioThread, "fixture reset requires the worker to be joined");
    Require(CanLock(host.driver_mutex) && CanLock(g_callbackMutex), "previous run leaked a lock");
    host.MemoryWrite32(driver + 4, native_mutex);
    host.worker_calls = 0; host.pool_busy = false;
    host.before_worker = {}; host.mix = {}; host.release_tls = {};
    host.callback_code = {0xe3510000, 0x012fff1e};
    g_guestCallbackAddr = callback_pc; g_guestMixAddr = mix_pc;
    g_guestCallbackContext = driver;
    g_cbFp0 = host.callback_code[0]; g_cbFp1 = host.callback_code[1];
    g_bqCallbackPending = 3; g_audioPaused = false;
    g_hostPlayerBufferQueue = &queue_table; g_hostPlayerObject = &object_table;
    g_hostPlayerVolume = &volume_table;
    g_hostOutputMixObject = nullptr; g_hostEngineObject = nullptr;
    g_guestPlayerObjectAddr = 0x1000; g_guestEngineObjectAddr = 0x1800;
    g_guestOutputMixObjectAddr = 0x1900; g_currentBufferIndex = 0;
    queued.clear(); state_result = enqueue_result = SL_RESULT_SUCCESS;
    destroyed = 0; mixing = false;
}
"""

CHECKS = r"""
int main() {
    static DynarmicHost host;
    ThunkManager manager; RegisterCallbacks(manager, host);
    Prepare(host);
    g_audioPaused = true;
    PumpOpenSLESCallbacks(host);
    Require(g_bqCallbackPending == 3 && host.worker_calls == 0, "pause consumed pending audio");
    Require(CanLock(g_callbackMutex), "paused pump leaked lifetime lock");
    g_audioPaused = false;
    {
        std::lock_guard<std::mutex> shutdown_lock(host.driver_mutex);
        std::promise<void> finished;
        auto completion = finished.get_future();
        std::thread audio([&] { PumpOpenSLESCallbacks(host); finished.set_value(); });
        Require(completion.wait_for(1s) == std::future_status::ready,
                "pump waited on shutdown's driver mutex");
        audio.join();
        Require(g_bqCallbackPending == 3 && host.worker_calls == 0,
                "busy driver consumed pending audio");
    }
    host.pool_busy = true;
    host.before_worker = [] { HostBqPlayerCallback(g_hostPlayerBufferQueue, nullptr); };
    PumpOpenSLESCallbacks(host);
    Require(g_bqCallbackPending == 4, "pool exhaustion lost pending or a new HAL callback");
    Require(CanLock(host.driver_mutex) && CanLock(g_callbackMutex), "failed lease leaked locks");
    host.pool_busy = false; host.before_worker = {};
    host.mix = [] { throw std::runtime_error("backend fixture failure"); };
    bool caught = false;
    try { PumpOpenSLESCallbacks(host); } catch (const std::runtime_error&) { caught = true; }
    Require(caught && CanLock(host.driver_mutex) && CanLock(g_callbackMutex),
            "worker exception failed to unwind locks");

    Prepare(host);
    host.callback_code[0] ^= 1;
    PumpOpenSLESCallbacks(host);
    Require(g_bqCallbackPending == 0 && host.worker_calls == 0, "stale callback executed");
    Prepare(host);
    const std::array<int16_t, 8> authored{-32768, -23001, -2, -1, 0, 1, 12345, 32767};
    std::memcpy(host.memory.data() + pcm, authored.data(), sizeof(authored));
    host.mix = [&] {
        for (unsigned i = 0; i < 2; ++i)
            Require(Invoke(manager, host, "SLBufferQueue_Enqueue", {0, pcm, sizeof(authored)}) == SL_RESULT_SUCCESS,
                    "original mixed PCM failed to enqueue");
        HostBqPlayerCallback(g_hostPlayerBufferQueue, nullptr);
    };
    PumpOpenSLESCallbacks(host);
    Require(host.worker_calls == 1 && queued.size() == 2 && g_bqCallbackPending == 1,
            "pump replayed old callbacks or consumed a new callback during mixing");
    for (const auto* bytes : queued)
        Require(std::memcmp(bytes, authored.data(), sizeof(authored)) == 0,
                "PCM samples/gain changed in production copying");
    Require(Invoke(manager, host, "SLVolume_SetVolumeLevel", {0, uint32_t(-800)}) == SL_RESULT_SUCCESS
            && seen_volume == -800, "authored volume was lowered or the millibel ABI changed");

    Prepare(host);
    for (unsigned i = 0; i < BUFFER_QUEUE_COUNT; ++i) {
        host.memory[pcm] = static_cast<uint8_t>(i);
        Require(Invoke(manager, host, "SLBufferQueue_Enqueue", {0, pcm, 16}) == SL_RESULT_SUCCESS,
                "available ring slot rejected");
    }
    const auto old_front = queued.front()[0];
    host.memory[pcm] = 239;
    Require(Invoke(manager, host, "SLBufferQueue_Enqueue", {0, pcm, 16}) == SL_RESULT_BUFFER_INSUFFICIENT,
            "full HAL queue was accepted");
    Require(queued.front()[0] == old_front && g_currentBufferIndex == 0,
            "full queue overwrote PCM still owned by Android");
    state_result = SL_RESULT_RESOURCE_ERROR;
    Require(Invoke(manager, host, "SLBufferQueue_Enqueue", {0, pcm, 16}) == SL_RESULT_RESOURCE_ERROR
            && queued.front()[0] == old_front, "failed queue query overwrote active PCM");
    Require(Invoke(manager, host, "SLBufferQueue_GetState", {0, 0}) == SL_RESULT_PARAMETER_INVALID,
            "null guest queue-state pointer accepted");

    Prepare(host);
    std::promise<void> mix_entered, permit_mix_exit, destroy_entered, destroy_finished;
    auto entered = mix_entered.get_future();
    auto release = permit_mix_exit.get_future().share();
    auto destroy_started = destroy_entered.get_future();
    auto destroy_done = destroy_finished.get_future();
    host.mix = [&] { mix_entered.set_value(); release.wait(); };
    std::thread audio([&] { PumpOpenSLESCallbacks(host); });
    Require(entered.wait_for(1s) == std::future_status::ready, "mixer did not enter");
    Require(!CanLock(g_callbackMutex) && !CanLock(host.driver_mutex), "mix is outside its lifetime locks");
    std::thread shutdown([&] {
        destroy_entered.set_value();
        Invoke(manager, host, "SLObject_Destroy", {g_guestPlayerObjectAddr});
        destroy_finished.set_value();
    });
    Require(destroy_started.wait_for(1s) == std::future_status::ready, "Destroy thread did not start");
    Require(destroy_done.wait_for(50ms) == std::future_status::timeout,
            "Destroy completed while a callback still owned the player");
    permit_mix_exit.set_value();
    audio.join(); shutdown.join();
    Require(destroyed == 1 && !g_hostPlayerObject && !g_hostPlayerBufferQueue
            && !g_guestCallbackAddr && !g_guestMixAddr && g_bqCallbackPending == 0,
            "Destroy did not retire callback/player/late HAL pending");
    const unsigned previous_calls = host.worker_calls;
    PumpOpenSLESCallbacks(host);
    Require(host.worker_calls == previous_calls, "retired player callback executed");

    Prepare(host);
    std::promise<void> thread_failed, thread_finished, retried;
    auto failed = thread_failed.get_future();
    auto exited = thread_finished.get_future();
    auto resumed = retried.get_future();
    host.release_tls = [&] { thread_finished.set_value(); };
    host.mix = [&] {
        thread_failed.set_value();
        throw std::runtime_error("thread backend fixture failure");
    };
    StartAudioThread(&host);
    Require(failed.wait_for(1s) == std::future_status::ready, "worker did not reach failure fixture");
    const auto parked_deadline = std::chrono::steady_clock::now() + 1s;
    while (!g_audioPaused && std::chrono::steady_clock::now() < parked_deadline)
        std::this_thread::yield();
    Require(g_audioPaused && CanLock(g_callbackMutex) && CanLock(host.driver_mutex),
            "failed audio thread neither parked nor unwound locks");
    {
        std::lock_guard<std::mutex> callback_lock(g_callbackMutex);
        host.mix = [&] { retried.set_value(); };
        g_bqCallbackPending = 1;
        g_audioPaused = false;
    }
    g_audioCv.notify_one();
    Require(resumed.wait_for(1s) == std::future_status::ready,
            "parked worker cannot resume after the player is restarted");
    StopAudioThread();
    Require(exited.wait_for(0ms) == std::future_status::ready, "worker was not joined before teardown");
    Require(!g_audioThreadRunning && !g_audioThread, "stopped audio worker remained joinable");
    std::puts("Audio callback lock/pending/lifecycle/PCM contract passed");
}
"""


class AudioCallbackContract(unittest.TestCase):
    def test_production_audio_bodies(self) -> None:
        state = SOURCE[SOURCE.index("DynarmicHost* g_opensles_host"):
                       SOURCE.index("// Host OpenSL ES Buffer Queue Callback")]
        fingerprints = SOURCE[SOURCE.index("static std::atomic<uint32_t> g_cbFp0"):
                              SOURCE.index("static bool BqCallbackInCodeSegment")]
        cpp = PRELUDE + state + fingerprints
        cpp += function("static void HostBqPlayerCallback(") + FIXTURE
        cpp += "\n".join(function(signature) for signature in (
            "bool HasPendingAudioCallbacks()", "void PumpOpenSLESCallbacks(",
            "static void AudioThreadLoop(", "void StartAudioThread(", "void StopAudioThread()",
        ))
        cpp += "\nvoid RegisterCallbacks(ThunkManager& manager, DynarmicHost& host) {\n"
        cpp += "\n".join(thunk(name) for name in (
            "SLObject_Destroy", "SLBufferQueue_GetState", "SLBufferQueue_Enqueue",
            "SLVolume_SetVolumeLevel",
        )) + "\n}\n" + CHECKS
        with tempfile.TemporaryDirectory(prefix="mc4-audio-contract-") as directory:
            temporary = Path(directory)
            stub = temporary / "dynarmic/interface/A32/a32.h"
            stub.parent.mkdir(parents=True)
            stub.write_text(
                "#pragma once\n#include <array>\n#include <cstdint>\n"
                "namespace Dynarmic::A32 { struct Jit {\n"
                "std::array<uint32_t,16> registers{};\n"
                "auto& Regs() { return registers; } }; }\n",
                encoding="utf-8",
            )
            (temporary / "contract.cpp").write_text(cpp, encoding="utf-8")
            vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            installation = subprocess.check_output(
                [str(vswhere), "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"], text=True,
            ).strip()
            self.assertTrue(installation, "local MSVC C++ toolchain is required")
            vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
            command = (
                f'call "{vcvars}" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /O2 '
                f'/I"{temporary}" /I"{ROOT / "src"}" contract.cpp /Fe:contract.exe'
            )
            result = subprocess.run(command, shell=True, cwd=temporary,
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            result = subprocess.run([str(temporary / "contract.exe")], cwd=temporary,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("contract passed", result.stdout)

    def test_immutable_guest_callback_mutex_and_top_up(self) -> None:
        guest = (ROOT.parent / "app/assets/guest_libs/libModernCombat4.so").read_bytes()

        def word(address: int) -> int:
            return struct.unpack_from("<I", guest, address)[0]

        def branch_target(address: int) -> int:
            instruction = word(address)
            self.assertEqual((instruction >> 25) & 7, 5, hex(address))
            offset = instruction & 0xffffff
            if offset & 0x800000:
                offset -= 0x1000000
            return address + 8 + offset * 4

        # CallbackOSL's R1 is DriverAndroid*, its +4 member is vox::Mutex.
        self.assertEqual(word(0xf1fa6c), 0xe2815004)  # add r5, r1, #4
        self.assertEqual(word(0xf1fa70), 0xe1a04001)  # mov r4, r1
        self.assertEqual(branch_target(0xf1fa78), 0xf0a4c0)
        self.assertEqual(word(0xf0a4c0), 0xe5900000)  # Lock loads the pthread pointer.
        self.assertEqual(word(0xf1fa7c), 0xe1a00004)  # DoCallbackOSL takes R0=driver.
        self.assertEqual(branch_target(0xf1fa80), 0xf1f634)
        self.assertEqual(branch_target(0xf1fa8c), 0xf0a4d0)
        self.assertEqual(word(0xf0a4d0), 0xe5900000)
        # Shutdown owns the same member through all three object Destroy calls.
        self.assertEqual(word(0xf1c734), 0xe2805004)  # add r5, r0, #4
        self.assertEqual(branch_target(0xf1c740), 0xf0a4c0)
        for address in (0xf1c770, 0xf1c798, 0xf1c7b8):
            self.assertEqual(word(address), 0xe5923018)  # SLObject vtable slot6.
        self.assertEqual(branch_target(0xf1c7d4), 0xf0a4d0)
        # DoCallback gets BQ state, then mixes only until the existing count reaches2.
        self.assertEqual(word(0xf1f658), 0xe5933008)  # GetState vtable slot2.
        self.assertEqual(word(0xf1f660), 0xe59d5008)  # r5=state.count
        self.assertEqual(word(0xf1f664), 0xe3550001)  # cmp r5, #1
        self.assertEqual(word(0xf1f668) >> 28, 0xc)  # bgt: count>=2 returns.
        self.assertEqual(branch_target(0xf1f668), 0xf1f6ac)
        self.assertEqual(word(0xf1f678), 0xe2855001)  # increment count once per mix.
        self.assertEqual(branch_target(0xf1f68c), 0xf1ee24)  # Original _FillBuffer.
        self.assertEqual(word(0xf1f6a4), 0xe3550002)  # cmp r5, #2
        self.assertEqual(word(0xf1f6a8) >> 28, 1)  # bne: top up to2.
        self.assertEqual(branch_target(0xf1f6a8), 0xf1f66c)


if __name__ == "__main__":
    unittest.main(verbosity=2)
