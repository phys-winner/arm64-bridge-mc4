#include "thunks_opensles.h"
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"

#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <android/log.h>
#include <pthread.h>
#include <cstring>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <algorithm>

#if defined(__ANDROID__)
#include <sys/resource.h>
#endif

#define LOG_TAG "Arm32Bridge_Audio"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

DynarmicHost* g_opensles_host = nullptr;

// Host OpenSL ES global state
SLObjectItf g_hostEngineObject = nullptr;
SLEngineItf g_hostEngineEngine = nullptr;
SLObjectItf g_hostOutputMixObject = nullptr;
SLObjectItf g_hostPlayerObject = nullptr;
SLPlayItf g_hostPlayerPlay = nullptr;
SLAndroidSimpleBufferQueueItf g_hostPlayerBufferQueue = nullptr;
SLVolumeItf g_hostPlayerVolume = nullptr;

// Guest addresses for objects & vtables
uint32_t g_guestEngineObjectAddr = 0;
uint32_t g_guestEngineVtblAddr = 0;
uint32_t g_guestEngineInterfaceAddr = 0;
uint32_t g_guestEngineInterfaceVtblAddr = 0;

uint32_t g_guestOutputMixObjectAddr = 0;
uint32_t g_guestOutputMixVtblAddr = 0;

uint32_t g_guestPlayerObjectAddr = 0;
uint32_t g_guestPlayerVtblAddr = 0;
uint32_t g_guestPlayInterfaceAddr = 0;
uint32_t g_guestPlayInterfaceVtblAddr = 0;
uint32_t g_guestBufferQueueInterfaceAddr = 0;
uint32_t g_guestBufferQueueInterfaceVtblAddr = 0;
uint32_t g_guestVolumeInterfaceAddr = 0;
uint32_t g_guestVolumeInterfaceVtblAddr = 0;

// Host-owned PCM slots; the guest controls queue depth through GetState.
static constexpr size_t BUFFER_QUEUE_COUNT = 128;
static constexpr size_t MAX_BUFFER_SIZE = 16384;
static uint8_t g_hostAudioBuffers[BUFFER_QUEUE_COUNT][MAX_BUFFER_SIZE];
static size_t g_currentBufferIndex = 0;
static std::mutex g_audioMutex;
static std::mutex g_callbackMutex;

static uint32_t g_guestCallbackAddr = 0;
static uint32_t g_guestCallbackContext = 0;
static uint32_t g_guestMixAddr = 0;

static uint32_t g_guestConfigInterfaceAddr = 0;
static uint32_t g_guestConfigInterfaceVtblAddr = 0;

static std::unordered_map<std::string, uint32_t> g_iid_pointer_map;
static std::atomic<int> g_bqCallbackPending{0};

// Background Audio Thread synchronization
static std::atomic<bool> g_audioThreadRunning{false};
static std::atomic<bool> g_audioPaused{false};
static std::mutex g_audioCvMutex;
static std::condition_variable g_audioCv;
static std::unique_ptr<std::thread> g_audioThread;

// Host OpenSL ES Buffer Queue Callback (fired on real-time audio thread by Android HAL)
static void HostBqPlayerCallback(SLAndroidSimpleBufferQueueItf bq, void *context) {
    g_bqCallbackPending.fetch_add(1, std::memory_order_relaxed);
    g_audioCv.notify_one();
}

bool IID_Matches(DynarmicHost& host, uint32_t iid_ptr, const SLInterfaceID host_iid) {
    if (iid_ptr == 0 || !host_iid) return false;
    const void* pStruct = host_iid;

    if (iid_ptr + sizeof(struct SLInterfaceID_) <= host.GetGuestMemorySize()) {
        const void* guest1 = host.GetGuestMemoryBase() + iid_ptr;
        if (memcmp(guest1, pStruct, sizeof(struct SLInterfaceID_)) == 0) return true;
    }

    if (iid_ptr + 4 <= host.GetGuestMemorySize()) {
        uint32_t deref = host.MemoryRead32(iid_ptr);
        if (deref != 0 && deref + sizeof(struct SLInterfaceID_) <= host.GetGuestMemorySize()) {
            const void* guest2 = host.GetGuestMemoryBase() + deref;
            if (memcmp(guest2, pStruct, sizeof(struct SLInterfaceID_)) == 0) return true;
        }
    }
    return false;
}

static uint32_t AllocAndRegisterIID(ThunkManager& manager, DynarmicHost& host, const std::string& name, const SLInterfaceID host_iid) {
    // 1. Allocate 16 bytes for struct SLInterfaceID_
    uint32_t struct_addr = host.GuestAlloc(sizeof(struct SLInterfaceID_), 4);
    if (host_iid) {
        memcpy(host.GetGuestMemoryBase() + struct_addr, host_iid, sizeof(struct SLInterfaceID_));
    }

    // 2. Allocate 4 bytes for pointer to struct
    uint32_t ptr_addr = host.GuestAlloc(4, 4);
    host.MemoryWrite32(ptr_addr, struct_addr);

    // 3. Register in ThunkManager and map
    manager.RegisterSymbol(name, ptr_addr);
    g_iid_pointer_map[name] = ptr_addr;

    LOGI("Registered OpenSL ES IID %s: ptr=0x%08X -> struct=0x%08X", name.c_str(), ptr_addr, struct_addr);
    return ptr_addr;
}

} // namespace

// BQ callback policing: the guest may register a callback pointing outside
// the module (strings, freed heap scratch) and the pump would execute data as
// code - the process then dies on a wild SVC or SIGSEGV. Validated at
// registration (code segment only) and fingerprinted for freed-block reuse.
static std::atomic<uint32_t> g_cbFp0{0};
static std::atomic<uint32_t> g_cbFp1{0};
static std::atomic<int32_t> g_cbStubStreak{0};
static bool BqCallbackInCodeSegment(uint32_t addr) {
    const uint32_t kImageStart = 0x40000000u;
    const uint32_t kImageEnd = kImageStart + 0x1813000u;
    return addr >= kImageStart && addr < kImageEnd;
}

void ResetBqCallbackPumpState() {
    g_cbFp0.store(0, std::memory_order_relaxed);
    g_cbFp1.store(0, std::memory_order_relaxed);
    g_cbStubStreak.store(0, std::memory_order_relaxed);
}

bool HasPendingAudioCallbacks() {
    return g_bqCallbackPending.load(std::memory_order_relaxed) > 0;
}
int32_t BqPendingCount() {
    return g_bqCallbackPending.load(std::memory_order_relaxed);
}
uint32_t GuestBqCallbackAddr() {
    return g_guestCallbackAddr;
}

void PumpOpenSLESCallbacks(DynarmicHost& host) {
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    if (g_audioPaused.load(std::memory_order_relaxed)) return;
    if (!g_guestCallbackAddr || !g_guestMixAddr || !HasPendingAudioCallbacks()) return;
    if (host.MemoryRead32(g_guestCallbackAddr) != g_cbFp0.load() ||
        host.MemoryRead32(g_guestCallbackAddr + 4) != g_cbFp1.load()) {
        LOGE("[AUDIO] callback fingerprint changed; parking until re-registration");
        g_bqCallbackPending.store(0, std::memory_order_release);
        return;
    }
    // ShutdownOSL owns this mutex while destroying the player. Never wait for
    // it under the callback lifetime lock, or shutdown and audio deadlock.
    const uint32_t driver_mutex = host.MemoryRead32(g_guestCallbackContext + 4);
    if (!driver_mutex || host.GuestMutexTryLock(driver_mutex) != 0) return;
    struct UnlockDriver {
        DynarmicHost& host;
        uint32_t mutex;
        ~UnlockDriver() { host.GuestMutexUnlock(mutex); }
    } unlock{host, driver_mutex};
    const int pending = g_bqCallbackPending.exchange(0, std::memory_order_acq_rel);
    // Original CallbackOSL is Lock -> DoCallbackOSL -> Unlock; retain that
    // critical section while mixing on a worker core independent of rendering.
    if (!host.TryRunWorkerFunction(g_guestMixAddr, {g_guestCallbackContext}))
        g_bqCallbackPending.fetch_add(pending, std::memory_order_relaxed);
}

void PumpAudioWorkers(DynarmicHost& host) {
    if (g_audioPaused.load(std::memory_order_relaxed)) return;
    const auto& workers = GetGuestThreadWorkers();
    for (size_t wi = 0; wi < workers.size(); ++wi) {
        const auto& worker = workers[wi];
        if (worker.arg) {
            host.MemoryWrite8(worker.arg + 0x10c, 1);
            host.MemoryWrite8(worker.arg + 0x134, 1);
            uint32_t worker_func = host.MemoryRead32(worker.arg + 0x120);
            uint32_t worker_arg = host.MemoryRead32(worker.arg + 0x110);
            if (!worker_func) {
                uint32_t vtable = host.MemoryRead32(worker.arg);
                if (vtable) {
                    worker_func = host.MemoryRead32(vtable);
                    worker_arg = worker.arg;
                }
            }
            if (worker_arg && worker_arg != worker.arg) {
                host.MemoryWrite8(worker_arg + 0x10c, 1);
                host.MemoryWrite8(worker_arg + 0x134, 1);
            }
            // Same data-as-code hazard as the BQ callback: a stale/garbage
            // worker pointer must never reach the JIT.
            if (worker_func && BqCallbackInCodeSegment(worker_func)) {
                if (!host.TryRunFunctionAt(DynarmicHost::kAsyncStackTop, worker_func, {worker_arg})) {
                    return;  // core busy; workers re-run on the next pump tick
                }
            } else if (worker_func) {
                static int bad_worker_logged = 0;
                if (++bad_worker_logged <= 8)
                    LOGE("[AUDIO] rejecting non-code worker_func 0x%08X (arg=%08X)",
                         worker_func, worker_arg);
            }
        }
    }
}

static void AudioThreadLoop(DynarmicHost* host) {
    pthread_setname_np(pthread_self(), "bridge-audio");
    LOGI("Dedicated audio thread started with high priority!");
#if defined(__ANDROID__)
    setpriority(PRIO_PROCESS, 0, -16); // High priority audio thread
#endif

    while (g_audioThreadRunning.load(std::memory_order_relaxed)) {
        {
            std::unique_lock<std::mutex> lock(g_audioCvMutex);
            // Pending callbacks may be waiting for the guest driver mutex;
            // an always-true pending predicate would spin at audio priority.
            g_audioCv.wait_for(lock, std::chrono::milliseconds(5));
        }

        if (!g_audioThreadRunning.load(std::memory_order_relaxed)) break;
        if (!host || g_audioPaused.load(std::memory_order_relaxed)) continue;

        if (g_bqCallbackPending.load(std::memory_order_relaxed) > 0) {
            try {
                PumpOpenSLESCallbacks(*host);
            } catch (const std::exception& e) {
                LOGE("[AUDIO] callback failed: %s", e.what());
                g_audioPaused.store(true);
            } catch (...) {
                LOGE("[AUDIO] callback failed");
                g_audioPaused.store(true);
            }
        }
    }
    host->ReleaseGuestThreadTls();
    LOGI("Dedicated audio thread stopped.");
}

void StartAudioThread(DynarmicHost* host) {
    if (g_audioThreadRunning.load(std::memory_order_relaxed)) return;
    if (!host) return;
    g_audioThreadRunning.store(true, std::memory_order_relaxed);
    g_audioPaused.store(false, std::memory_order_relaxed);
    try {
        g_audioThread = std::make_unique<std::thread>(AudioThreadLoop, host);
    } catch (...) {
        g_audioThreadRunning.store(false);
        throw;
    }
    LOGI("Audio thread launched successfully!");
}

void StopAudioThread() {
    if (!g_audioThreadRunning.load(std::memory_order_relaxed)) return;
    g_audioThreadRunning.store(false, std::memory_order_relaxed);
    g_audioCv.notify_all();
    if (g_audioThread && g_audioThread->joinable()) {
        g_audioThread->join();
    }
    g_audioThread.reset();
}

void PauseAudioPlayback() {
    LOGI("PauseAudioPlayback requested");
    g_audioPaused.store(true, std::memory_order_release);
    if (g_hostPlayerPlay) {
        (*g_hostPlayerPlay)->SetPlayState(g_hostPlayerPlay, SL_PLAYSTATE_PAUSED);
    }
}

void ResumeAudioPlayback() {
    LOGI("ResumeAudioPlayback requested");
    g_audioPaused.store(false, std::memory_order_release);
    if (g_hostPlayerPlay) {
        (*g_hostPlayerPlay)->SetPlayState(g_hostPlayerPlay, SL_PLAYSTATE_PLAYING);
    }
}

uint32_t GetOpenSLESInterfacePointer(const std::string& name) {
    auto it = g_iid_pointer_map.find(name);
    if (it != g_iid_pointer_map.end()) {
        return it->second;
    }
    return 0;
}

void RegisterOpenSLESThunks(ThunkManager& manager, DynarmicHost& host) {
    g_opensles_host = &host;
    LOGI("Registering OpenSL ES guest bridge thunks...");

    // Register all standard OpenSL ES interface IDs
    AllocAndRegisterIID(manager, host, "SL_IID_ENGINE", SL_IID_ENGINE);
    AllocAndRegisterIID(manager, host, "SL_IID_ANDROIDSIMPLEBUFFERQUEUE", SL_IID_ANDROIDSIMPLEBUFFERQUEUE);
    AllocAndRegisterIID(manager, host, "SL_IID_ANDROIDCONFIGURATION", SL_IID_ANDROIDCONFIGURATION);
    AllocAndRegisterIID(manager, host, "SL_IID_PLAY", SL_IID_PLAY);
    AllocAndRegisterIID(manager, host, "SL_IID_VOLUME", SL_IID_VOLUME);
    AllocAndRegisterIID(manager, host, "SL_IID_OUTPUTMIX", SL_IID_OUTPUTMIX);
    AllocAndRegisterIID(manager, host, "SL_IID_BUFFERQUEUE", SL_IID_BUFFERQUEUE);
    AllocAndRegisterIID(manager, host, "SL_IID_RECORD", SL_IID_RECORD);

    // 1. slCreateEngine
    manager.RegisterThunk("slCreateEngine", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t pEngine = jit.Regs()[0];
        LOGI("slCreateEngine called! pEngine=0x%08X", pEngine);

        // Initialize Host OpenSL ES
        if (!g_hostEngineObject) {
            auto fail = [&jit](SLresult result) {
                if (g_hostOutputMixObject) (*g_hostOutputMixObject)->Destroy(g_hostOutputMixObject);
                if (g_hostEngineObject) (*g_hostEngineObject)->Destroy(g_hostEngineObject);
                g_hostOutputMixObject = nullptr;
                g_hostEngineObject = nullptr;
                g_hostEngineEngine = nullptr;
                jit.Regs()[0] = result;
            };
            SLresult result = slCreateEngine(&g_hostEngineObject, 0, nullptr, 0, nullptr, nullptr);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host slCreateEngine failed: %u", result);
                fail(result);
                return;
            }

            result = (*g_hostEngineObject)->Realize(g_hostEngineObject, SL_BOOLEAN_FALSE);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host Engine Realize failed: %u", result);
                fail(result);
                return;
            }

            result = (*g_hostEngineObject)->GetInterface(g_hostEngineObject, SL_IID_ENGINE, &g_hostEngineEngine);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host Engine GetInterface failed: %u", result);
                fail(result);
                return;
            }

            // Create Host OutputMix
            result = (*g_hostEngineEngine)->CreateOutputMix(g_hostEngineEngine, &g_hostOutputMixObject, 0, nullptr, nullptr);
            if (result == SL_RESULT_SUCCESS) {
                result = (*g_hostOutputMixObject)->Realize(g_hostOutputMixObject, SL_BOOLEAN_FALSE);
            }
            if (result != SL_RESULT_SUCCESS) {
                fail(result);
                return;
            }
        }

        // Allocate Guest Engine Object structure
        if (g_guestEngineObjectAddr == 0) {
            g_guestEngineVtblAddr = host.GuestAlloc(64 * 4, 8);
            g_guestEngineObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestEngineObjectAddr, g_guestEngineVtblAddr);

            // Populate VTable with thunk addresses
            host.MemoryWrite32(g_guestEngineVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Resume"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_GetState"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 3 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_GetInterface"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 4 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_RegisterCallback"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 5 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_AbortAsyncOperation"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pEngine) {
            host.MemoryWrite32(pEngine, g_guestEngineObjectAddr);
        }

        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 2. Generic SLObject Thunks
    manager.RegisterThunk("SLObject_Realize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("SLObject_Realize called");
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t pState = jit.Regs()[1];
        if (pState) host.MemoryWrite32(pState, SL_OBJECT_STATE_REALIZED);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_AbortAsyncOperation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
    });

    manager.RegisterThunk("SLObject_Destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("SLObject_Destroy called");
        std::lock_guard<std::mutex> callback_lock(g_callbackMutex);
        const uint32_t object = jit.Regs()[0];
        if (object == g_guestPlayerObjectAddr || object == g_guestEngineObjectAddr) {
            g_guestCallbackAddr = 0;
            g_guestCallbackContext = 0;
            g_guestMixAddr = 0;
            g_bqCallbackPending.store(0, std::memory_order_release);
            g_cbFp0.store(0, std::memory_order_relaxed);
            g_cbFp1.store(0, std::memory_order_relaxed);
            g_cbStubStreak.store(0, std::memory_order_relaxed);
            if (g_hostPlayerObject) (*g_hostPlayerObject)->Destroy(g_hostPlayerObject);
            g_hostPlayerObject = nullptr;
            g_hostPlayerPlay = nullptr;
            g_hostPlayerBufferQueue = nullptr;
            g_hostPlayerVolume = nullptr;
            g_currentBufferIndex = 0;
            // Destroy has joined any in-flight HAL callback.
            g_bqCallbackPending.store(0, std::memory_order_release);
        }
        if (object == g_guestOutputMixObjectAddr || object == g_guestEngineObjectAddr) {
            if (g_hostOutputMixObject) (*g_hostOutputMixObject)->Destroy(g_hostOutputMixObject);
            g_hostOutputMixObject = nullptr;
        }
        if (object == g_guestEngineObjectAddr) {
            if (g_hostEngineObject) (*g_hostEngineObject)->Destroy(g_hostEngineObject);
            g_hostEngineObject = nullptr;
            g_hostEngineEngine = nullptr;
        }
    });

    // 3. SLEngine_GetInterface
    manager.RegisterThunk("SLEngine_GetInterface", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t self = jit.Regs()[0];
        uint32_t iid_ptr = jit.Regs()[1];
        uint32_t pInterface = jit.Regs()[2];

        LOGI("SLEngine_GetInterface self=0x%08X, iid=0x%08X, pInterface=0x%08X", self, iid_ptr, pInterface);

        if (IID_Matches(host, iid_ptr, SL_IID_ENGINE)) {
            if (g_guestEngineInterfaceAddr == 0) {
                g_guestEngineInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                g_guestEngineInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestEngineInterfaceAddr, g_guestEngineInterfaceVtblAddr);

                // Populate SLEngineItf VTable
                host.MemoryWrite32(g_guestEngineInterfaceVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_CreateAudioPlayer"));
                host.MemoryWrite32(g_guestEngineInterfaceVtblAddr + 7 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_CreateOutputMix"));
            }

            if (pInterface) {
                host.MemoryWrite32(pInterface, g_guestEngineInterfaceAddr);
            }
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        LOGI("SLEngine_GetInterface: unsupported IID 0x%08X", iid_ptr);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    // 4. SLEngine_CreateOutputMix
    manager.RegisterThunk("SLEngine_CreateOutputMix", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t pMix = jit.Regs()[1];
        LOGI("SLEngine_CreateOutputMix called! pMix=0x%08X", pMix);

        if (g_guestOutputMixObjectAddr == 0) {
            g_guestOutputMixVtblAddr = host.GuestAlloc(64 * 4, 8);
            g_guestOutputMixObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestOutputMixObjectAddr, g_guestOutputMixVtblAddr);

            host.MemoryWrite32(g_guestOutputMixVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestOutputMixVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_GetState"));
            host.MemoryWrite32(g_guestOutputMixVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pMix) {
            host.MemoryWrite32(pMix, g_guestOutputMixObjectAddr);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 5. SLEngine_CreateAudioPlayer
    manager.RegisterThunk("SLEngine_CreateAudioPlayer", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t self = jit.Regs()[0];
        uint32_t pPlayer = jit.Regs()[1];
        uint32_t pAudioSrc = jit.Regs()[2];
        uint32_t pAudioSnk = jit.Regs()[3];
        uint32_t numInterfaces = jit.Regs()[4];
        LOGI("SLEngine_CreateAudioPlayer called! pPlayer=0x%08X, pAudioSrc=0x%08X, pAudioSnk=0x%08X",
             pPlayer, pAudioSrc, pAudioSnk);

        // Parse PCM parameters from guest
        SLuint32 numChannels = 2;
        SLuint32 sampleRate = SL_SAMPLINGRATE_44_1;
        SLuint32 channelMask = SL_SPEAKER_FRONT_LEFT | SL_SPEAKER_FRONT_RIGHT;

        if (pAudioSrc) {
            uint32_t pFormat = host.MemoryRead32(pAudioSrc + 4);
            if (pFormat) {
                const SLDataFormat_PCM* gfmt = reinterpret_cast<const SLDataFormat_PCM*>(
                    GuestToHost(host.GetGuestMemoryBase(), pFormat));
                if (gfmt && gfmt->formatType == SL_DATAFORMAT_PCM) {
                    numChannels = gfmt->numChannels;
                    sampleRate = gfmt->samplesPerSec;
                    channelMask = gfmt->channelMask;
                    LOGI("Extracted PCM format from guest: %u channels, %u mHz sampleRate", numChannels, sampleRate);
                }
            }
        }

        // Setup host OpenSL ES Audio Player
        SLDataLocator_AndroidSimpleBufferQueue loc_bufq = {
            SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE,
            static_cast<SLuint32>(BUFFER_QUEUE_COUNT)
        };

        SLDataFormat_PCM format_pcm = {
            SL_DATAFORMAT_PCM,
            numChannels,
            sampleRate,
            SL_PCMSAMPLEFORMAT_FIXED_16,
            SL_PCMSAMPLEFORMAT_FIXED_16,
            channelMask,
            SL_BYTEORDER_LITTLEENDIAN
        };

        SLDataSource audioSrc = { &loc_bufq, &format_pcm };

        SLDataLocator_OutputMix loc_outmix = {
            SL_DATALOCATOR_OUTPUTMIX,
            g_hostOutputMixObject
        };
        SLDataSink audioSnk = { &loc_outmix, nullptr };

        const SLInterfaceID ids[4] = { SL_IID_ANDROIDSIMPLEBUFFERQUEUE, SL_IID_PLAY, SL_IID_VOLUME, SL_IID_ANDROIDCONFIGURATION };
        const SLboolean req[4] = { SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE };

        if (g_hostEngineEngine && !g_hostPlayerObject) {
            SLresult res = (*g_hostEngineEngine)->CreateAudioPlayer(
                g_hostEngineEngine, &g_hostPlayerObject, &audioSrc, &audioSnk, 4, ids, req);
            if (res == SL_RESULT_SUCCESS) {
                // Set Android Media Stream Type BEFORE Realize
                SLAndroidConfigurationItf configItf = nullptr;
                if ((*g_hostPlayerObject)->GetInterface(g_hostPlayerObject, SL_IID_ANDROIDCONFIGURATION, &configItf) == SL_RESULT_SUCCESS) {
                    SLint32 streamType = SL_ANDROID_STREAM_MEDIA;
                    (*configItf)->SetConfiguration(configItf, SL_ANDROID_KEY_STREAM_TYPE, &streamType, sizeof(SLint32));
                }

                res = (*g_hostPlayerObject)->Realize(g_hostPlayerObject, SL_BOOLEAN_FALSE);
                if (res == SL_RESULT_SUCCESS)
                    res = (*g_hostPlayerObject)->GetInterface(g_hostPlayerObject, SL_IID_PLAY, &g_hostPlayerPlay);
                if (res == SL_RESULT_SUCCESS)
                    res = (*g_hostPlayerObject)->GetInterface(g_hostPlayerObject, SL_IID_ANDROIDSIMPLEBUFFERQUEUE, &g_hostPlayerBufferQueue);
                if (res == SL_RESULT_SUCCESS)
                    res = (*g_hostPlayerObject)->GetInterface(g_hostPlayerObject, SL_IID_VOLUME, &g_hostPlayerVolume);
                
                if (g_hostPlayerVolume) {
                    (*g_hostPlayerVolume)->SetVolumeLevel(g_hostPlayerVolume, 0); // 0 mB = 100% full volume
                }

                if (res == SL_RESULT_SUCCESS)
                    res = (*g_hostPlayerBufferQueue)->RegisterCallback(g_hostPlayerBufferQueue, HostBqPlayerCallback, nullptr);
                LOGI("Host Audio Player created and realized successfully!");
            } else {
                LOGE("Host CreateAudioPlayer failed: %u", res);
            }
            if (res != SL_RESULT_SUCCESS) {
                if (g_hostPlayerObject) (*g_hostPlayerObject)->Destroy(g_hostPlayerObject);
                g_hostPlayerObject = nullptr;
                g_hostPlayerPlay = nullptr;
                g_hostPlayerBufferQueue = nullptr;
                g_hostPlayerVolume = nullptr;
                jit.Regs()[0] = res;
                return;
            }
        }
        if (!g_hostPlayerObject) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }

        // Allocate Guest Player Object
        if (g_guestPlayerObjectAddr == 0) {
            g_guestPlayerVtblAddr = host.GuestAlloc(64 * 4, 8);
            g_guestPlayerObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestPlayerObjectAddr, g_guestPlayerVtblAddr);

            host.MemoryWrite32(g_guestPlayerVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_GetState"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 3 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLPlayer_GetInterface"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pPlayer) {
            host.MemoryWrite32(pPlayer, g_guestPlayerObjectAddr);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 6. SLPlayer_GetInterface
    manager.RegisterThunk("SLPlayer_GetInterface", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t self = jit.Regs()[0];
        uint32_t iid_ptr = jit.Regs()[1];
        uint32_t pInterface = jit.Regs()[2];

        LOGI("SLPlayer_GetInterface self=0x%08X, iid=0x%08X, pInterface=0x%08X", self, iid_ptr, pInterface);

        if (IID_Matches(host, iid_ptr, SL_IID_PLAY)) {
            LOGI("SLPlayer_GetInterface: matched SL_IID_PLAY");
            if (g_guestPlayInterfaceAddr == 0) {
                g_guestPlayInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                g_guestPlayInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestPlayInterfaceAddr, g_guestPlayInterfaceVtblAddr);

                host.MemoryWrite32(g_guestPlayInterfaceVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLPlay_SetPlayState"));
                host.MemoryWrite32(g_guestPlayInterfaceVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLPlay_GetPlayState"));
            }
            if (pInterface) host.MemoryWrite32(pInterface, g_guestPlayInterfaceAddr);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_ANDROIDSIMPLEBUFFERQUEUE) || IID_Matches(host, iid_ptr, SL_IID_BUFFERQUEUE)) {
            LOGI("SLPlayer_GetInterface: matched SL_IID_ANDROIDSIMPLEBUFFERQUEUE");
            if (g_guestBufferQueueInterfaceAddr == 0) {
                g_guestBufferQueueInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                g_guestBufferQueueInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestBufferQueueInterfaceAddr, g_guestBufferQueueInterfaceVtblAddr);

                host.MemoryWrite32(g_guestBufferQueueInterfaceVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLBufferQueue_Enqueue"));
                host.MemoryWrite32(g_guestBufferQueueInterfaceVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLBufferQueue_Clear"));
                host.MemoryWrite32(g_guestBufferQueueInterfaceVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLBufferQueue_GetState"));
                host.MemoryWrite32(g_guestBufferQueueInterfaceVtblAddr + 3 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLBufferQueue_RegisterCallback"));
            }
            if (pInterface) host.MemoryWrite32(pInterface, g_guestBufferQueueInterfaceAddr);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_VOLUME)) {
            LOGI("SLPlayer_GetInterface: matched SL_IID_VOLUME");
            if (g_guestVolumeInterfaceAddr == 0) {
                g_guestVolumeInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                g_guestVolumeInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestVolumeInterfaceAddr, g_guestVolumeInterfaceVtblAddr);

                host.MemoryWrite32(g_guestVolumeInterfaceVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLVolume_SetVolumeLevel"));
            }
            if (pInterface) host.MemoryWrite32(pInterface, g_guestVolumeInterfaceAddr);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_ANDROIDCONFIGURATION)) {
            LOGI("SLPlayer_GetInterface: matched SL_IID_ANDROIDCONFIGURATION");
            if (g_guestConfigInterfaceAddr == 0) {
                g_guestConfigInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                g_guestConfigInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestConfigInterfaceAddr, g_guestConfigInterfaceVtblAddr);

                host.MemoryWrite32(g_guestConfigInterfaceVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLConfig_SetConfiguration"));
                host.MemoryWrite32(g_guestConfigInterfaceVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLConfig_GetConfiguration"));
            }
            if (pInterface) host.MemoryWrite32(pInterface, g_guestConfigInterfaceAddr);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        LOGI("SLPlayer_GetInterface: unsupported IID 0x%08X (returning FEATURE_UNSUPPORTED)", iid_ptr);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    manager.RegisterThunk("SLConfig_SetConfiguration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLConfig_GetConfiguration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 7. SLPlay Thunks
    manager.RegisterThunk("SLPlay_SetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t state = jit.Regs()[1];
        LOGI("SLPlay_SetPlayState: %u", state);
        const SLresult result = g_hostPlayerPlay
            ? (*g_hostPlayerPlay)->SetPlayState(g_hostPlayerPlay, static_cast<SLuint32>(state))
            : SL_RESULT_PRECONDITIONS_VIOLATED;
        if (result == SL_RESULT_SUCCESS) g_audioPaused.store(state != SL_PLAYSTATE_PLAYING);
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLPlay_GetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t pState = jit.Regs()[1];
        if (pState) {
            SLuint32 state = SL_PLAYSTATE_PLAYING;
            if (g_hostPlayerPlay) (*g_hostPlayerPlay)->GetPlayState(g_hostPlayerPlay, &state);
            host.MemoryWrite32(pState, state);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 8. SLBufferQueue Thunks
    manager.RegisterThunk("SLBufferQueue_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t cb = jit.Regs()[1];
        std::lock_guard<std::mutex> callback_lock(g_callbackMutex);
        const uint32_t context = jit.Regs()[2];
        const uint32_t mix = host.FindSymbol("_ZN3vox13DriverAndroid13DoCallbackOSLEv");
        if (!BqCallbackInCodeSegment(cb) ||
            cb != host.FindSymbol("_ZN3vox13DriverAndroid11CallbackOSLEPKPK17SLBufferQueueItf_Pv") ||
            !mix || !context || !GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), context, 0xec)) {
            static int bad_logged = 0;
            if (++bad_logged <= 8)
                LOGE("[AUDIO] rejecting non-code callback 0x%08X (ctx=0x%08X)",
                     cb, jit.Regs()[2]);
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        g_guestCallbackAddr = cb;
        g_guestCallbackContext = context;
        g_guestMixAddr = mix;
        ResetBqCallbackPumpState();
        g_cbFp0.store(host.MemoryRead32(cb));
        g_cbFp1.store(host.MemoryRead32(cb + 4));
        try {
            StartAudioThread(&host);
        } catch (...) {
            g_guestCallbackAddr = g_guestCallbackContext = g_guestMixAddr = 0;
            jit.Regs()[0] = SL_RESULT_RESOURCE_ERROR;
            return;
        }
        LOGI("SLBufferQueue_RegisterCallback: callback=0x%08X, context=0x%08X",
             g_guestCallbackAddr, g_guestCallbackContext);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLBufferQueue_Clear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const SLresult result = g_hostPlayerBufferQueue
            ? (*g_hostPlayerBufferQueue)->Clear(g_hostPlayerBufferQueue)
            : SL_RESULT_PRECONDITIONS_VIOLATED;
        if (result == SL_RESULT_SUCCESS) {
            std::lock_guard<std::mutex> lock(g_audioMutex);
            g_bqCallbackPending.store(0);
            g_currentBufferIndex = 0;
        }
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLBufferQueue_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t pState = jit.Regs()[1];
        if (!pState || !GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), pState, 8)) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLAndroidSimpleBufferQueueState state{};
        const SLresult result = g_hostPlayerBufferQueue
            ? (*g_hostPlayerBufferQueue)->GetState(g_hostPlayerBufferQueue, &state)
            : SL_RESULT_PRECONDITIONS_VIOLATED;
        if (result == SL_RESULT_SUCCESS) {
            host.MemoryWrite32(pState + 0, state.count);
            host.MemoryWrite32(pState + 4, state.index);
        }
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLBufferQueue_Enqueue", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t self = jit.Regs()[0];
        uint32_t pBuffer = jit.Regs()[1];
        uint32_t size = jit.Regs()[2];
        static uint32_t s_enq_count = 0;
        if (++s_enq_count <= 10 || s_enq_count % 200 == 0) {
            LOGI("SLBufferQueue_Enqueue #%u: size=%u, pBuffer=0x%08X, idx=%zu", s_enq_count, size, pBuffer, g_currentBufferIndex);
        }

        if (size > 0 && size <= MAX_BUFFER_SIZE && pBuffer &&
            uint64_t(pBuffer) + size <= host.GetGuestMemorySize()) {
            const void* guest_buf = GuestToHost(host.GetGuestMemoryBase(), pBuffer);
            if (guest_buf && g_hostPlayerBufferQueue) {
#if MC4_ENABLE_NATIVE_LOGGING
                {
                    const auto* bytes = static_cast<const uint8_t*>(guest_buf);
                    int peak = 0;
                    unsigned clipped = 0;
                    uint64_t energy = 0;
                    for (uint32_t i = 0; i + 1 < size; i += 2) {
                        int16_t sample;
                        memcpy(&sample, bytes + i, sizeof(sample));
                        peak = std::max(peak, std::abs(int(sample)));
                        clipped += sample == INT16_MIN || sample == INT16_MAX;
                        energy += int64_t(sample) * sample;
                    }
                    static int window_peak = 0;
                    static uint64_t window_clipped = 0, window_energy = 0, window_samples = 0;
                    static unsigned window_buffers = 0;
                    window_peak = std::max(window_peak, peak);
                    window_clipped += clipped;
                    window_energy += energy;
                    window_samples += size / 2;
                    if (++window_buffers >= 44 && window_samples) {
                        LOGI("PCM-WINDOW #%u: samples=%llu peak=%d clipped=%llu mean_square=%llu",
                             s_enq_count, (unsigned long long)window_samples, window_peak,
                             (unsigned long long)window_clipped,
                             (unsigned long long)(window_energy / window_samples));
                        window_peak = 0;
                        window_clipped = window_energy = window_samples = 0;
                        window_buffers = 0;
                    }
                }
#endif
                std::lock_guard<std::mutex> lock(g_audioMutex);
                SLAndroidSimpleBufferQueueState state{};
                SLresult res = (*g_hostPlayerBufferQueue)->GetState(g_hostPlayerBufferQueue, &state);
                if (res != SL_RESULT_SUCCESS || state.count >= BUFFER_QUEUE_COUNT) {
                    jit.Regs()[0] = res == SL_RESULT_SUCCESS ? SL_RESULT_BUFFER_INSUFFICIENT : res;
                    return;
                }
                const size_t copy_size = size;
                memcpy(g_hostAudioBuffers[g_currentBufferIndex], guest_buf, copy_size);

                res = (*g_hostPlayerBufferQueue)->Enqueue(
                    g_hostPlayerBufferQueue,
                    g_hostAudioBuffers[g_currentBufferIndex],
                    static_cast<SLuint32>(copy_size)
                );
                if (res == SL_RESULT_SUCCESS)
                    g_currentBufferIndex = (g_currentBufferIndex + 1) % BUFFER_QUEUE_COUNT;
                jit.Regs()[0] = res;
                return;
            }
        }
        jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
    });

    // 9. SLVolume Thunk
    manager.RegisterThunk("SLVolume_SetVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const SLmillibel level = static_cast<SLmillibel>(jit.Regs()[1]);
        jit.Regs()[0] = g_hostPlayerVolume
            ? (*g_hostPlayerVolume)->SetVolumeLevel(g_hostPlayerVolume, level)
            : SL_RESULT_PRECONDITIONS_VIOLATED;
    });
}
