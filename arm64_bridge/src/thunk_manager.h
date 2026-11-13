#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <array>
#include <atomic>
#include <memory>
#include <mutex>

namespace Dynarmic::A32 {
    class Jit;
}

class DynarmicHost;

using ThunkHandler = std::function<void(Dynarmic::A32::Jit& jit, DynarmicHost& host)>;

class ThunkManager {
public:
    ThunkManager(DynarmicHost& host);
    ~ThunkManager();

    void RegisterAllThunks();
    // Returns the guest address of this thunk's trampoline.
    uint32_t RegisterThunk(const std::string& name, ThunkHandler handler);
    void RegisterSymbol(const std::string& name, uint32_t address);

    uint32_t GetOrCreateThunkAddress(const std::string& name);
    // Lookup-only: 0 when the symbol has no trampoline. eglGetProcAddress
    // uses this so unknown extensions return NULL instead of minting new
    // trampoline cells (one of which collided with the RunFunction exit
    // trap and halted the loader on every GL-driver init).
    uint32_t FindThunkAddress(const std::string& name) const;
    void DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit);
    std::string FindThunkNameForProgramCounter(uint32_t guest_pc) const;
    uint32_t CopyRecentThunkNames(char (*out)[48], uint32_t count) const;
    // Diagnostic only: consume this thread's bounded handler count/time window.
    void DumpThreadProfile();

    const std::unordered_map<std::string, uint32_t>& GetThunkSymbolTable() const {
        return m_symbol_to_address;
    }

    static uint32_t s_screenWidth;
    static uint32_t s_screenHeight;
    // Virtual screen size reported to the guest for UI scaling; 0 = report the real one.
    static uint32_t s_virtualWidth;
    static uint32_t s_virtualHeight;
    static uint32_t s_forced_dpi;
    static uint32_t s_ui_inset;

private:
    static constexpr uint32_t kFastThunkCapacity = 16384;
#if MC4_ENABLE_NATIVE_LOGGING
    struct ProfileCounter {
        uint64_t calls = 0;
        uint64_t nanoseconds = 0;
    };
    static thread_local std::array<ProfileCounter, kFastThunkCapacity> s_thread_profile;
    static thread_local uint64_t s_thread_profile_overflow;
#endif
    struct FastThunkEntry {
        std::string name;
        ThunkHandler handler;
    };

    void RegisterGLThunks();
    void RegisterLibcThunks();
    uint32_t RegisterThunkLocked(const std::string& name, ThunkHandler handler);
    void PublishFastThunk(uint32_t thunk_id, const std::string& name,
                          const ThunkHandler& handler);
    void DispatchThunkEntry(uint32_t thunk_id, const char* name,
                            const ThunkHandler& handler, Dynarmic::A32::Jit& jit);
    DynarmicHost& m_host;
    uint32_t m_next_thunk_addr = 0x00010000; // Base address for thunk trampolines
    std::unordered_map<std::string, uint32_t> m_symbol_to_address;
    std::unordered_map<uint32_t, ThunkHandler> m_id_to_handler;
    std::unordered_map<uint32_t, std::string> m_id_to_name;
    mutable std::mutex m_registration_mutex;
    std::array<std::atomic<FastThunkEntry*>, kFastThunkCapacity> m_fast_thunks{};
    std::vector<std::unique_ptr<FastThunkEntry>> m_fast_thunk_storage;
};

struct GuestThreadWorker {
    uint32_t start_func;
    uint32_t arg;
};

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers();
void AddGuestThreadWorker(uint32_t start_func, uint32_t arg);
void BridgeAttachCurrentThread();

// Watchdog diagnostics: name of the last thunk dispatched and the total
// dispatch count (thunk_manager.cpp).
const char* LastThunkName();
uint64_t ThunkDispatchCount();

// Device probes the guest usually wants (thunk_manager.cpp). Kept generic: no
// game class is consulted, only android.os / Resources / system properties.
std::string QueryDeviceLanguage();
std::string QueryDeviceCountryCode();
uint32_t QueryDeviceDensity();
uint32_t QueryDeviceIsPad();

// Asset overriding from <externalFilesDir>/... (thunks_libc.cpp).
// Technique: the engine's own archive->archive->plain-file lookup chain is left
// alone; the first source is simply made to miss for any file the user dropped
// into the override root, so the engine's existing fallback does the work.
void SetAssetOverrideRoot(const std::string& root);
bool HasAssetOverride(const char* entry_name);
// plt_slot: the guest PLT entry of the archive-open function to divert.
// real_symbol: that same function's name, resolved in the guest for the tail call.
void InstallAssetOverrideHook(DynarmicHost& host, uint32_t plt_slot, const char* real_symbol);
