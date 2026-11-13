#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <pthread.h>
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>
#include <dynarmic/interface/exclusive_monitor.h>

// [DEF84] arm a host-side write watch on the root movie def's class slot.
void ArmDef84Watch(uint32_t vaddr);

class ElfLoader;
class ThunkManager;

// Last sprite passed to SpriteInstance::advance (stage-notify shim).
uint32_t LastAdvancedSprite();

class DynarmicHost : public Dynarmic::A32::UserCallbacks {
public:
    // The full 32-bit guest address space. Mapping all of it means fastmem can resolve any
    // guest address as base + zext32(vaddr) without ever faulting.
    static constexpr size_t GUEST_ADDRESS_SPACE = 0x100000000ULL; // 4 GiB
    // Fallback if the 4 GiB reservation is refused: no fastmem, bounds-checked callbacks.
    static constexpr size_t GUEST_FALLBACK_SIZE = 0x80000000ULL;  // 2 GiB

    DynarmicHost();
    ~DynarmicHost() override;

    bool Initialize();
    bool LoadGame(const std::string& elf_path);
    bool LoadGameFromMemory(const uint8_t* data, size_t size);

    bool LoadLibraries(const std::string& fmodex_path, const std::string& fmodevent_path, const std::string& game_path);
    bool LoadLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                 const uint8_t* fmodevent_data, size_t fmodevent_size,
                                 const uint8_t* game_data, size_t game_size);

    uint32_t RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args = {});
    uint32_t RunFunction(uint32_t target_pc, std::span<const uint32_t> args);
    // Each concurrently live guest worker has a distinct JIT and exclusive-
    // monitor processor slot. A parked worker cannot monopolize all workers.
    uint32_t RunWorkerFunction(uint32_t target_pc, const std::vector<uint32_t>& args = {}, bool* started = nullptr);
    bool TryRunWorkerFunction(uint32_t target_pc, const std::vector<uint32_t>& args);
    // Halt diagnostics of the most recent run (async audio-pump policing).
    uint32_t LastHaltPc() const { return m_last_halt_pc; }
    // Bring-up: sample the live guest PC while the JIT runs and log a
    // histogram, to name the code a long loading loop actually spins in.
    void StartPcSampler();
    uint32_t LastHaltLr() const { return m_last_halt_lr; }
    // Async contexts (audio pump, cooperative worker drain) must not descend
    // into the same stack window the main thread's live guest frames use;
    // this variant runs with an explicit stack top instead of m_stack_top.
    uint32_t RunFunctionAt(uint32_t stack_top, uint32_t target_pc, const std::vector<uint32_t>& args = {});
    uint32_t RunFunctionAt(uint32_t stack_top, uint32_t target_pc, std::span<const uint32_t> args);
    // Non-blocking variant for foreign threads (audio pump): returns false
    // without running if the run mutex is contended (the main JIT thread is
    // inside a run). Blocking here deadlocks: the main thread cannot make
    // progress while a pump thread holds m_mutex and waits on guest state
    // that only the main thread can advance.
    bool TryRunFunctionAt(uint32_t stack_top, uint32_t target_pc, const std::vector<uint32_t>& args = {});
    // Stack region for async guest calls, well below the main thread's live
    // frame window near m_stack_top.
    static constexpr uint32_t kAsyncStackTop = 0x7F700000;
    // R1 right after the last RunFunction: 64-bit guest returns are r0:r1, and
    // RunFunction hands back r0 only.
    uint32_t GetLastR1() const { return m_last_r1; }
    // Bring-up watchdog: best-effort live PC of the running JIT (unsynchronized
    // read of the register array while the JIT thread executes; u32 reads are
    // atomic on arm64 and a torn value only garbles one diagnostic line).
    Dynarmic::A32::Jit* GetJitForDiagnostics() const { return m_jit.get(); }
    const std::atomic<uint32_t>& WatchdogPcSlot() const { return m_watchdog_pc; }
    bool IsJitRunningFlag() const { return m_watchdog_active; }
    // Runs calls that were made from inside a thunk (i.e. from inside Jit::Run, where the JIT
    // is not re-entrant). Call once per frame from a point known to be outside the JIT.
    void DrainDeferred();

    uint8_t* GetGuestMemoryBase() const { return m_memory; }
    size_t GetGuestMemorySize() const { return m_memory_size; }
    ElfLoader& GetElfLoader() { return *m_elf_loader; }
    ElfLoader* GetFmodExLoader() { return m_fmodex_loader.get(); }
    ElfLoader* GetFmodEventLoader() { return m_fmodevent_loader.get(); }
    ThunkManager& GetThunkManager() { return *m_thunk_manager; }
    std::recursive_mutex& GetMutex() { return m_mutex; }
    uint32_t FindSymbol(const std::string& name);
    // Drop any cached translation of a guest range that was just rewritten.
    void InvalidateGuestCode(uint32_t addr, size_t size);
    // Per-host-thread guest TLS block: __kuser_get_tls consumers need a
    // stable per-thread pointer; a hard 0 lands every TLS slot on the zero
    // page and worker threads corrupt each other's state (gotcha 21).
    uint32_t GuestThreadTls();
    uint32_t ExistingGuestThreadTls();
    // Bionic pthread keys occupy slots 7..63 in that same 32-bit TLS array.
    // Key deletion clears live threads; worker teardown releases its page so
    // a recycled host thread identity cannot inherit stale guest TLS.
    void GuestClearTlsSlotForAllThreads(uint32_t slot);
    void ReleaseGuestThreadTls();
    // SVC dispatch and exceptions must hit the core that raised them: the
    // worker core used to have its thunks run against the MAIN register
    // file, corrupting both cores' state (gotcha 22).
    Dynarmic::A32::Jit& CurrentCore();
    // Watchdog recharges the fast-malloc pool table through this.
    void SetFastPoolTable(uint32_t t) { m_fast_pool_table = t; }
    // CZipReader ctor probe (native index seeding RE): the ctor's `this`.
    uint32_t m_zip_reader_this[8] = {0,0,0,0,0,0,0,0};
    uint32_t m_zip_reader_count = 0;
    void NoteZipReader(uint32_t this_ptr) {
        for (int i = 0; i < 8; ++i)
            if (m_zip_reader_this[i] == this_ptr) return;
        for (int i = 0; i < 8; ++i)
            if (!m_zip_reader_this[i]) { m_zip_reader_this[i] = this_ptr; ++m_zip_reader_count; return; }
    }
    bool HasZipReader() const { return m_zip_reader_count > 0; }
    // ARM32 bionic sync objects occupy four guest bytes. Native pthread
    // objects live in an address-keyed registry and never overwrite them.
    int GuestMutexInit(uint32_t mutex_addr, uint32_t attr_addr);
    int GuestMutexDestroy(uint32_t mutex_addr);
    int GuestMutexLock(uint32_t mutex_addr);
    int GuestMutexTryLock(uint32_t mutex_addr);
    int GuestMutexUnlock(uint32_t mutex_addr);
    int GuestCondInit(uint32_t cond_addr, uint32_t attr_addr);
    int GuestCondDestroy(uint32_t cond_addr);
    int GuestCondWait(uint32_t cond_addr, uint32_t mutex_addr,
                      uint32_t abstime_addr, bool timed);
    int GuestCondSignal(uint32_t cond_addr, bool all);
    uint32_t GuestAlloc(size_t size, size_t alignment = 8);
    void GuestFree(uint32_t addr);
    // Payload size of a live GuestAlloc block, 0 if addr did not come from here.
    uint32_t GuestAllocSize(uint32_t addr);
    // Address space for whole-file mappings (the mmap thunk), deliberately outside the
    // malloc heap: one expansion file can be hundreds of megabytes and would otherwise eat
    // the arena permanently -- a 345 MB .obb mapped twice is how "GuestAlloc out of guest
    // heap" showed up right after loading started. Bump-only, never freed: these mappings
    // live for the process and the address is never reused.
    uint32_t GuestAllocMapping(size_t size, size_t alignment);
    bool GuestMappingContains(uint32_t addr, uint64_t length);

    // Runaway-PC containment. The loaded modules and the trampoline page are
    // covered automatically; register anything else that legitimately holds guest
    // code (hand-built veneers, JIT-ed guest stubs) so it is not trapped.
    void AddExecutableRange(uint32_t base, uint32_t size);

    // Dynarmic UserCallbacks interface
    std::optional<std::uint32_t> MemoryReadCode(std::uint32_t vaddr) override;

    std::uint8_t MemoryRead8(std::uint32_t vaddr) override;
    std::uint16_t MemoryRead16(std::uint32_t vaddr) override;
    std::uint32_t MemoryRead32(std::uint32_t vaddr) override;
    std::uint64_t MemoryRead64(std::uint32_t vaddr) override;

    void MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) override;
    void MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) override;
    void MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) override;
    void MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) override;

    // Needed now that global_monitor is set: the base-class defaults return false, which makes
    // every guest STREX report failure and spin its retry loop forever.
    bool MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) override;
    bool MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) override;
    bool MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) override;
    bool MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) override;

    void InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) override;
    void CallSVC(std::uint32_t swi) override;
    void ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) override;

    void AddTicks(std::uint64_t ticks) override;
    std::uint64_t GetTicksRemaining() override;

    bool IsJitRunning() const { return m_is_running_jit; }

private:
    uint8_t* m_memory = nullptr;
    size_t m_memory_size = 0;
    // 24 x 256 KiB stacks use 0x7E800000..0x7EE00000, below the
    // main-JIT deferred-callback stack at 0x7EF80000.
    static constexpr size_t kMaxWorkerCores = 24;
    struct WorkerCoreSlot {
        std::unique_ptr<Dynarmic::A32::Jit> jit;
        bool in_use = false;
    };
    std::unique_ptr<Dynarmic::ExclusiveMonitor> m_monitor;
    Dynarmic::A32::UserConfig m_worker_config;
    std::array<WorkerCoreSlot, kMaxWorkerCores> m_worker_cores;
    std::mutex m_worker_cores_mutex;
    std::condition_variable m_worker_cores_cv;

    std::mutex m_tls_mutex;
    std::unordered_map<std::thread::id, uint32_t> m_tls_pages;
    // Fast guest malloc pool table (guest address, 4 words: curA,endA,curB,endB).
    // The watchdog recharges exhausted pools with fresh GuestAlloc windows.
    uint32_t m_fast_pool_table = 0;
    std::atomic<bool> m_fast_pool_recharge{false};
    struct GuestMutex {
        pthread_mutex_t native{};
        std::mutex owner_guard;
        std::thread::id owner{};
        unsigned depth = 0;
        int type = PTHREAD_MUTEX_NORMAL;
    };
    struct GuestCondition {
        pthread_cond_t native{};
    };
    std::mutex m_guest_sync_mutex;
    std::unordered_map<uint32_t, std::shared_ptr<GuestMutex>> m_guest_mutexes;
    std::unordered_map<uint32_t, std::shared_ptr<GuestCondition>> m_guest_conditions;
    std::shared_ptr<GuestMutex> FindGuestMutex(uint32_t addr, int& error);
    std::shared_ptr<GuestCondition> FindGuestCondition(uint32_t addr, int& error);
    std::thread::id m_main_run_tid;
    std::unique_ptr<Dynarmic::A32::Jit> m_jit;
    std::unique_ptr<ElfLoader> m_fmodex_loader;
    std::unique_ptr<ElfLoader> m_fmodevent_loader;
    std::unique_ptr<ElfLoader> m_elf_loader;
    std::unique_ptr<ThunkManager> m_thunk_manager;
    std::recursive_mutex m_mutex;
    bool m_is_running_jit = false;

    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> m_deferred;
    std::vector<std::pair<uint32_t, uint32_t>> m_code_ranges;   // [base, end)

    // Guest heap: bump pointer for fresh memory, free lists for reuse. Requests up
    // to kMaxClassSize round to a power-of-two size class; anything larger (asset
    // payloads, thread stacks) is sized exactly and recycled by exact capacity, so
    // repeated 8 MB stacks do not round up to 16 MB.
    static constexpr uint32_t kHeapBase  = 0x50000000;
    static constexpr uint32_t kHeapLimit = 0x7E000000;   // guest stacks live above this
    // Second heap window: the 2026-09-17 long-load runs exhausted the first
    // 704 MB (per-pass allocations). 0x80000000-0xA0000000 is free space
    // above the stacks and below the file-mapping region.
    static constexpr uint32_t kHeapWindow2 = 0x80000000;
    static constexpr uint32_t kHeapLimit2  = 0xE0000000;   // maps moved to 0xE0000000
    // File mappings sit above both guest stacks and below the kuser helper page.
    static constexpr uint32_t kMapBase   = 0xE0000000;   // shrunk 2026-09-17: heap window 2 needed the room
    static constexpr uint32_t kMapLimit  = 0xF0000000;
    static constexpr int kMinClassShift = 5;                        // 32 B smallest block
    static constexpr uint32_t kMaxClassSize = 1u << 20;             // 1 MB largest class
    static constexpr int kNumSizeClasses = 20 - kMinClassShift + 1;
    void HeapSelfCheck();
    std::mutex m_heap_mutex;
    std::vector<uint32_t> m_free_small[kNumSizeClasses];             // class -> block bases
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_free_huge; // capacity -> block bases
    uint32_t m_heap_current = kHeapBase;                             // guarded by m_heap_mutex
    uint32_t m_map_current  = kMapBase;                              // guarded by m_heap_mutex

    uint32_t m_stack_top    = 0x7F000000;
    uint32_t m_last_halt_pc = 0;
    uint32_t m_last_halt_lr = 0;
    // Process-wide pointer to the one live host; background threads (watchdog,
    // audio pump) re-read it every iteration so a destroyed host is never
    // dereferenced.
    static std::atomic<DynarmicHost*> s_live_host;

    std::uint64_t m_ticks_remaining = 0;
    // Spin-hunt disabled: AddTicks must never drive the budget to zero, because
    // a zero budget halts the JIT with reason=0 at every block boundary.
    bool m_ticks_unbounded = false;
    std::uint32_t m_last_r1 = 0;

    // Bring-up watchdog state (see RunFunction).
    std::atomic<uint32_t> m_watchdog_pc{0};
    std::atomic<bool> m_watchdog_active{false};
};
