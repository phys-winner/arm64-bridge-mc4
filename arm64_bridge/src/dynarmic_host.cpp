#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "arm32_push.h"
#include "arm32_guest_atomic.h"
#include "thunk_types.h"
#include <algorithm>
#include <cstring>
#include <atomic>
#include <functional>
#include <set>
#include <mutex>
#include <thread>
#include <exception>
#include <unwind.h>
#include <chrono>
#include <zlib.h>
#include <mutex>
#include <unordered_map>
#include <android/log.h>
#include "thunks_opensles.h"
#include <pthread.h>
#include "mc4_phase3.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define LOG_TAG "Arm32Bridge_Host"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#if MC4_ENABLE_NATIVE_LOGGING
const char* GuestGLUniformName(uint32_t location, uint32_t* program);
void GuestGLSkyPass(bool enter);
#endif

static std::atomic<uint32_t> g_iips_this{0};  // true iFPS 'this' (R10 in iFPS::Init)
// last sprite passed to SpriteInstance::advance (for stage-notify shim)
static std::atomic<uint32_t> g_last_adv_sprite{0};
uint32_t LastAdvancedSprite() { return g_last_adv_sprite.load(std::memory_order_relaxed); }

// Plain "libc++abi: terminating" tells nothing; name the exception (if any)
// before the process dies. Installed once at static init.
static _Unwind_Reason_Code TerminateUnwind(struct _Unwind_Context* ctx, void* arg) {
    uintptr_t pc = _Unwind_GetIP(ctx);
    int* n = reinterpret_cast<int*>(arg);
    if (*n < 48) LOGE("  unwind #%d: pc=0x%08lx", (*n)++, static_cast<long>(pc));
    return _URC_NO_REASON;
}

static const bool s_terminate_hook_installed = [] {
    std::set_terminate([] {
        if (std::current_exception()) {
            try { throw; }
            catch (const std::exception& e) { LOGE("TERMINATE exc: %s", e.what()); }
            catch (...) { LOGE("TERMINATE unknown exception"); }
        } else {
            LOGE("TERMINATE with no active exception");
        }
        int frames = 0;
        _Unwind_Backtrace(TerminateUnwind, &frames);
        std::abort();
    });
    return true;
}();
namespace {
// Which JIT the CURRENT host thread is executing guest code on. Both the
// main run and worker runs funnel through here before guest code executes.
// Thread identity alone is wrong: RunFunctionAt is invoked from several host
// threads (sensor/input/deferred drains), which would misattribute the main
// core and send its SVCs to the worker registers.
thread_local Dynarmic::A32::Jit* tl_current_core = nullptr;

// GuestAlloc leak hunt: allocation size-class histogram + live block count
// (allocs minus frees). The watchdog logs these so a per-pass leak shows up
// as a steadily climbing live counter.
std::atomic<uint64_t> g_alloc_buckets[32]{};
std::atomic<uint64_t> g_alloc_frees{0};
std::atomic<int64_t> g_alloc_live{0};
std::atomic<uint64_t> g_free_magic_miss{0};
// FileManager instance captured by probe_fm_vtable (0x567A24); consumed by
// probe_fm_init_shunt (0x56868C) to short-circuit later Init calls.
// Milestone probe sites that must be re-installed after guest initialization.
// Code probes are installed before .init_array; some guest constructors
// overwrite probe sites. Keep every control-flow probe needed by bring-up in
// this list so the post-constructor pass restores the exact SVC words.
static std::vector<std::pair<uint32_t, uint32_t>> g_probe_rewrites;
std::atomic<uint32_t> g_fm_captured_instance{0};
struct FindClassDropRefTrace {
    bool drop_seen = false;
    bool free_seen = false;
    uint32_t drop_sp = 0;
    uint32_t drop_saved_lr = 0;
    uint32_t object = 0;
    uint32_t ref_count = 0;
    uint32_t vtable = 0;
    uint32_t destructor = 0;
    uint32_t free_sp = 0;
    uint32_t free_pointer = 0;
    uint32_t free_size = 0;
};
thread_local FindClassDropRefTrace tl_findclass_dropref_trace;
}  // namespace


#define EXIT_TRAP_ARM   0x00000004
#define EXIT_TRAP_THUMB 0x00000008

std::atomic<DynarmicHost*> DynarmicHost::s_live_host{nullptr};

DynarmicHost::DynarmicHost() = default;

DynarmicHost::~DynarmicHost() {
    StopAudioThread();
    if (m_memory) {
#if defined(_WIN32)
        VirtualFree(m_memory, 0, MEM_RELEASE);
#else
        munmap(m_memory, m_memory_size);
#endif
        m_memory = nullptr;
    }
}

// Reserve guest memory. MAP_NORESERVE keeps the 4 GiB reservation virtual: untouched pages
// cost nothing and only written pages are ever committed.
static uint8_t* MapGuestMemory(size_t size) {
#if defined(_WIN32)
    return reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
    void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? nullptr : reinterpret_cast<uint8_t*>(p);
#endif
}

namespace {
// [ENV74] write-watch window: armed by the DOINIT probe, disarmed by the
// ENV74 dtor probe when doInitActions destroys its stack ASEnvironment.
// While armed, every guest store into the env's inline ASValue slots
// (env 0x7EFFF504 + 0x70..0xD0) is logged with the writer's PC/LR -- one
// of those stores carries the corrupt object pointer whose dropRef
// fetches wild code during the entry-script teardown.
std::atomic<bool> g_env74_watch{false};
std::atomic<uint32_t> g_env74_hits{0};
// [VTVGUARD] The teardown chaos wrote wild pointers over the MenuFX
// vtable (image .data.rel.ro, read-only on real hardware). Guard just
// that window: drop any write whose value is not an in-image code pointer.
std::atomic<bool> g_relro_on{false};
constexpr uint32_t kRelroStart = 0x4172CA68u;   // .data.rel.ro.local
constexpr uint32_t kRelroEnd = 0x417982FCu;     // ..end of .data.rel.ro (GOT EXCLUDED)
// [DEF84] watch address for the root movie def's class slot
std::atomic<uint32_t> g_def84_addr{0};
}  // namespace
void ArmDef84Watch(uint32_t vaddr) {
    g_def84_addr.store(vaddr, std::memory_order_relaxed);
}

namespace mc4 { bool InstallFastGuestMalloc(DynarmicHost& host); }
extern void BridgeSafepointCheck();
namespace mc4 { bool InstallZipResultProbe(DynarmicHost& host, uint32_t init_entry_guest); }

bool DynarmicHost::Initialize() {
    // Mapping the whole 32-bit space lets the JIT emit a single `ldr Wt, [Xfastmem, Waddr, uxtw]`
    // per guest access instead of a call into MemoryRead*/MemoryWrite*.
    m_memory_size = GUEST_ADDRESS_SPACE;
    m_memory = MapGuestMemory(m_memory_size);

    bool fastmem = m_memory != nullptr;
    if (m_memory == nullptr) {
        LOGE("Could not reserve %zu bytes for the guest address space; "
             "falling back to %zu bytes without fastmem.", GUEST_ADDRESS_SPACE, GUEST_FALLBACK_SIZE);
        m_memory_size = GUEST_FALLBACK_SIZE;
        m_memory = MapGuestMemory(m_memory_size);
        if (!m_memory) {
            LOGE("Failed to allocate guest memory (%zu bytes)", m_memory_size);
            m_memory_size = 0;
            return false;
        }
    }

    s_live_host.store(this, std::memory_order_release);

    HeapSelfCheck();

    // ARM exit trap at 0x00000004: SVC 0 (0xEF000000)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_ARM) = 0xEF000000;

    // Thumb exit trap at 0x00000008: SVC 0 (0xDF00, 0xDF00)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_THUMB) = 0xDF00DF00;

    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();

    // Guest-side bump allocator for malloc/calloc: removes the per-call
    // SVC->host->JIT roundtrip that dominated the zip TOC parse (2026-09-17).
    if (!mc4::InstallFastGuestMalloc(*this)) {
        LOGE("fast guest malloc not installed; falling back to thunk malloc");
    }
    m_fast_pool_recharge = true;

    // Linux ARM kuser helper page (0xFFFF0FA0/FC0/FE0): old binaries call
    // __kuser_cmpxchg/__kuser_get_tls/__kuser_memory_barrier directly. The
    // guest's protobuf OnShutdown static-init used __kuser_cmpxchg, hit the
    // RUNAWAY guard at boot, and died - leaving later static objects (the
    // Application stage-1 gate singleton) unconstructed forever. Write
    // SVC+BX-LR trampolines into the kuser page and register the handlers.
    {
        auto kuser = [&](const char* name, uint32_t page_addr,
                         std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)> body) {
            uint32_t t = m_thunk_manager->RegisterThunk(name, body);
            uint32_t svc = MemoryRead32(t) & 0x00FFFFFFu;
            MemoryWrite32(page_addr, 0xEF000000u | svc);
            MemoryWrite32(page_addr + 4, 0xE12FFF1Eu); // BX LR
            LOGI("kuser helper '%s' mapped at 0x%08X (svc %u)", name, page_addr, svc);
        };
        // Canonical ARM kernel layout (gotcha 20): barrier=0xFFFF0FA0,
        // cmpxchg=0xFFFF0FC0, get_tls=0xFFFF0FE0. A rotated mapping put
        // cmpxchg at the barrier slot: GoogleOnce's CAS compared garbage,
        // the init gate never opened, and App::GetInstance spun forever.
        kuser("kuser_memory_barrier", 0xFFFF0FA0u,
              [](Dynarmic::A32::Jit&, DynarmicHost&) {
                  mc4::GuestMemoryBarrier();
              });
        kuser("kuser_cmpxchg", 0xFFFF0FC0u,
              [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                  // r0=oldval, r1=newval, r2=guest ptr; C=1 iff r0 is zero.
                  uint32_t ptr = jit.Regs()[2];
                  uint32_t oldv = jit.Regs()[0];
                  uint32_t newv = jit.Regs()[1];
                  const bool exchanged = mc4::GuestAtomicCompareExchange(
                      host.GetGuestMemoryBase(), host.GetGuestMemorySize(), ptr, oldv, newv);
                  jit.Regs()[0] = exchanged ? 0u : 0xFFFFFFFFu;
                  jit.SetCpsr(mc4::KuserCpsrWithCarry(jit.Cpsr(), exchanged));
              });
        kuser("kuser_get_tls", 0xFFFF0FE0u,
              [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                  jit.Regs()[0] = host.GuestThreadTls();
              });
    }

    // The JIT dereferences global_monitor unconditionally for LDREX/STREX.
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(kMaxWorkerCores + 1);

    Dynarmic::A32::UserConfig config;
    // No coprocessor is registered on purpose: the guest has no legitimate
    // CP15 instructions (verified by an ELF scan). Junk-decoded coproc words
    // from code slides raise a guest exception via the backend's
    // EmitCoprocessorException -> ExceptionRaised path, which halts the
    // offending run instead of asserting.
    config.callbacks = this;
    config.global_monitor = m_monitor.get();
    config.arch_version = Dynarmic::A32::ArchVersion::v7;  // guest libs are ARMv7-A + NEON
    // Every guest call runs to a real return (kSpinHuntBudget == 0 below).
    // Counting cycles therefore cannot terminate a run. In the pinned
    // Dynarmic A32 backend it instead calls AddTicks and GetTicksRemaining
    // around *every* SVC, including every GLES thunk, and emits per-block
    // tick arithmetic. Keep the independent watchdog/halt checks, but drop
    // this redundant render-path overhead.
    config.enable_cycle_counting = false;
    config.always_little_endian = true;                    // guest never uses SETEND; drops CPSR.E handling
    config.define_unpredictable_behaviour = true;          // define rather than halt on odd encodings
    // Keep the linear GetSet/DCE pass: repeated guest register state traffic
    // is hot on the CPU-bound render thread. Do not enable ConstProp: the menu
    // loader's deep IR dependency chains blew the GLThread stack in that pass
    // (tombstone_12). This is a separate measured A/B from probe removal.
    config.optimizations = static_cast<Dynarmic::OptimizationFlag>(
        static_cast<uint32_t>(Dynarmic::OptimizationFlag::BlockLinking) |
        static_cast<uint32_t>(Dynarmic::OptimizationFlag::ReturnStackBuffer) |
        static_cast<uint32_t>(Dynarmic::OptimizationFlag::FastDispatch) |
        static_cast<uint32_t>(Dynarmic::OptimizationFlag::GetSetElimination));
    if (fastmem) {
        config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);
    }

    m_jit = std::make_unique<Dynarmic::A32::Jit>(config);

    // Worker cores are created lazily with unique monitor processor IDs.
    // One cached JIT may be reused only after its previous Run() has exited.
    m_worker_config = config;

    // Pre-build the Thumb decode table on THIS thread, single-threaded. The
    // first Thumb block used to arrive on a worker during FMOD init; the
    // lazy GetThumbDecodeTable build threw inside its inplace_merge and the
    // escaping exception killed the process (runs 2026-09-17 01:56-02:07).
    {
        const uint32_t thumb_code[2] = {0x47704770};  // bx lr; bx lr
        memcpy(m_memory + EXIT_TRAP_THUMB + 16, thumb_code, sizeof(thumb_code));
        AddExecutableRange(EXIT_TRAP_THUMB + 16, 8);
        RunFunctionAt(0x7EFFF000u, EXIT_TRAP_THUMB + 17 /* thumb bit */);
        LOGI("[INIT] Thumb decode table prebuilt");
    }

    LOGI("Dynarmic Host initialized: %zu bytes guest space, fastmem %s",
         m_memory_size, fastmem ? "ON" : "OFF");
    return true;
}

bool DynarmicHost::LoadGame(const std::string& elf_path) {
    LOGI("Loading main game ELF from file: %s", elf_path.c_str());
    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->Load(elf_path)) {
        LOGE("Failed to load ELF: %s", elf_path.c_str());
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Game ELF loaded and initialized successfully!");
    return true;
}

bool DynarmicHost::LoadGameFromMemory(const uint8_t* data, size_t size) {
    LOGI("Loading main game ELF from memory (%zu bytes)...", size);
    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->LoadFromMemory(data, size)) {
        LOGE("Failed to load ELF from memory buffer");
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    // Bring-up probe: genericDriverInit loads its ctype table through this GOT
    // slot (guest vaddr 0x17987CC); the version-string scan hangs if it is 0.
    // Remove with the rest of the phase-7 bring-up diagnostics.
    LOGI("[PROBE] GOT _ctype_ slot @0x17987CC = 0x%08X, resolver(_ctype_)=0x%08X",
         MemoryRead32(0x40000000u + 0x17987CCu), m_thunk_manager->GetOrCreateThunkAddress("_ctype_"));

    // (phase-7 SVC code probes at 0x8872E0/EC/F8 were removed: their r0/r3
    // clobbering corrupted the very path they instrumented.)
    // Bring-up: log every item id queried through InAppBilling::getItemInfoByID.
    // The probe replaces the function's `push {r4-r11, lr}` prologue with an
    // SVC; the handler logs r1 (the id) and then performs the push itself, so
    // the guest continues with an intact frame. Remove with phase-7 cleanup.
    {
        uint32_t probe_addr = m_thunk_manager->RegisterThunk("probe_iab_lookup",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                uint32_t name_g = jit.Regs()[1];
                static std::mutex m;
                static std::set<std::string> seen;
                if (name_g && host.GetGuestMemoryBase()) {
                    const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + name_g);
                    char buf[64]; size_t n = 0;
                    while (n + 1 < sizeof(buf) && p[n]) { buf[n] = p[n]; ++n; }
                    buf[n] = 0;
                    std::lock_guard<std::mutex> lk(m);
                    if (seen.insert(buf).second && seen.size() <= 150)
                        LOGI("[IAB-LOOKUP] '%s'", buf);
                }
                // emulate `push {r4-r11, lr}`: 9 words, r4..r11 then lr
                uint32_t sp = jit.Regs()[13] - 36;
                for (int i = 0; i < 8; ++i) host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                jit.Regs()[13] = sp;
            });
        uint32_t svc_id = MemoryRead32(probe_addr) & 0x00FFFFFFu;
        MemoryWrite32(0x40000000u + 0x4E8AB8u, 0xEF000000u | svc_id);
        LOGI("[IAB-LOOKUP] probe installed at 0x4E8AB8 (svc %u)", svc_id);

        // Bring-up: count gaia::ThreadManagerService::AddRequest calls and log
        // the request pointer per 1000th plus every pointer outside the malloc
        // heap (0x50000000..0x7E000000) - unaligned/garbage entries there are
        // what makes the startup priority sort spin forever. The probe
        // replaces AddRequest's `push {r4-r10, lr}` and performs it itself.
        {
            uint32_t add_addr = m_thunk_manager->RegisterThunk("probe_add_request",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> count{0};
                    uint32_t n = count.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t req = jit.Regs()[1];
                    bool in_w1 = req >= 0x50000000u && req < 0x7E000000u;
                    bool in_w2 = req >= kHeapWindow2 && req < kHeapLimit2;
                    bool outside = !in_w1 && !in_w2;
                    if (n <= 20 || (n % 1000) == 0 || outside)
                        LOGI("[ADDREQ] #%u req=%08X%s", n, req, outside ? " OUT-OF-HEAP!" : "");
                    // emulate `push {r4-r10, lr}`: 8 words
                    uint32_t sp = jit.Regs()[13] - 32;
                    for (int i = 0; i < 7; ++i) host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 28, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            uint32_t svc2 = MemoryRead32(add_addr) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0xD26F98u, 0xEF000000u | svc2);
            LOGI("[ADDREQ] probe installed at 0xD26F98 (svc %u)", svc2);
        }


        // Bring-up: dump ThreadManagerService state on every StartRequest.
        {
            uint32_t sr_addr = m_thunk_manager->RegisterThunk("probe_start_request",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> count{0};
                    uint32_t n = count.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 12) {
                        uint32_t th = jit.Regs()[0];
                        uint32_t vt = host.MemoryRead32(th);
                        uint32_t f4 = host.MemoryRead32(th + 4);
                        uint32_t f8 = host.MemoryRead32(th + 8);
                        uint32_t fc = host.MemoryRead32(th + 0xC);
                        uint32_t f10 = host.MemoryRead32(th + 0x10);
                        LOGI("[STARTREQ] #%u this=%08X vtbl=%08X cap?=%08X size?=%08X begin=%08X end=%08X (bytes=%d)",
                             n, th, vt, f4, f8, fc, f10, (int32_t)(f10 - fc));
                        // MITIGATION: a garbage (unaligned / non-multiple-of-4)
                        // pending-request vector makes the unguarded insertion
                        // sort spin forever. Reset it to empty so the service
                        // skips this round instead of hanging the loader.
                        uint32_t bytes = f10 - fc;
                        if (bytes > 0 && ((bytes % 4) != 0 || (fc & 3u) != 0)) {
                            host.MemoryWrite32(th + 0xC, 0);
                            host.MemoryWrite32(th + 0x10, 0);
                            host.MemoryWrite32(th + 0x14, 0);
                            LOGE("[STARTREQ] sanitized garbage vector: begin=%08X end=%08X bytes=%u -> empty", fc, f10, bytes);
                        }
                    }
                    // emulate `push {r4-r11, lr}`: 9 words
                    uint32_t sp = jit.Regs()[13] - 36;
                    for (int i = 0; i < 8; ++i) host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            uint32_t svc4 = MemoryRead32(sr_addr) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0xD279FCu, 0xEF000000u | svc4);
            LOGI("[STARTREQ] probe installed at 0xD279FC (svc %u)", svc4);
        }

        // Bring-up: AndroidGetOBBPatchFilename entry + result probes. Entry
        // replaces `push {r4,r5,r6,r7,lr}` (emulated in-handler); the result
        // probe sits on `mov r0, r7` after GetStringUTFChars (emulated), and
        // logs the string the guest actually received plus its caller LR.
        {
            uint32_t ent = m_thunk_manager->RegisterThunk("probe_obb_patch_ent",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> cnt{0};
                    uint32_t n = cnt.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 10 || (n % 2000) == 0) {
                        LOGI("[OBB-PATCH] enter #%u caller_lr=%08X", n, jit.Regs()[14]);
                    }
                    // push {r4-r8, lr} = 6 words
                    uint32_t sp2 = jit.Regs()[13] - 24;
                    for (int i = 0; i < 5; ++i) host.MemoryWrite32(sp2 + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp2 + 20, jit.Regs()[14]);
                    jit.Regs()[13] = sp2;
                });
            uint32_t res = m_thunk_manager->RegisterThunk("probe_obb_patch_res",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> cnt{0};
                    uint32_t n = cnt.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 10 || (n % 2000) == 0) {
                        uint32_t utf = jit.Regs()[5];
                        char buf[80]; size_t k = 0;
                        if (utf && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + utf);
                            while (k + 1 < sizeof(buf) && p[k]) { buf[k] = p[k]; ++k; }
                        }
                        buf[k] = 0;
                        LOGI("[OBB-PATCH] result #%u utf=%08X len=%zu '%s'", n, utf, k, buf);
                    }
                    jit.Regs()[0] = jit.Regs()[7]; // emulate `mov r0, r7`
                });
            uint32_t s5 = MemoryRead32(ent) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x4D5394u, 0xEF000000u | s5);
            uint32_t s6 = MemoryRead32(res) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x4D53FCu, 0xEF000000u | s6);
            LOGI("[OBB-PATCH] probes installed (entry svc %u, result svc %u)", s5, s6);
        }

        // Bring-up: log addObbFileArchive entries (path in r1). Replaces the
        // `push {r4-r9, lr}` prologue and performs it itself.
        {
            uint32_t ao_addr = m_thunk_manager->RegisterThunk("probe_add_obb",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> cnt{0};
                    uint32_t n = cnt.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 12 || (n % 2000) == 0) {
                        uint32_t path_g = jit.Regs()[1];
                        char buf[80]; size_t k = 0;
                        if (path_g && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + path_g);
                            while (k + 1 < sizeof(buf) && p[k]) { buf[k] = p[k]; ++k; }
                        }
                        buf[k] = 0;
                        // caller frame: original sp; iFPS chain:
                        // cell=[sp+0xC]; device=[cell]; fs=[device+0x28]
                        uint32_t osp = jit.Regs()[13];
                        uint32_t cell = host.MemoryRead32(osp + 0xC);
                        uint32_t device = cell ? host.MemoryRead32(cell) : 0;
                        uint32_t fs = device ? host.MemoryRead32(device + 0x28) : 0;
                        LOGI("[ADD-OBB] #%u this=%08X path='%.40s' cell=%08X device=%08X fs=%08X",
                             n, jit.Regs()[0], buf, cell, device, fs);
                    }
                    // emulate `push {r4-r9, lr}`: 7 words
                    uint32_t sp = jit.Regs()[13] - 28;
                    for (int i = 0; i < 6; ++i) host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 24, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            uint32_t s7 = MemoryRead32(ao_addr) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x571790u, 0xEF000000u | s7);
            LOGI("[ADD-OBB] probe installed at 0x571790 (svc %u)", s7);
        }

        // Bring-up: CustomIrrFactory::createFileSystem — was the file system
        // ever created, and where did it go? Entry probe logs the cell; a
        // return-site probe at 0x5228B8 logs the stored value.
        {
            uint32_t cfs = m_thunk_manager->RegisterThunk("probe_cfs",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> cnt{0};
                    uint32_t n = cnt.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 8)
                        LOGI("[CFS] enter #%u cell=%08X fs_param=%08X", n, jit.Regs()[0], jit.Regs()[2]);
                    // push {r4, r5, r6, lr}: 4 words
                    uint32_t sp = jit.Regs()[13] - 16;
                    for (int i = 0; i < 3; ++i) host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 12, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            uint32_t s8 = MemoryRead32(cfs) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x522868u, 0xEF000000u | s8);
            LOGI("[CFS] probe installed at 0x522868 (svc %u)", s8);
        }

        // Diagnostic probes for selected iFPS::Init instructions. Each probe
        // replaces one linear instruction and must emulate that instruction
        // exactly.
        const struct {
            const char* name;
            uint32_t site;
            uint32_t expectedInstruction;
            int words;
        } milestones[] = {
            // ldr r0,[r6]            after mounts, folder loop
            {"M2_FOLDERS", 0x8A2CF0u, 0xE5960000u, 0},
            // ldr r3,[sp,#0x40]      first instruction AFTER the folder
            //                        loop exit (0x8A2D14-18-1C fall
            //                        through): fires once per COMPLETED
            //                        loop. M2 fires 6x per pass, M2B 1x --
            //                        M2B << M2/6 means passes die inside
            //                        addObbFileArchive iterations.
            {"M2B_LOOPEXIT", 0x8A2D20u, 0xE59D3040u, 0},
            // ldr r0,[sp,#0x40]      MCLogger region
            {"M3_LOGGER", 0x8A2D40u, 0xE59D0040u, 0},
            // mov r1,r9              before Application::Init
            {"M4_APPINIT", 0x8A2D8Cu, 0xE1A01009u, 0},
            // mov r0,#532            after FileManager::Init
            {"M5_FMINIT", 0x8A2DCCu, 0xE3A00F85u, 0},
            // ldr r3,[pc,#0xc60]     after SoundManagerVox ctor
            {"M6_SND", 0x8A2DDCu, 0xE59F3C60u, 0},
            // 0x8A2DFC is BL CreationSettings::CreationSettings, not MOV R0,R9.
            // Leave it untouched: GlWebTools::Initialize consumes this object.
            // str r6,[r10,#0xAD8]    after MemoryObfuscationManager ctor
            {"W2_MEMOBF", 0x8A2E7Cu, 0xE58A6AD8u, 0},
            // str r6,[r3]            after MultiplayerManager ctor
            {"W3_MPCTOR", 0x8A2E9Cu, 0xE5836000u, 0},
            // mov r1,r4              after OnlineServicesManager::Init
            {"W4_OSINIT", 0x8A2EA4u, 0xE1A01004u, 0},
            // ldr r0,[r3,#0x28]      right before the SaveGame BLX
            {"W5_SAVEGD", 0x8A2ECCu, 0xE5930028u, 0},
            // ldr r3,[pc,#0x6a8]     spin/achievements region
            {"M7_SPIN", 0x8A33D4u, 0xE59F36A8u, 0},
            // mov r0,#0x358          after the SaveGame.bin vt call
            {"A0_SAVEGAME", 0x8A2EDCu, 0xE3A00FD6u, 0},
            // ldr r7,[r3,#4]         achievements count load (post-singleton)
            {"A1_ACHCNT", 0x8A2F0Cu, 0xE5937004u, 0},
            // ldrb r1,[r0,#0xBD]     after AndroidLoadLocalAchievementsAGC!
            {"A2_POSTAGC", 0x8A2FA8u, 0xE5D010BDu, 0},
            // ldr r3,[sp,#0xC]       after SetGyroscopeEnabled
            {"A3_GYRO", 0x8A2FB4u, 0xE59D300Cu, 0},
            // ldr r3,[pc,#0xA84]     after AndroidWasLaunchedByPN
            {"A4_PN", 0x8A2FC8u, 0xE59F3A84u, 0},
            // add r7,sp,#0x28        after BITracking singleton check
            {"A5_BITRACK", 0x8A2FE0u, 0xE28D7028u, 0},
            // mov r4,r0              after MenuManager ctor
            {"A4_MENUMGR", 0x8A3140u, 0xE1A04000u, 0},
            // mov r1,r0              right after _GetId("game_graphml"):
            //                        r0 = the resolved id (-1 = missing)
            {"A5_GRAPHML_ID", 0x8A317Cu, 0xE1A01000u, 0},
            // ldr r3,[r6]            Player::loadFile: fires only if the
            //                        shell createMovie returned non-null
            {"LF_MOVIE", 0xFB28D0u, 0xE5963000u, 0},
            // mov r0,r4              after vtable+0x3C Root creation
            {"LF_ROOT", 0xFB28ECu, 0xE1A00004u, 0},
            // mov r1,#0xD            flash.display String resize start
            {"AVM1", 0xFB2904u, 0xE3A0100Du, 0},
            // ldr r3,[sp,#0x14]      after Strcpy_s "flash.display"
            {"AVM2", 0xFB2944u, 0xE59D3014u, 0},
            // mov r1,#5              second String resize
            {"AVM3", 0xFB2950u, 0xE3A01005u, 0},
            // mov r5,r2              Character ctor: r5 = parent
            {"CHCTOR", 0xF6B058u, 0xE1A05002u, 0},
            // mov r2,#0               Character ctor: after CMP R5,#0
            {"CHCTOR2", 0xF6B074u, 0xE3A02000u, 0},
            // ldr r3,[r2,#0x10]      s_datas rb-tree walk step (key read).
            {"SDWALK", 0x73833Cu, 0xE5923010u, 0},
            // ldrb r3,[r7]           createRoot: after Root ctor
            //                        (R5=Root, R8=player)
            {"CR_ROOT", 0xF945BCu, 0xE5D73000u, 0},
            // ldr r0,[r4,#0x18]      createRoot: after Root caching
            {"CR2", 0xF945ECu, 0xE5940018u, 0},
            // mov r7,r0              createRoot: after createSpriteInstance
            {"CR3", 0xF94638u, 0xE1A07000u, 0},
            // str r0,[r6]            Data::Data right after ReadInt:
            //                        R0 = the graph state count
            {"DSCOUNT", 0x7381F0u, 0xE5860000u, 0},
            // ldr r3,[r2,#4]         SA_CreateState: the state type fed by
            //                        the graph parse (9=logo, 3=mainmenu)
            {"CS_TYPE", 0x8A17F0u, 0xE5923004u, 0},
            // mov r2,#0              StateAutomat ctor argument after MenuManager
            {"B1_POSTMM", 0x8A3154u, 0xE3A02000u, 0},
            // ldr r3,[pc,#0x900]     first instruction after StateAutomat ctor
            {"B2_POSTSA_CTOR", 0x8A3160u, 0xE59F3900u, 0},
        };
        for (const auto& m : milestones) {
            const uint32_t site = 0x40000000u + m.site;
            const uint32_t original = MemoryRead32(site);
            if (original != m.expectedInstruction) {
                LOGE("[IFPS-M] refusing stale probe %s at %08X: expected %08X, found %08X",
                     m.name, m.site, m.expectedInstruction, original);
                continue;
            }
            auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
            uint32_t tramp = m_thunk_manager->RegisterThunk(m.name,
                [m, cnt](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    uint32_t n = cnt->fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 3 || (n % 1000) == 0)
                        LOGI("[IFPS-M] %s #%u", m.name, n);
                    switch (m.expectedInstruction) {
                    case 0xE5960000u: {  // ldr r0,[r6]
                        // CustomFileSystem resurrection: the FS object's
                        // block gets freed+recycled+zeroed between passes
                        // while the device keeps a stale pointer, so the
                        // virtual call ldr r12,[r0,#0x1C]; blx r12 turns
                        // into a silent slide no-op and the whole loader
                        // pass becomes an empty shell (ADD-OBB 722 vs M2
                        // 99000 in the guard run). Capture the vtable the
                        // first time it is valid; restore it afterwards.
                        static uint32_t fs_vtable = 0;
                        static std::atomic<uint32_t> fs_fix{0};
                        uint32_t fs = jit.Regs()[6];
                        if (fs) {
                            uint32_t vp = host.MemoryRead32(fs);
                            if (vp >= 0x40000000u && vp < 0x44000000u) {
                                fs_vtable = vp;
                            } else if (fs_vtable) {
                                host.MemoryWrite32(fs, fs_vtable);
                                uint32_t k = fs_fix.fetch_add(1, std::memory_order_relaxed) + 1;
                                if (k <= 6 || (k % 1000) == 0)
                                    LOGE("[FSFIX] #%u CustomFileSystem %08X vptr %08X -> %08X",
                                         k, fs, vp, fs_vtable);
                            }
                        }
                        if (n == 1 || (n % 1000) == 0) {
                            uint32_t cell = host.MemoryRead32(jit.Regs()[13] + 0xC);
                            uint32_t dev = cell ? host.MemoryRead32(cell) : 0;
                            LOGI("[IFPS-M] %s #%u r6=%08X r0old=%08X cell=%08X dev=%08X",
                                 m.name, n, jit.Regs()[6], jit.Regs()[0], cell, dev);
                        }
                        jit.Regs()[0] = host.MemoryRead32(jit.Regs()[6]);
                        break;
                    }
                    case 0xE59D0040u:  // ldr r0,[sp,#0x40]
                        jit.Regs()[0] = host.MemoryRead32(jit.Regs()[13] + 0x40);
                        break;
                    case 0xE59D3040u:  // ldr r3,[sp,#0x40] (M2B loop exit)
                        jit.Regs()[3] = host.MemoryRead32(jit.Regs()[13] + 0x40);
                        break;
                    case 0xE1A01009u:  // mov r1,r9
                        jit.Regs()[1] = jit.Regs()[9];
                        break;
                    case 0xE3A00F85u:  // mov r0,#532
                        jit.Regs()[0] = 532;
                        break;
                    case 0xE5923004u:  // ldr r3,[r2,#4] (CS_TYPE)
                        jit.Regs()[3] = host.MemoryRead32(jit.Regs()[2] + 4u);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[CS] type=%08X autom=%08X", jit.Regs()[3],
                                 jit.Regs()[0]);
                        break;
                    case 0xE5923010u: {  // s_datas tree walk key read (SDWALK)
                        const uint32_t node = jit.Regs()[2];
                        // Guest heap nodes are allocated across the complete
                        // 32-bit address space (the live tree node was at
                        // 0xB8C9A690). Restricting this read to the ELF image
                        // silently substituted key 0 and corrupted the
                        // std::map search. Mirror the displaced LDR exactly.
                        const uint32_t key = host.MemoryRead32(node + 0x10u);
                        jit.Regs()[3] = key;
                        static std::atomic<uint32_t> sn{0};
                        const uint32_t k = sn.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 8 || (k % 200) == 0) {
                            LOGE("[SDWALK] #%u node=%08X left=%08X right=%08X key=%08X",
                                 k, node, host.MemoryRead32(node + 8u),
                                 host.MemoryRead32(node + 12u), key);
                        }
                        break;
                    }
                                        case 0xE5860000u: {  // str r0,[r6] (DSCOUNT)
                        host.MemoryWrite32(jit.Regs()[6], jit.Regs()[0]);
                        static std::atomic<uint32_t> dn{0};
                        uint32_t k = dn.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 6 || (k % 500) == 0)
                            LOGE("[DSCOUNT] #%u graph state count=%08X",
                                 k, jit.Regs()[0]);
                        break;
                    }
                    case 0xE5963000u:  // ldr r3,[r6] (LF_MOVIE)
                        jit.Regs()[3] = host.MemoryRead32(jit.Regs()[6]);
                        if (n == 1 || (n % 200) == 0) {
                            uint32_t dp = host.MemoryRead32(
                                jit.Regs()[6] + 24u);
                            LOGE("[LF-MOVIE] def=%08X def+24(player)=%08X",
                                 jit.Regs()[6], dp);
                        }
                        break;
                    case 0xE1A00004u:  // mov r0,r4 (LF_ROOT: after Root creation)
                        jit.Regs()[0] = jit.Regs()[4];
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[LF-ROOT] Root=%08X", jit.Regs()[4]);
                        break;
                                        case 0xE5D73000u: {  // ldrb r3,[r7] (CR_ROOT)
                        jit.Regs()[3] = host.MemoryRead8(jit.Regs()[7]);
                        // CACHECLR: pre-clear def+0xD4 (cached-root slot) so
                        // the caching block's dropRef never dereferences a
                        // Root destroyed by the pass-end cleanup (observed:
                        // second createRoot died before CR2).
                        host.MemoryWrite32(jit.Regs()[4] + 0xD4u, 0);
                        static std::atomic<uint32_t> cn{0};
                        uint32_t k = cn.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 6 || (k % 500) == 0)
                            LOGE("[CR_ROOT] #%u Root=%08X player=%08X",
                                 k, jit.Regs()[5], jit.Regs()[8]);
                        break;
                    }
                    case 0xE5940018u:  // ldr r0,[r4,#0x18] (CR2: after Root caching)
                        jit.Regs()[0] = host.MemoryRead32(jit.Regs()[4] + 0x18u);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[CR2] createRoot past Root caching");
                        break;
                    case 0xE1A07000u:  // mov r7,r0 (CR3: sprite created!)
                        jit.Regs()[7] = jit.Regs()[0];
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[CR3] createSpriteInstance RETURNED sprite=%08X",
                                 jit.Regs()[0]);
                        break;
                    case 0xE1A05002u:  // mov r5,r2 (CHCTOR: Character ctor)
                        jit.Regs()[5] = jit.Regs()[2];
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[CHCTOR] Character ctor parent=%08X",
                                 jit.Regs()[2]);
                        break;
                    case 0xE3A02000u:  // mov r2,#0 (CHCTOR2: inside Character ctor)
                        jit.Regs()[2] = 0;
                        if (m.site == 0x8A3154u && (n <= 8 || (n % 1000) == 0)) {
                            const uint32_t sp = jit.Regs()[13];
                            LOGE("[IFPS-LOCAL] pre-state-ctor #%u sp=%08X slot=%08X local=%08X",
                                 n, sp, sp + 0xCu, host.MemoryRead32(sp + 0xCu));
                        }
                        if (m.site == 0xF6B074u && (n == 1 || (n % 200) == 0))
                            LOGE("[CHCTOR2] inside Character ctor r1(player)=%08X",
                                 jit.Regs()[1]);
                        break;
                    case 0xE3A0100Du:  // mov r1,#0xD (AVM1)
                        jit.Regs()[1] = 0xD;
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[AVM1] flash.display setup reached");
                        break;
                    case 0xE59D3014u:  // ldr r3,[sp,#0x14] (AVM2)
                        jit.Regs()[3] = host.MemoryRead32(jit.Regs()[13] + 0x14u);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[AVM2] Strcpy_s flash.display done");
                        break;
                    case 0xE3A01005u:  // mov r1,#5 (AVM3)
                        jit.Regs()[1] = 5;
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[AVM3] second resize reached");
                        break;
                    case 0xE59F3C60u:  // ldr r3,[pc,#0xc60]
                        jit.Regs()[3] = host.MemoryRead32(0x40000000u + m.site + 8 + 0xC60u);
                        if (n == 1 || (n % 200) == 0) {
                            uint32_t sm = host.MemoryRead32(0x417B5BB0u);
                            LOGE("[S_MGR@M6] = %08X (ctor ran just before)", sm);
                        }
                        // SMFIX: 8 instructions after this probe the pass
                        // executes `str r6,[r3]` with r3 = *(GOT-0xA5B0) =
                        // &SoundManager::s_instance. The pass-end cleanup
                        // recycles+zeroes that GOT slot like the
                        // CustomFileSystem one (see FSFIX above), and the
                        // STR then faults and kills the pass between M6 and
                        // W1. Verify and repair the slot host-side.
                        {
                            uint32_t slot = 0x417944B0u;
                            uint32_t want = 0x417B7818u;
                            uint32_t v = host.MemoryRead32(slot);
                            if (v != want) {
                                host.MemoryWrite32(slot, want);
                                static std::atomic<uint32_t> sn{0};
                                uint32_t k = sn.fetch_add(1, std::memory_order_relaxed) + 1;
                                if (k <= 6 || (k % 500) == 0)
                                    LOGE("[SMFIX] #%u GOT slot %08X: %08X -> %08X",
                                         k, slot, v, want);
                            }
                        }
                        // VD-EARLY: the MenuManager ctor (BL 0x8A3144, the
                        // very next probe region) dereferences *(app+0x35C)
                        // (the glitch IVideoDriver). Application::Init is
                        // shunted, and the old VDRIVER-FIX only ran at
                        // 0x8A3164 -- AFTER the ctor -- so the ctor's read
                        // faulted and killed every pass inside it. Fill the
                        // driver pointer here, a full region earlier.
                        {
                            uint32_t si = host.MemoryRead32(0x417B7D88u);
                            if (si > 0x1000u) {
                                uint32_t dev = host.MemoryRead32(si + 0x344);
                                if (dev > 0x1000u) {
                                    uint32_t vd = host.MemoryRead32(dev + 8);
                                    if (vd > 0x1000u
                                        && host.MemoryRead32(si + 0x35C) != vd) {
                                        host.MemoryWrite32(si + 0x35C, vd);
                                        LOGE("[VD-EARLY] app+0x35C <- %08X",
                                             vd);
                                    }
                                }
                            }
                        }
                        break;
                    case 0xE1A00009u:  // mov r0,r9 (W1, before GlWebTools::Initialize)
                        jit.Regs()[0] = jit.Regs()[9];
                        break;
                    case 0xE58A6AD8u:  // str r6,[r10,#0xAD8] (W2, after MemObf ctor)
                        host.MemoryWrite32(jit.Regs()[10] + 0xAD8u, jit.Regs()[6]);
                        break;
                    case 0xE5836000u:  // str r6,[r3] (W3, after MP ctor)
                        host.MemoryWrite32(jit.Regs()[3], jit.Regs()[6]);
                        break;
                    case 0xE1A01004u:  // mov r1,r4 (W4, after OnlineServices Init)
                        jit.Regs()[1] = jit.Regs()[4];
                        break;
                    case 0xE5930028u:  // ldr r0,[r3,#0x28] (W5, before SaveGame BLX)
                        jit.Regs()[0] = host.MemoryRead32(jit.Regs()[3] + 0x28u);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[W5] s_inst_chain ok, r3=%08X", jit.Regs()[3]);
                        break;
                    case 0xE3A00FD6u:  // mov r0,#0x358 (GameSettings size)
                        jit.Regs()[0] = 0x358;
                        if (n == 1 || (n % 200) == 0) {
                            uint32_t sm = host.MemoryRead32(0x417B5BB0u);
                            LOGE("[S_MGR@A0] = %08X", sm);
                        }
                        break;
                    case 0xE59D300Cu:  // ldr r3,[sp,#0xC] (A3 post-gyro / B1 post-MenuManager)
                    {
                        const uint32_t sp = jit.Regs()[13];
                        const uint32_t slot_address = sp + 0xCu;
                        const uint32_t local = host.MemoryRead32(slot_address);
                        if (m.site == 0x8A2FB4u && (n <= 8 || (n % 1000) == 0))
                            LOGE("[IFPS-LOCAL] post-gyro #%u sp=%08X slot=%08X local=%08X",
                                 n, sp, slot_address, local);
                        jit.Regs()[3] = local;
                        if (m.site == 0x8A3154u && (n == 1 || (n % 200) == 0))
                            LOGE("[B1] SURVIVED MenuManager ctor region");
                        break;
                    }
                    case 0xE5937004u:  // ldr r7,[r3,#4] (A1 achievements count)
                        jit.Regs()[7] = host.MemoryRead32(jit.Regs()[3] + 4u);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[A1] ach count r7=%08X", jit.Regs()[7]);
                        break;
                    case 0xE5D010BDu:  // ldrb r1,[r0,#0xBD] (A2 post-AGC)
                        jit.Regs()[1] = host.MemoryRead8(jit.Regs()[0] + 0xBDu);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[A2] SURVIVED AndroidLoadLocalAchievementsAGC");
                        break;
                    case 0xE59F3A84u:  // ldr r3,[pc,#0xA84] (A4 post-PN)
                        jit.Regs()[3] = host.MemoryRead32(0x40000000u + m.site + 8 + 0xA84u);
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[A4] SURVIVED WasLaunchedByPN");
                        break;
                    case 0xE28D7028u:  // add r7,sp,#0x28 (A5 post-BITrack check)
                        jit.Regs()[7] = jit.Regs()[13] + 0x28u;
                        break;
                    case 0xE1A04000u:  // mov r4,r0 (MenuManager instance)
                        jit.Regs()[4] = jit.Regs()[0];
                        break;
                    case 0xE1A01000u: {  // mov r1,r0 (game_graphml id)
                        const uint32_t sp = jit.Regs()[13];
                        if (n <= 8 || (n % 1000u) == 0)
                            LOGE("[IFPS-LOCAL] post-GetId #%u sp=%08X slot=%08X local=%08X",
                                 n, sp, sp + 0xCu, host.MemoryRead32(sp + 0xCu));
                        if (n == 1 || (n % 200) == 0)
                            LOGE("[GRAPHML] GetId(game_graphml) = %08X", jit.Regs()[0]);
                        if (n == 1) {
                            // GOT slot for s_mgr_ptr must hold &s_mgr.
                            uint32_t got = host.MemoryRead32(0x417986B4u);
                            LOGE("[GRAPHML] GOT s_mgr_ptr=%08X (expect 417B5BB0)", got);
                            uint32_t fm = host.MemoryRead32(0x417B5BB0u);
                            LOGE("[GRAPHML] s_mgr=%08X", fm);
                            if (fm > 0x1000u) {
                                uint32_t hdr = host.MemoryRead32(fm);
                                uint32_t count = host.MemoryRead32(hdr);
                                uint32_t entries = host.MemoryRead32(hdr + 4);
                                uint32_t sort = host.MemoryRead32(fm + 40);
                                LOGE("[GRAPHML] count=%u entries=%08X sort=%08X",
                                     count, entries, sort);
                                for (uint32_t i = 0; i < count && i < 12; ++i) {
                                    uint32_t e = entries + 12 * i;
                                    uint32_t np = host.MemoryRead32(e + 4);
                                    uint32_t pp = host.MemoryRead32(e + 8);
                                    char nb[40] = {0}, pb[40] = {0};
                                    if (host.GetGuestMemoryBase()) {
                                        if (np) {
                                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + np);
                                            for (size_t q = 0; q + 1 < sizeof(nb) && p[q]; ++q) nb[q] = p[q];
                                        }
                                        if (pp) {
                                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + pp);
                                            for (size_t q = 0; q + 1 < sizeof(pb) && p[q]; ++q) pb[q] = p[q];
                                        }
                                    }
                                    LOGE("[GRAPHML] e[%u] '%s' -> '%s'", i, nb, pb);
                                }
                                for (uint32_t i = 0; i < count && i < 12; ++i) {
                                    uint32_t sp = host.MemoryRead32(sort + 8 * i);
                                    uint32_t sid = host.MemoryRead32(sort + 8 * i + 4);
                                    char sb[40] = {0};
                                    if (sp && host.GetGuestMemoryBase()) {
                                        const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + sp);
                                        for (size_t q = 0; q + 1 < sizeof(sb) && p[q]; ++q) sb[q] = p[q];
                                    }
                                    LOGE("[GRAPHML] sort[%u] '%s' id=%u", i, sb, sid);
                                }
                            }
                        }
                        jit.Regs()[1] = jit.Regs()[0];
                        break;
                    }
                    case 0xE59F36A8u: {  // ldr r3,[pc,#0x6a8]
                        jit.Regs()[3] = host.MemoryRead32(0x40000000u + m.site + 8 + 0x6A8u);
                        break;
                    }
                    case 0xE59F3900u: {  // ldr r3,[pc,#0x900] (B2_POSTSA_CTOR)
                        const uint32_t sp = jit.Regs()[13];
                        const uint32_t slot = sp + 0xCu;
                        const uint32_t literal = host.MemoryRead32(
                            0x40000000u + m.site + 8u + 0x900u);
                        if (n <= 8 || (n % 1000u) == 0)
                            LOGE("[IFPS-LOCAL] post-state-ctor #%u sp=%08X slot=%08X local=%08X",
                                 n, sp, slot, host.MemoryRead32(slot));
                        jit.Regs()[3] = literal;
                        break;
                    }
                    }
                });
            uint32_t s = MemoryRead32(tramp) & 0x00FFFFFFu;
            const uint32_t replacement = 0xEF000000u | s;
            MemoryWrite32(site, replacement);
            g_probe_rewrites.push_back(
                {site, replacement});
            LOGI("[IFPS-M] probe %s installed at 0x%08X (svc %u)", m.name, m.site, s);
        }

        // Resolve the final iFPS::Init gate without steering guest control
        // flow: the vtable slot at 0x8A31B8 is ParseArguments(argc, argv),
        // followed by CMP R0,#0 and a branch to exit(-1) on failure. Preserve
        // each displaced instruction exactly and record only its inputs/result.
        {
            constexpr uint32_t kCallOffset = 0x8A31B8u;
            constexpr uint32_t kCallExpected = 0xE12FFF33u; // blx r3
            const uint32_t call_site = 0x40000000u + kCallOffset;
            const uint32_t call_original = MemoryRead32(call_site);
            if (call_original == kCallExpected) {
                const uint32_t call_thunk = m_thunk_manager->RegisterThunk(
                    "diag_ifps_parse_arguments_call",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> calls{0};
                        const uint32_t n = calls.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t argc = jit.Regs()[1];
                        const uint32_t argv = jit.Regs()[2];
                        const uint32_t argv0 = (argv && argc > 0)
                            ? host.MemoryRead32(argv) : 0;
                        const uint32_t argv1 = (argv && argc > 1)
                            ? host.MemoryRead32(argv + 4u) : 0;
                        const uint32_t target = jit.Regs()[3];
                        if (n <= 12 || (n % 1000) == 0)
                            LOGE("[PARSEARGS] call #%u argc=%u argv=%08X argv0=%08X argv1=%08X target=%08X",
                                 n, argc, argv, argv0, argv1, target);

                        jit.Regs()[14] = 0x40000000u + 0x8A31BCu;
                        const uint32_t cpsr = jit.Cpsr();
                        jit.SetCpsr((cpsr & ~0x20u) | ((target & 1u) ? 0x20u : 0u));
                        jit.Regs()[15] = target & ~1u;
                    });
                const uint32_t call_svc = 0xEF000000u |
                    (MemoryRead32(call_thunk) & 0x00FFFFFFu);
                MemoryWrite32(call_site, call_svc);
                g_probe_rewrites.push_back({call_site, call_svc});
                LOGI("[PARSEARGS] exact BLX probe installed at 0x%08X", kCallOffset);
            } else {
                LOGE("[PARSEARGS] BLX probe not installed: expected %08X, found %08X",
                     kCallExpected, call_original);
            }

            constexpr uint32_t kCmpOffset = 0x8A31BCu;
            constexpr uint32_t kCmpExpected = 0xE3500000u; // cmp r0,#0
            const uint32_t cmp_site = 0x40000000u + kCmpOffset;
            const uint32_t cmp_original = MemoryRead32(cmp_site);
            if (cmp_original == kCmpExpected) {
                const uint32_t cmp_thunk = m_thunk_manager->RegisterThunk(
                    "diag_ifps_parse_arguments_result",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                        static std::atomic<uint32_t> results{0};
                        const uint32_t n = results.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t result = jit.Regs()[0];
                        if (n <= 12 || (n % 1000) == 0)
                            LOGE("[PARSEARGS] result #%u r0=%08X", n, result);
                        uint32_t cpsr = jit.Cpsr() & ~0xF0000000u;
                        cpsr |= result & 0x80000000u; // N
                        if (result == 0) cpsr |= 0x40000000u; // Z
                        cpsr |= 0x20000000u; // C: subtraction by zero has no borrow
                        jit.SetCpsr(cpsr);
                    });
                const uint32_t cmp_svc = 0xEF000000u |
                    (MemoryRead32(cmp_thunk) & 0x00FFFFFFu);
                MemoryWrite32(cmp_site, cmp_svc);
                g_probe_rewrites.push_back({cmp_site, cmp_svc});
                LOGI("[PARSEARGS] exact CMP probe installed at 0x%08X", kCmpOffset);
            } else {
                LOGE("[PARSEARGS] CMP probe not installed: expected %08X, found %08X",
                     kCmpExpected, cmp_original);
            }

            constexpr uint32_t kExitOffset = 0x8A394Cu;
            constexpr uint32_t kExitExpected = 0xE3E00000u; // mvn r0,#0
            const uint32_t exit_site = 0x40000000u + kExitOffset;
            const uint32_t exit_original = MemoryRead32(exit_site);
            if (exit_original == kExitExpected) {
                const uint32_t exit_thunk = m_thunk_manager->RegisterThunk(
                    "diag_ifps_parse_arguments_exit",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                        static std::atomic<uint32_t> exits{0};
                        const uint32_t n = exits.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (n <= 12 || (n % 1000) == 0)
                            LOGE("[PARSEARGS] exit(-1) path #%u", n);
                        jit.Regs()[0] = 0xFFFFFFFFu;
                    });
                const uint32_t exit_svc = 0xEF000000u |
                    (MemoryRead32(exit_thunk) & 0x00FFFFFFu);
                MemoryWrite32(exit_site, exit_svc);
                g_probe_rewrites.push_back({exit_site, exit_svc});
                LOGI("[PARSEARGS] exact error-path probe installed at 0x%08X", kExitOffset);
            } else {
                LOGE("[PARSEARGS] exit probe not installed: expected %08X, found %08X",
                     kExitExpected, exit_original);
            }
        }

        // Trace the first resource-driven object load in iFPS::Init without
        // substituting an ID or steering guest control flow. game_graphml is
        // absent from the real Res.array, so StateAutomat::Load receives -1.
        // Bracket that call and the ResStream DVD-name/open boundary to learn
        // whether the missing resource returns cleanly or strands the caller.
        {
            // iFPS::Init loads Application::s_instance through this GOT
            // instruction, then stores the result in [SP+0xC]. Check the
            // instruction preimage before replacing it; the thunk reproduces
            // the non-flag-setting LDR and only adds read-only diagnostics.
            constexpr uint32_t kApplicationInstanceGotAddress = 0x417984A0u;
            constexpr uint32_t kApplicationInstanceCellAddress = 0x417B7D88u;
            constexpr uint32_t kInitGotLoadOffset = 0x8A2EB8u;
            constexpr uint32_t kInitGotLoadExpected = 0xE7953003u; // ldr r3,[r5,r3]
            const uint32_t init_got_load = 0x40000000u + kInitGotLoadOffset;
            const uint32_t init_got_load_actual = MemoryRead32(init_got_load);
            if (init_got_load_actual == kInitGotLoadExpected) {
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "diag_ifps_application_instance_got",
                    [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t r5 = jit.Regs()[5];
                        const uint32_t offset = jit.Regs()[3];
                        const uint32_t address = r5 + offset;
                        const uint32_t value = host.MemoryRead32(address);
                        const uint32_t got = host.MemoryRead32(
                            kApplicationInstanceGotAddress);
                        const uint32_t instance = host.MemoryRead32(
                            kApplicationInstanceCellAddress);
                        const uint32_t n = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        if (n <= 8 || (n % 1000u) == 0)
                            LOGE("[IFPS-GOT] #%u r5=%08X offset=%08X address=%08X "
                                 "value=%08X direct=%08X instance=%08X",
                                 n, r5, offset, address, value, got, instance);
                        jit.Regs()[3] = value;
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(init_got_load, replacement);
                InvalidateGuestCode(init_got_load, sizeof(uint32_t));
                g_probe_rewrites.push_back({init_got_load, replacement});
                LOGI("[IFPS-GOT] strict-preimage probe installed at %08X",
                     kInitGotLoadOffset);
            } else {
                LOGE("[IFPS-GOT] probe not installed: expected %08X, found %08X",
                     kInitGotLoadExpected, init_got_load_actual);
            }

            // Observe the reused caller local immediately after its original
            // STR at 0x8A2EC0, without replacing that store. This exact LDR
            // preimage distinguishes a missing/overwritten stack value from
            // a bad GOT result while preserving the guest instruction.
            constexpr uint32_t kPostGotLoadOffset = 0x8A2EC4u;
            constexpr uint32_t kPostGotLoadExpected = 0xE5933000u; // ldr r3,[r3]
            const uint32_t post_got_load = 0x40000000u + kPostGotLoadOffset;
            const uint32_t post_got_load_actual = MemoryRead32(post_got_load);
            if (post_got_load_actual == kPostGotLoadExpected) {
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "diag_ifps_post_got_local",
                    [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t sp = jit.Regs()[13];
                        const uint32_t slot_address = sp + 0xCu;
                        const uint32_t local = host.MemoryRead32(slot_address);
                        const uint32_t base = jit.Regs()[3];
                        const uint32_t value = host.MemoryRead32(base);
                        const uint32_t n = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        if (n <= 8 || (n % 1000u) == 0)
                            LOGE("[IFPS-LOCAL] post-store #%u sp=%08X slot=%08X "
                                 "local=%08X base=%08X loaded=%08X",
                                 n, sp, slot_address, local, base, value);
                        jit.Regs()[3] = value;
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(post_got_load, replacement);
                InvalidateGuestCode(post_got_load, sizeof(uint32_t));
                g_probe_rewrites.push_back({post_got_load, replacement});
                LOGI("[IFPS-LOCAL] post-store probe installed at %08X",
                     kPostGotLoadOffset);
            } else {
                LOGE("[IFPS-LOCAL] post-store probe not installed: expected %08X, found %08X",
                     kPostGotLoadExpected, post_got_load_actual);
            }

            constexpr uint32_t kLoadEntryOffset = 0x73873Cu;
            constexpr uint32_t kLoadEntryExpected = 0xE52DE004u; // str lr,[sp,#-4]!
            const uint32_t load_entry = 0x40000000u + kLoadEntryOffset;
            const uint32_t load_entry_actual = MemoryRead32(load_entry);
            if (load_entry_actual == kLoadEntryExpected) {
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "diag_stateautomat_load_entry",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> hits{0};
                        const uint32_t n = hits.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t lr = jit.Regs()[14];
                        const uint32_t caller_sp = jit.Regs()[13];
                        const uint32_t caller_local = host.MemoryRead32(caller_sp + 0xCu);
                        const uint32_t got = host.MemoryRead32(
                            kApplicationInstanceGotAddress);
                        const uint32_t sp = caller_sp - 4u;
                        if (n <= 8 || (n % 1000u) == 0)
                            LOGE("[STATELOAD] enter #%u this=%08X id=%08X caller=%08X "
                                 "sp=%08X caller_sp=%08X local=%08X got=%08X",
                                 n, jit.Regs()[0], jit.Regs()[1], lr, sp,
                                 caller_sp, caller_local, got);
                        host.MemoryWrite32(sp, lr);
                        jit.Regs()[13] = sp;
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(load_entry, replacement);
                InvalidateGuestCode(load_entry, sizeof(uint32_t));
                g_probe_rewrites.push_back({load_entry, replacement});
                LOGI("[STATELOAD] exact prologue probe installed at %08X", kLoadEntryOffset);
            } else {
                LOGE("[STATELOAD] entry probe not installed: expected %08X, found %08X",
                     kLoadEntryExpected, load_entry_actual);
            }

            constexpr uint32_t kLoadReturnOffset = 0x8A3188u;
            constexpr uint32_t kLoadReturnExpected = 0xE59D400Cu; // ldr r4,[sp,#0xC]
            const uint32_t load_return = 0x40000000u + kLoadReturnOffset;
            const uint32_t load_return_actual = MemoryRead32(load_return);
            if (load_return_actual == kLoadReturnExpected) {
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "diag_stateautomat_load_return",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> hits{0};
                        const uint32_t n = hits.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t sp = jit.Regs()[13];
                        const uint32_t app = host.MemoryRead32(sp + 0xCu);
                        const uint32_t got = host.MemoryRead32(
                            kApplicationInstanceGotAddress);
                        const uint32_t instance = host.MemoryRead32(
                            kApplicationInstanceCellAddress);
                        const uint32_t device = instance > 0x1000u
                            ? host.MemoryRead32(instance + 0x344u) : 0;
                        const uint32_t scene = device > 0x1000u
                            ? host.MemoryRead32(device + 0x18u) : 0;
                        const uint32_t driver = scene > 0x1000u
                            ? host.MemoryRead32(scene + 0x10u) : 0;
                        const uint32_t vtable = scene > 0x1000u
                            ? host.MemoryRead32(scene) : 0;
                        if (n <= 8 || (n % 1000u) == 0) {
                            LOGE("[STATELOAD] return #%u result=%08X autom=%08X app=%08X "
                                 "sp=%08X got=%08X",
                                 n, jit.Regs()[0], jit.Regs()[4], app, sp, got);
                            LOGE("[STATELOAD] linkage #%u instance=%08X device=%08X scene=%08X "
                                 "driver=%08X vtable=%08X",
                                 n, instance, device, scene, driver, vtable);
                        }
                        jit.Regs()[4] = app;
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(load_return, replacement);
                InvalidateGuestCode(load_return, sizeof(uint32_t));
                g_probe_rewrites.push_back({load_return, replacement});
                LOGI("[STATELOAD] exact return probe installed at %08X", kLoadReturnOffset);
            } else {
                LOGE("[STATELOAD] return probe not installed: expected %08X, found %08X",
                     kLoadReturnExpected, load_return_actual);
            }

            // The global app/device/scene snapshots are valid immediately
            // after StateAutomat::Load, but the next three original loads
            // feed CustomSceneManager::Init. Observe each exact operand/value
            // transition to identify the first bad base register.
            struct InitLinkProbe {
                const char* name;
                uint32_t offset;
                uint32_t expected;
                uint32_t baseReg;
                uint32_t destReg;
                uint32_t fieldOffset;
            };
            const InitLinkProbe linkProbes[] = {
                {"app-cell", 0x8A318Cu, 0xE5943000u, 4, 3, 0x000u}, // ldr r3,[r4]
                {"device",   0x8A3190u, 0xE5933344u, 3, 3, 0x344u}, // ldr r3,[r3,#0x344]
                {"scene",    0x8A3194u, 0xE5930018u, 3, 0, 0x018u}, // ldr r0,[r3,#0x18]
            };
            for (const InitLinkProbe& probe : linkProbes) {
                const uint32_t site = 0x40000000u + probe.offset;
                const uint32_t actual = MemoryRead32(site);
                if (actual != probe.expected) {
                    LOGE("[INITLINK] %s probe not installed: expected %08X, found %08X",
                         probe.name, probe.expected, actual);
                    continue;
                }
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    (std::string("diag_initlink_") + probe.name).c_str(),
                    [probe, hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t n = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        const uint32_t base = jit.Regs()[probe.baseReg];
                        const uint32_t address = base + probe.fieldOffset;
                        const uint32_t value = host.MemoryRead32(address);
                        if (n <= 8 || (n % 1000u) == 0)
                            LOGE("[INITLINK] %s #%u base=%08X address=%08X value=%08X",
                                 probe.name, n, base, address, value);
                        jit.Regs()[probe.destReg] = value;
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
                LOGI("[INITLINK] exact %s load probe installed at %08X",
                     probe.name, probe.offset);
            }

            constexpr uint32_t kDvdReturnOffset = 0x570A60u;
            constexpr uint32_t kDvdReturnExpected = 0xE1A03000u; // mov r3,r0
            const uint32_t dvd_return = 0x40000000u + kDvdReturnOffset;
            const uint32_t dvd_return_actual = MemoryRead32(dvd_return);
            if (dvd_return_actual == kDvdReturnExpected) {
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "diag_resstream_dvd_name",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> hits{0};
                        const uint32_t n = hits.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t id = host.MemoryRead32(jit.Regs()[13] + 4u);
                        if (id == 0xFFFFFFFFu || n <= 8 || (n % 1000u) == 0)
                            LOGE("[RESSTREAM] dvd-name #%u id=%08X resource_path=%08X dvd_name=%08X",
                                 n, id, jit.Regs()[5], jit.Regs()[0]);
                        jit.Regs()[3] = jit.Regs()[0];
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(dvd_return, replacement);
                InvalidateGuestCode(dvd_return, sizeof(uint32_t));
                g_probe_rewrites.push_back({dvd_return, replacement});
                LOGI("[RESSTREAM] exact DVD-name probe installed at %08X", kDvdReturnOffset);
            } else {
                LOGE("[RESSTREAM] DVD-name probe not installed: expected %08X, found %08X",
                     kDvdReturnExpected, dvd_return_actual);
            }

            constexpr uint32_t kOpenReturnOffset = 0x570A74u;
            constexpr uint32_t kOpenReturnExpected = 0xE1A00004u; // mov r0,r4
            const uint32_t open_return = 0x40000000u + kOpenReturnOffset;
            const uint32_t open_return_actual = MemoryRead32(open_return);
            if (open_return_actual == kOpenReturnExpected) {
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "diag_resstream_open_result",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> hits{0};
                        const uint32_t n = hits.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t id = host.MemoryRead32(jit.Regs()[13] + 4u);
                        if (id == 0xFFFFFFFFu || n <= 8 || (n % 1000u) == 0)
                            LOGE("[RESSTREAM] open #%u id=%08X result=%08X path=%08X stream=%08X",
                                 n, id, jit.Regs()[0], jit.Regs()[5], jit.Regs()[4]);
                        jit.Regs()[0] = jit.Regs()[4];
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(open_return, replacement);
                InvalidateGuestCode(open_return, sizeof(uint32_t));
                g_probe_rewrites.push_back({open_return, replacement});
                LOGI("[RESSTREAM] exact FileStream::Open result probe installed at %08X",
                     kOpenReturnOffset);
            } else {
                LOGE("[RESSTREAM] open probe not installed: expected %08X, found %08X",
                     kOpenReturnExpected, open_return_actual);
            }
        }

        // The state-load probes show that Load(-1) returns with an empty
        // state list. Bracket CustomSceneManager::Init and its concrete
        // resource/driver steps; this is the next synchronous call before
        // ParseArguments. Each SVC has a strict ARM preimage and emulates the
        // displaced instruction exactly, including the prologue push.
        {
            // Observe the factory's actual intrusive_ptr argument before it
            // allocates the scene manager. The hidden structure-return slot
            // shifts the method arguments: R2 points at the driver intrusive_ptr.
            {
                constexpr uint32_t site = 0x40000000u + 0x528B90u;
                constexpr uint32_t expected = 0xE92D40F8u; // push {r3-r7,lr}
                const uint32_t actual = MemoryRead32(site);
                if (actual != expected) {
                    LOGE("[SCENEFACTORY] entry probe not installed: expected %08X, found %08X",
                         expected, actual);
                } else {
                    auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                    const uint32_t thunk = m_thunk_manager->RegisterThunk(
                        "diag_scenefactory_entry",
                        [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                            const uint32_t n = hits->fetch_add(
                                1, std::memory_order_relaxed) + 1;
                            const uint32_t driverHolder = jit.Regs()[2];
                            const uint32_t driver = driverHolder
                                ? host.MemoryRead32(driverHolder) : 0;
                            const uint32_t fsHolder = jit.Regs()[3];
                            const uint32_t fs = fsHolder
                                ? host.MemoryRead32(fsHolder) : 0;
                            if (n <= 8 || (n % 500u) == 0)
                                LOGE("[SCENEFACTORY] entry #%u result=%08X factory=%08X "
                                     "driver-holder=%08X driver=%08X fs-holder=%08X fs=%08X "
                                     "caller=%08X",
                                     n, jit.Regs()[0], jit.Regs()[1], driverHolder,
                                     driver, fsHolder, fs, jit.Regs()[14]);

                            // Exact PUSH {R3-R7,LR} emulation.
                            const uint32_t sp = jit.Regs()[13] - 6u * 4u;
                            for (uint32_t i = 0; i < 5; ++i)
                                host.MemoryWrite32(sp + i * 4u, jit.Regs()[3u + i]);
                            host.MemoryWrite32(sp + 5u * 4u, jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    const uint32_t replacement = 0xEF000000u |
                        (MemoryRead32(thunk) & 0x00FFFFFFu);
                    MemoryWrite32(site, replacement);
                    InvalidateGuestCode(site, sizeof(uint32_t));
                    g_probe_rewrites.push_back({site, replacement});
                    LOGI("[SCENEFACTORY] exact createSceneManager entry probe installed");
                }
            }

            // Confirm that the concrete CustomSceneManager constructor receives
            // the same driver that the factory was given.
            {
                constexpr uint32_t site = 0x40000000u + 0x5285E0u;
                constexpr uint32_t expected = 0xE92D4FF0u; // push {r4-r11,lr}
                const uint32_t actual = MemoryRead32(site);
                if (actual != expected) {
                    LOGE("[SCENECTOR] entry probe not installed: expected %08X, found %08X",
                         expected, actual);
                } else {
                    auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                    const uint32_t thunk = m_thunk_manager->RegisterThunk(
                        "diag_scenemanager_ctor_entry",
                        [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                            const uint32_t n = hits->fetch_add(
                                1, std::memory_order_relaxed) + 1;
                            const uint32_t driver = jit.Regs()[1];
                            const uint32_t driverVtable = driver
                                ? host.MemoryRead32(driver) : 0;
                            if (n <= 8 || (n % 500u) == 0)
                                LOGE("[SCENECTOR] entry #%u this=%08X driver=%08X "
                                     "driver-vtable=%08X fs-holder=%08X caller=%08X",
                                     n, jit.Regs()[0], driver, driverVtable,
                                     jit.Regs()[2], jit.Regs()[14]);

                            // Exact PUSH {R4-R11,LR} emulation.
                            const uint32_t sp = jit.Regs()[13] - 9u * 4u;
                            for (uint32_t i = 0; i < 8; ++i)
                                host.MemoryWrite32(sp + i * 4u, jit.Regs()[4u + i]);
                            host.MemoryWrite32(sp + 8u * 4u, jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    const uint32_t replacement = 0xEF000000u |
                        (MemoryRead32(thunk) & 0x00FFFFFFu);
                    MemoryWrite32(site, replacement);
                    InvalidateGuestCode(site, sizeof(uint32_t));
                    g_probe_rewrites.push_back({site, replacement});
                    LOGI("[SCENECTOR] exact CustomSceneManager constructor probe installed");
                }
            }

            // Record the exact scene pointer published through the factory's
            // structure-return slot, preserving its original STR.
            {
                constexpr uint32_t site = 0x40000000u + 0x528BBCu;
                constexpr uint32_t expected = 0xE5854000u; // str r4,[r5]
                const uint32_t actual = MemoryRead32(site);
                if (actual != expected) {
                    LOGE("[SCENEFACTORY] result-store probe not installed: expected %08X, found %08X",
                         expected, actual);
                } else {
                    auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                    const uint32_t thunk = m_thunk_manager->RegisterThunk(
                        "diag_scenefactory_result_store",
                        [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                            const uint32_t n = hits->fetch_add(
                                1, std::memory_order_relaxed) + 1;
                            const uint32_t resultSlot = jit.Regs()[5];
                            const uint32_t scene = jit.Regs()[4];
                            host.MemoryWrite32(resultSlot, scene);
                            if (n <= 8 || (n % 500u) == 0)
                                LOGE("[SCENEFACTORY] result-store #%u slot=%08X scene=%08X",
                                     n, resultSlot, scene);
                        });
                    const uint32_t replacement = 0xEF000000u |
                        (MemoryRead32(thunk) & 0x00FFFFFFu);
                    MemoryWrite32(site, replacement);
                    InvalidateGuestCode(site, sizeof(uint32_t));
                    g_probe_rewrites.push_back({site, replacement});
                    LOGI("[SCENEFACTORY] exact result-store probe installed at 0x528BBC");
                }
            }

            // Trace the later IDevice::createScene publication into the exact
            // device field consumed by iFPS::Init.
            {
                constexpr uint32_t site = 0x40000000u + 0x10CB0B4u;
                constexpr uint32_t expected = 0xE5842018u; // str r2,[r4,#0x18]
                const uint32_t actual = MemoryRead32(site);
                if (actual != expected) {
                    LOGE("[SCENEPUBLISH] probe not installed: expected %08X, found %08X",
                         expected, actual);
                } else {
                    auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                    const uint32_t thunk = m_thunk_manager->RegisterThunk(
                        "diag_scenepublish_store",
                        [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                            const uint32_t n = hits->fetch_add(
                                1, std::memory_order_relaxed) + 1;
                            const uint32_t device = jit.Regs()[4];
                            const uint32_t scene = jit.Regs()[2];
                            const uint32_t oldScene = jit.Regs()[3];
                            host.MemoryWrite32(device + 0x18u, scene);
                            if (n <= 8 || (n % 500u) == 0)
                                LOGE("[SCENEPUBLISH] store #%u device=%08X old=%08X new=%08X",
                                     n, device, oldScene, scene);
                        });
                    const uint32_t replacement = 0xEF000000u |
                        (MemoryRead32(thunk) & 0x00FFFFFFu);
                    MemoryWrite32(site, replacement);
                    InvalidateGuestCode(site, sizeof(uint32_t));
                    g_probe_rewrites.push_back({site, replacement});
                    LOGI("[SCENEPUBLISH] exact device scene-pointer store probe installed");
                }
            }

            struct SceneProbe {
                const char* name;
                uint32_t offset;
                uint32_t expected;
                uint32_t action;
            };
            const SceneProbe probes[] = {
                {"enter",             0x52C02Cu, 0xE92D4030u, 1}, // push {r4,r5,lr}
                {"material-maps-done",0x52C044u, 0xE3A000B4u, 2}, // mov r0,#0xb4
                {"light-manager-done",0x52C05Cu, 0xE1A00004u, 3}, // mov r0,r4
                {"normal-cube-done", 0x52C064u, 0xE1A00004u, 3},
                {"black-texture-done",0x52C06Cu, 0xE1A00004u, 3},
                {"global-params-done",0x52C074u, 0xE5941010u, 4}, // ldr r1,[r4,#0x10]
                {"white-texture-done",0x52C094u, 0xE59D2004u, 5}, // ldr r2,[sp,#4]
                {"caller-return",     0x8A319Cu, 0xE5940000u, 6}, // ldr r0,[r4]
            };
            for (const SceneProbe& probe : probes) {
                const uint32_t site = 0x40000000u + probe.offset;
                const uint32_t actual = MemoryRead32(site);
                if (actual != probe.expected) {
                    LOGE("[SCENEMGR] %s probe not installed: expected %08X, found %08X",
                         probe.name, probe.expected, actual);
                    continue;
                }
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    (std::string("diag_scenemgr_") + probe.name).c_str(),
                    [probe, hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t n = hits->fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t r4 = jit.Regs()[4];
                        if (n <= 8 || (n % 1000u) == 0) {
                            if (probe.action == 1) {
                                const uint32_t scene = jit.Regs()[0];
                                LOGE("[SCENEMGR] %s #%u this=%08X driver=%08X caller=%08X sp=%08X",
                                     probe.name, n, scene,
                                     host.MemoryRead32(scene + 0x10u),
                                     jit.Regs()[14], jit.Regs()[13]);
                                LOGE("[SCENEMGR] object #%u vtable=%08X field04=%08X field08=%08X",
                                     n, host.MemoryRead32(scene),
                                     host.MemoryRead32(scene + 4u),
                                     host.MemoryRead32(scene + 8u));
                                const uint32_t device = jit.Regs()[3];
                                const uint32_t publishedScene = device > 0x1000u
                                    ? host.MemoryRead32(device + 0x18u) : 0;
                                LOGE("[SCENEMGR] linkage #%u device=%08X published-scene=%08X matches=%u",
                                     n, device, publishedScene,
                                     publishedScene == scene ? 1u : 0u);
                            } else if (probe.action == 3) {
                                const uint32_t light = host.MemoryRead32(r4 + 0x35Cu);
                                LOGE("[SCENEMGR] %s #%u this=%08X light=%08X",
                                     probe.name, n, r4, light);
                            } else if (probe.action == 4) {
                                LOGE("[SCENEMGR] %s #%u this=%08X driver=%08X",
                                     probe.name, n, r4, host.MemoryRead32(r4 + 0x10u));
                            } else if (probe.action == 5) {
                                LOGE("[SCENEMGR] %s #%u this=%08X white_texture=%08X",
                                     probe.name, n, r4,
                                     host.MemoryRead32(jit.Regs()[13] + 4u));
                            } else if (probe.action == 6) {
                                LOGE("[SCENEMGR] %s #%u init_result=%08X app=%08X sp=%08X",
                                     probe.name, n, jit.Regs()[0], r4, jit.Regs()[13]);
                            } else {
                                LOGE("[SCENEMGR] %s #%u this=%08X r0=%08X",
                                     probe.name, n, jit.Regs()[0], r4);
                            }
                        }
                        switch (probe.action) {
                        case 1: {
                            const uint32_t sp = jit.Regs()[13] - 12u;
                            host.MemoryWrite32(sp, jit.Regs()[4]);
                            host.MemoryWrite32(sp + 4u, jit.Regs()[5]);
                            host.MemoryWrite32(sp + 8u, jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                            break;
                        }
                        case 2: jit.Regs()[0] = 0xB4u; break;
                        case 3: jit.Regs()[0] = r4; break;
                        case 4: jit.Regs()[1] = host.MemoryRead32(r4 + 0x10u); break;
                        case 5: jit.Regs()[2] = host.MemoryRead32(jit.Regs()[13] + 4u); break;
                        case 6: jit.Regs()[0] = host.MemoryRead32(r4); break;
                        }
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
                LOGI("[SCENEMGR] exact %s probe installed at %08X",
                     probe.name, probe.offset);
            }
        }

        // Observe the real Res.array buffer returned by FileStream::Load in
        // FileManager::FileManager. This replaces only the verified
        // `add r2, sp, #0x60` instruction and emulates it exactly; no guest
        // data or resource IDs are changed by this probe.
        {
            constexpr uint32_t kSiteOffset = 0x567A78u;
            constexpr uint32_t kExpected = 0xE28D2060u; // add r2, sp, #0x60
            const uint32_t site = 0x40000000u + kSiteOffset;
            const uint32_t actual = MemoryRead32(site);
            if (actual != kExpected) {
                LOGE("[RESARRAY-PROBE] not installed: preimage at %08X is %08X, expected %08X",
                     site, actual, kExpected);
            } else {
                uint32_t tramp = m_thunk_manager->RegisterThunk(
                    "probe_real_res_array",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> hits{0};
                        static std::atomic<bool> manifest_scanned{false};
                        const uint32_t hit = hits.fetch_add(1, std::memory_order_relaxed) + 1;
                        const uint32_t sp = jit.Regs()[13];
                        const uint32_t buffer = jit.Regs()[0];
                        const uint32_t size = host.MemoryRead32(sp + 0x2Cu);
                        uint32_t capacity = 0;
                        uint32_t parsed = 0;
                        uint32_t graph_id = UINT32_MAX;
                        uint32_t menu_id = UINT32_MAX;
                        uint32_t mp_modes_id = UINT32_MAX;
                        uint32_t mp_events_id = UINT32_MAX;
                        uint32_t mp_attachments_id = UINT32_MAX;
                        uint32_t multi01_id = UINT32_MAX;
                        uint32_t menu_path_off = 0;
                        uint32_t menu_path_len = 0;
                        uint32_t cursor = 4;
                        uint32_t count = 0;
                        bool valid = buffer != 0 && size >= 4 && size <= (64u << 20) &&
                            static_cast<uint64_t>(buffer) + size <= host.GetGuestMemorySize();
                        if (valid) {
                            capacity = host.GuestAllocSize(buffer);
                            count = host.MemoryRead32(buffer);
                            valid = count <= 200000u && count <= (size - 4u) / 8u;
                        }
                        const bool scan_this_buffer = valid &&
                            !manifest_scanned.exchange(true, std::memory_order_relaxed);
                        const uint8_t* bytes = host.GetGuestMemoryBase();
                        for (uint32_t i = 0; scan_this_buffer && valid && i < count; ++i) {
                            if (cursor > size - 4u) { valid = false; break; }
                            const uint32_t path_len = host.MemoryRead32(buffer + cursor);
                            cursor += 4;
                            if (path_len > size - cursor) { valid = false; break; }
                            const uint32_t path_off = cursor;
                            cursor += path_len;
                            if (cursor > size - 4u) { valid = false; break; }
                            const uint32_t name_len = host.MemoryRead32(buffer + cursor);
                            cursor += 4;
                            if (name_len > size - cursor) { valid = false; break; }
                            const uint32_t name_off = cursor;
                            if (bytes && name_len == 12u &&
                                std::memcmp(bytes + buffer + name_off, "game_graphml", 12) == 0)
                                graph_id = i;
                            if (bytes && name_len == 16u &&
                                std::memcmp(bytes + buffer + name_off, "swf_mainmenu_swf", 16) == 0) {
                                menu_id = i;
                                menu_path_off = path_off;
                                menu_path_len = path_len;
                            }
                            if (bytes && name_len == sizeof("mpgamemodes_array") - 1 &&
                                std::memcmp(bytes + buffer + name_off, "mpgamemodes_array", name_len) == 0)
                                mp_modes_id = i;
                            if (bytes && name_len == sizeof("multiplayerevents_array") - 1 &&
                                std::memcmp(bytes + buffer + name_off, "multiplayerevents_array", name_len) == 0)
                                mp_events_id = i;
                            if (bytes && name_len == sizeof("mpattachments_array") - 1 &&
                                std::memcmp(bytes + buffer + name_off, "mpattachments_array", name_len) == 0)
                                mp_attachments_id = i;
                            if (bytes && name_len == sizeof("multi01_lvl") - 1 &&
                                std::memcmp(bytes + buffer + name_off, "multi01_lvl", name_len) == 0)
                                multi01_id = i;
                            cursor += name_len;
                            ++parsed;
                        }
                        if (hit <= 3 || (hit % 1000u) == 0) {
                            LOGE("[RESARRAY-PROBE] #%u scan=%d buf=%08X size=%u guest_alloc=%u count=%u parsed=%u consumed=%u valid=%d graph_id=%u swf_mainmenu_swf_id=%u",
                                 hit, scan_this_buffer ? 1 : 0, buffer, size, capacity,
                                 count, parsed, cursor,
                                 valid ? 1 : 0, graph_id, menu_id);
                            if (menu_id != UINT32_MAX && bytes && menu_path_len <= 1024u)
                                LOGE("[RESARRAY-PROBE] swf_mainmenu_swf physical path='%.*s'",
                                     static_cast<int>(menu_path_len),
                                     reinterpret_cast<const char*>(bytes + buffer + menu_path_off));
                            LOGI("[RESARRAY-PROBE] MP ids modes=%08X events=%08X"
                                 " attachments=%08X multi01=%08X",
                                 mp_modes_id, mp_events_id, mp_attachments_id,
                                 multi01_id);
                        }
                        jit.Regs()[2] = sp + 0x60u;
                    });
                const uint32_t svc = MemoryRead32(tramp) & 0x00FFFFFFu;
                const uint32_t replacement = 0xEF000000u | svc;
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
                LOGI("[RESARRAY-PROBE] installed at %08X (svc %u)", site, svc);
            }
        }

        // Bring-up: addZipFileArchive entry — the first folder registration
        // call never returns to the iFPS::Init folder loop; log its path.
        {
            uint32_t az_tramp = m_thunk_manager->RegisterThunk("probe_add_zip",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> az{0};
                    uint32_t n = az.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 24 || (n % 2000) == 0) {
                        uint32_t path_g = jit.Regs()[1];
                        char buf[96]; size_t k = 0;
                        if (path_g && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + path_g);
                            while (k + 1 < sizeof(buf) && p[k]) { buf[k] = p[k]; ++k; }
                        }
                        buf[k] = 0;
                        LOGI("[ADD-ZIP] #%u this=%08X path='%s' r2=%08X r3=%08X lr=%08X",
                             n, jit.Regs()[0], buf, jit.Regs()[2], jit.Regs()[3], jit.Regs()[14]);
                    }
                    // emulate `push {r4-r11, lr}`: 9 words
                    uint32_t sp = jit.Regs()[13] - 36;
                    for (int i = 0; i < 8; ++i) host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            uint32_t s9 = MemoryRead32(az_tramp) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x571224u, 0xEF000000u | s9);
            LOGI("[ADD-ZIP] probe installed at 0x571224 (svc %u)", s9);
        }



        // Observe the original profile stream immediately before its first
        // ReadInt. Earlier builds skipped the entire scan and Profile::Read;
        // the vtable/length contract must be measured on the repaired bridge.
        {
            constexpr uint32_t site = 0x4088C4B0u;
            constexpr uint32_t expected = 0xE1A00005u; // mov r0,r5
            if (MemoryRead32(site) != expected) {
                LOGE("[PERF-STREAM] stale preimage %08X", MemoryRead32(site));
                return false;
            }
            const uint32_t thunk = m_thunk_manager->RegisterThunk(
                "perf_stream_boundary",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> count{0};
                    const uint32_t n = count.fetch_add(
                        1, std::memory_order_relaxed) + 1;
                    if (n <= 12 || n % 1000 == 0) {
                        const uint32_t bs = jit.Regs()[4];
                        const uint32_t ds = jit.Regs()[5];
                        const uint32_t sp = jit.Regs()[13];
                        LOGI("[PERF-STREAM] #%u bs=%08X bsvt=%08X"
                             " ds=%08X dsvt=%08X source=%08X size=%u",
                             n, bs, host.MemoryRead32(bs), ds,
                             host.MemoryRead32(ds),
                             host.MemoryRead32(sp + 8u),
                             host.MemoryRead32(sp + 0x14u));
                    }
                    jit.Regs()[0] = jit.Regs()[5];
                });
            const uint32_t replacement = 0xEF000000u |
                (MemoryRead32(thunk) & 0x00FFFFFFu);
            MemoryWrite32(site, replacement);
            InvalidateGuestCode(site, sizeof(uint32_t));
            g_probe_rewrites.push_back({site, replacement});
        }

        // Observe the actual name match and return value without changing
        // either branch. The older whole-profile skips hid a wrong-this
        // instrumentation bug; do not infer selection from a valid stream.
        {
            constexpr uint32_t select_site = 0x4088C550u;
            constexpr uint32_t select_expected = 0xE59D300Cu; // ldr r3,[sp,#12]
            constexpr uint32_t return_site = 0x4088C610u;
            constexpr uint32_t return_expected = 0xE1A00004u; // mov r0,r4
            if (MemoryRead32(select_site) != select_expected ||
                MemoryRead32(return_site) != return_expected) {
                LOGE("[PERF-SELECT] stale preimage select=%08X return=%08X",
                     MemoryRead32(select_site), MemoryRead32(return_site));
                return false;
            }
            const uint32_t selected = m_thunk_manager->RegisterThunk(
                "perf_selected_profile",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    auto guest_name = [&host](uint32_t address, char (&output)[65]) {
                        if (!address || address >= host.GetGuestMemorySize()) return;
                        for (size_t i = 0; i < sizeof(output) - 1; ++i) {
                            const uint64_t current = static_cast<uint64_t>(address) + i;
                            if (current >= host.GetGuestMemorySize()) break;
                            output[i] = static_cast<char>(host.MemoryRead8(static_cast<uint32_t>(current)));
                            if (!output[i]) break;
                        }
                    };
                    static std::atomic<uint32_t> count{0};
                    const uint32_t n = count.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 12) {
                        char chosen[65] = {}, requested[65] = {};
                        guest_name(jit.Regs()[4], chosen);
                        guest_name(jit.Regs()[9], requested);
                        LOGI("[PERF-SELECT] #%u chosen='%s' requested='%s'"
                             " app=%08X", n, chosen, requested,
                             host.MemoryRead32(jit.Regs()[13] + 12u));
                    }
                    jit.Regs()[3] = host.MemoryRead32(jit.Regs()[13] + 12u);
                });
            const uint32_t select_replacement = 0xEF000000u |
                (MemoryRead32(selected) & 0x00FFFFFFu);
            MemoryWrite32(select_site, select_replacement);
            InvalidateGuestCode(select_site, sizeof(uint32_t));
            g_probe_rewrites.push_back({select_site, select_replacement});

            const uint32_t returned = m_thunk_manager->RegisterThunk(
                "perf_profile_result",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> count{0};
                    const uint32_t n = count.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 12) {
                        LOGI("[PERF-RESULT] #%u matched=%u app=%08X",
                             n, jit.Regs()[4],
                             host.MemoryRead32(jit.Regs()[13] + 12u));
                    }
                    jit.Regs()[0] = jit.Regs()[4];
                });
            const uint32_t return_replacement = 0xEF000000u |
                (MemoryRead32(returned) & 0x00FFFFFFu);
            MemoryWrite32(return_site, return_replacement);
            InvalidateGuestCode(return_site, sizeof(uint32_t));
            g_probe_rewrites.push_back({return_site, return_replacement});
        }

        // CZipReader ctor probe: capture `this` per reader instance (native
    // index seeding needs the runtime object address).
    {
        uint32_t ctor_site = 0x40000000u + 0x134F1C8u;
        uint32_t t_probe = m_thunk_manager->RegisterThunk("probe_zipctor",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                host.NoteZipReader(jit.Regs()[0]);
                // PIN the IReadFile: the ctor grabbed it (+1 at [file+4]);
                // add one MORE reference so the file object survives every
                // loader-pass restart (the pass cleanup drops its own ref,
                // which used to destroy the file while later passes still
                // called through it -- the IReadFile use-after-free).
                {
                    uint32_t thisp = jit.Regs()[0];
                    if (thisp && host.GetGuestMemoryBase()) {
                        uint32_t file_ptr = host.MemoryRead32(thisp + 8);
                        if (file_ptr) {
                            uint32_t rc = host.MemoryRead32(file_ptr + 4);
                            host.MemoryWrite32(file_ptr + 4, rc + 1);
                        }
                    }
                }
                // The 2026-09-18 reader pin was REMOVED: combined with the
                // fast-malloc no-op free it kept stale refcounts >= 1 in
                // freed blocks forever, which iFPS::Init's refcount check
                // (0x8A2D20) treats as "held" -> the M2 loop. The free stub
                // now zeroes the block header, so stale counts read 0.
                static std::atomic<uint32_t> zn{0};
                uint32_t k = zn.fetch_add(1, std::memory_order_relaxed) + 1;
                LOGI("[ZIPCTOR] #%u this=%08X", k, jit.Regs()[0]);
                // replicate: push {r4, r5, r6, lr}
                uint32_t sp = jit.Regs()[13] - 16;
                host.MemoryWrite32(sp, jit.Regs()[4]);
                host.MemoryWrite32(sp + 4, jit.Regs()[5]);
                host.MemoryWrite32(sp + 8, jit.Regs()[6]);
                host.MemoryWrite32(sp + 12, jit.Regs()[14]);
                jit.Regs()[13] = sp;
            });
        MemoryWrite32(ctor_site, 0xEF000000u | (MemoryRead32(t_probe) & 0x00FFFFFFu));
        LOGI("[ZIPCTOR] probe installed at 0x134F1C8");
    }

    // NOTE: InstallZipResultProbe (wrapper over CZipReader::init) is REMOVED
    // (2026-09-18). It patched entry/{+4,+8} and then the ZIPINIT probe
    // overwrote its `bx r12` at +4, leaving entry = `ldr r12,[pc]` (literal
    // at +8 = blob) + SVC + BLOB-AS-INSTRUCTION: init ran with its first
    // instruction (CMP R1,#0) replaced and its third instruction
    // (MOVNE R1,R0) turned into a garbage store derived from the blob
    // address -- silent guest-memory corruption on every zip open, which
    // degraded the file system until createReadFile started failing. Restore
    // the two words; the ZIPINIT probe keeps +4 (the original PUSH, which
    // its thunk replicates).
    {
        MemoryWrite32(0x40000000u + 0x134E09Cu, 0xE3510000u);  // cmp r1, #0
        MemoryWrite32(0x40000000u + 0x134E0A4u, 0x11A01000u);  // movne r1, r0
        LOGI("[ZIPFIX] init entry words restored at 0x134E09C/0x134E0A4");
    }

    // CZipReader::init entry probe: log the reader's progress fields so the
    // stuck-incremental-parse hypothesis can be verified (the CD bytes were
    // fully read in the first 2 s, yet the registration loop never accepts).
    // Overwrites the `push {r4-r11, lr}` word; the thunk replicates it.
    {
        uint32_t init_entry = 0x40000000u + 0x134E09Cu + 4;
        uint32_t t_probe = m_thunk_manager->RegisterThunk("probe_zipinit",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                static std::atomic<uint32_t> n{0};
                uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                uint32_t thisp = jit.Regs()[0];
                if (k <= 24 || (k % 20000) == 0) {
                    char f[200]; int o = 0;
                    if (thisp && host.GetGuestMemoryBase()) {
                        for (int w = 0; w < 14 && o < (int)sizeof(f) - 12; ++w) {
                            uint32_t v = host.MemoryRead32(thisp + w * 4);
                            o += snprintf(f + o, sizeof(f) - o, " %02X:%08X", w * 4, v);
                        }
                    }
                    f[o] = 0;
                    LOGE("[ZIPINIT] #%u this=%08X r1=%08X r2=%08X r3=%08X f:%s",
                         k, thisp, jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], f);
                }
                BridgeSafepointCheck();
                                // replicate: push {r4, r5, r6, r7, r8, r9, r10, r11, lr} (9 words)
                uint32_t sp = jit.Regs()[13] - 36;
                for (int i = 0; i < 8; ++i)
                    host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                jit.Regs()[13] = sp;
            });
        MemoryWrite32(init_entry, 0xEF000000u | (MemoryRead32(t_probe) & 0x00FFFFFFu));
        LOGI("[ZIPINIT] probe installed at 0x134E0A0");
    }

    // CLimitReadFile::init (0x133A3DC) entry probe: name the file whose inner
    // IReadFile keeps dying (the per-frame heap-exec storm during load). The
    // entry word is PUSH {R4-R8,LR}; the thunk replicates it.
    {
        uint32_t lrf_entry = 0x40000000u + 0x133A3DCu;
        uint32_t t_lrf = m_thunk_manager->RegisterThunk("probe_lrfinit",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                static std::atomic<uint32_t> n{0};
                uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                if (k <= 40 || (k % 500) == 0) {
                    uint32_t holder = jit.Regs()[1];
                    uint32_t inner = holder ? host.MemoryRead32(holder) : 0;
                    uint32_t vptr = inner ? host.MemoryRead32(inner) : 0;
                    uint32_t slot9 = 0;
                    bool vt_code = false;
                    if (vptr >= 0x40000000u && vptr < 0x44000000u && host.GetGuestMemoryBase()) {
                        vt_code = true;  // inside the module: plausible vtable
                        slot9 = host.MemoryRead32(vptr + 0x24);
                    } else if (vptr) {
                        slot9 = host.MemoryRead32(vptr + 0x24);
                    }
                    char name[80] = "(null)";
                    uint32_t np = jit.Regs()[3];
                    if (np && host.GetGuestMemoryBase()) {
                        for (int i = 0; i < 60; ++i) {
                            char c = static_cast<char>(host.MemoryRead8(np + i));
                            if (!c) break;
                            name[i] = (c >= 32 && c < 127) ? c : '?';
                            name[i + 1] = 0;
                        }
                    }
                    LOGE("[LRFINIT] #%u name=%s inner=%08X vptr=%08X %s slot9=%08X",
                         k, name, inner, vptr, vt_code ? "vt-in-code" : "VT-GARBAGE", slot9);
                }
                // replicate: PUSH {R4-R8,LR} (6 words)
                uint32_t sp = jit.Regs()[13] - 24;
                for (int i = 0; i < 5; ++i)
                    host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                host.MemoryWrite32(sp + 20, jit.Regs()[14]);
                jit.Regs()[13] = sp;
            });
        MemoryWrite32(lrf_entry, 0xEF000000u | (MemoryRead32(t_lrf) & 0x00FFFFFFu));
        LOGI("[LRFINIT] probe installed at 0x133A3DC");
    }

        // iFPS::Init tail stage probes: log which init stage runs and which is
    // skipped when the loader resets the pass (M6 -> M2 regression, 2026-09-18).
    {
        // [MPCTOR] Observe the restored constructor without changing it.
        {
            constexpr uint32_t entry = 0x40668C50u;
            constexpr uint32_t exit = 0x4066911Cu;
            if (MemoryRead32(entry) != 0xE59F3514u ||
                MemoryRead32(exit) != 0xE1A0000Bu) {
                LOGE("[MPCTOR] stale entry/exit %08X/%08X",
                     MemoryRead32(entry), MemoryRead32(exit));
                return false;
            }
            auto install = [this](const char* name, uint32_t site,
                                  ThunkHandler callback) {
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    name, std::move(callback));
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
            };
            install("mp_ctor_entry", entry,
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> count{0};
                    const uint32_t n = count.fetch_add(
                        1, std::memory_order_relaxed) + 1;
                    if (n <= 8 || n % 500 == 0)
                        LOGI("[MPCTOR] entry #%u this=%08X lr=%08X",
                             n, jit.Regs()[0], jit.Regs()[14]);
                    jit.Regs()[3] = host.MemoryRead32(0x4066916Cu);
                });
            install("mp_ctor_exit", exit,
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> count{0};
                    const uint32_t n = count.fetch_add(
                        1, std::memory_order_relaxed) + 1;
                    const uint32_t object = jit.Regs()[11];
                    if (n <= 8 || n % 500 == 0)
                        LOGI("[MPCTOR] exit #%u this=%08X modes=%08X"
                             " experience=%08X lr=%08X",
                             n, object, host.MemoryRead32(object + 0x48u),
                             host.MemoryRead32(object), jit.Regs()[14]);
                    jit.Regs()[0] = object;
                });
        }
        const struct { const char* name; uint32_t entry; } stages[] = {
            {"MultiplayerManagerInit", 0x6696D0u},
            {"OnlineServicesInit",     0x749144u},
            {"LocalStoreMPInit",       0x67C248u},
            {"GameSettingsLoad",       0x89D0F4u},
            {"BITrackingLaunch",       0x8B8DECu},
            {"StateAutomatLoad",       0x73873Cu},
            {"LicenseCheck",           0x89C584u},
        };
        for (auto& st : stages) {
            uint32_t site = 0x40000000u + st.entry;
            uint32_t orig = MemoryRead32(site);
            if (!arm32::IsProbePush(orig)) {
                LOGE("[INITSTAGE] %s: prologue %08X not a push, skipped", st.name, orig);
                continue;
            }
            uint16_t mask = orig & 0xFFFFu;
            std::string sname(st.name);
            bool skip_this = (sname == "OnlineServicesInit");
            uint32_t t = m_thunk_manager->RegisterThunk(
                (std::string("probe_") + st.name).c_str(),
                [sname, mask, skip_this](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> sn{0};
                    uint32_t k = sn.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 10 || (k % 500) == 0)
                        LOGE("[INITSTAGE] %s #%u", sname.c_str(), k);
                    if (skip_this) {
                        // OnlineServicesManager::Init blocks on dead Gameloft
                        // servers. Return 0 immediately.
                        jit.Regs()[0] = 0;
                        jit.Regs()[15] = jit.Regs()[14] & ~1u;
                        return;
                    }
                    // One transfer for each set bit, including LR. The old
                    // loop included R14 and then wrote LR a second time at
                    // old_sp, overwriting the caller's first stack word.
                    jit.Regs()[13] = arm32::PushRegisters(
                        jit.Regs()[13], mask,
                        [&](unsigned reg) { return jit.Regs()[reg]; },
                        [&](uint32_t address, uint32_t value) {
                            host.MemoryWrite32(address, value);
                        });
                });
            MemoryWrite32(site, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[INITSTAGE] %s probe installed at 0x%08X skip=%d", st.name, st.entry, (int)skip_this);
        }
    }

    // io2::CZipReader::init (0x134E09C) is NOT shunted anymore: the
        // guest-side fast malloc removed the per-entry thunk overhead, so the
        // real central-directory parse runs at full JIT speed and builds the
        // real index (the GetId polls then complete and the load advances).

        // MC4 2026-09-17 (runs 26-29): after M6_SND the app FAILS somewhere
        // and unwinds StateAutomat::ExitAllSubAutomats; the cleanup walk
        // spins on a cyclic list and the main core burns there forever.
        // Probe BOTH entries: log who enters Exit and how often, so the
        // next capture names the first failing subsystem.
        {
            uint32_t ex = 0x40000000u + 0x72FAACu;   // StateAutomat::Exit
            uint32_t exa = 0x40000000u + 0x72FB30u;  // ExitAllSubAutomats
            uint32_t t1 = m_thunk_manager->RegisterThunk("probe_statexi",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 12 || (k % 500) == 0)
                        LOGE("[STATEXIT] StateAutomat::Exit #%u this=%08X lr=%08X",
                             k, jit.Regs()[0], jit.Regs()[14]);
                    // push {r4, lr}
                    uint32_t sp = jit.Regs()[13] - 8;
                    host.MemoryWrite32(sp, jit.Regs()[4]);
                    host.MemoryWrite32(sp + 4, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(ex, 0xEF000000u | (MemoryRead32(t1) & 0x00FFFFFFu));

            uint32_t t2 = m_thunk_manager->RegisterThunk("probe_stateexa",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 12 || (k % 500) == 0)
                        LOGE("[STATEXIT] ExitAllSubAutomats #%u this=%08X lr=%08X",
                             k, jit.Regs()[0], jit.Regs()[14]);
                    // push {r3, r4, r5, lr}
                    uint32_t sp = jit.Regs()[13] - 16;
                    host.MemoryWrite32(sp, jit.Regs()[3]);
                    host.MemoryWrite32(sp + 4, jit.Regs()[4]);
                    host.MemoryWrite32(sp + 8, jit.Regs()[5]);
                    host.MemoryWrite32(sp + 12, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(exa, 0xEF000000u | (MemoryRead32(t2) & 0x00FFFFFFu));
            LOGI("[STATEXIT] probes installed at 0x72FAAC and 0x72FB30");
        }

        // createAndOpenFile bounded strcpy (0x570BB0): `bl strcpy` copies a
        // name into char v23[256] with NO bounds check -- a corrupted source
        // string (COW refcount zeroed by the free-stub header wipe) has no
        // early NUL and overflows into the canary at [sp+0x104], killing
        // every pass in the vox data_N registration. Probe replaces the BL;
        // copy is capped at 255 bytes + NUL; lr already points at 0x570BB4.
        {
            uint32_t site = 0x40000000u + 0x570BB0u;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_cof_strcpy",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t dst = jit.Regs()[0], src = jit.Regs()[1];
                    uint32_t len = 0;
                    if (src && host.GetGuestMemoryBase()) {
                        const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + src);
                        while (len < 255 && p[len]) ++len;
                        if (len == 255) {
                            uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 8 || (k % 1000) == 0)
                                LOGE("[STRCPY-CAP] src=%08X no NUL in 255B, capped (lr=%08X)",
                                     src, jit.Regs()[14] & ~1u);
                        }
                        if (host.GetGuestMemoryBase() && dst)
                            memcpy(host.GetGuestMemoryBase() + dst, p, len);
                    }
                    if (dst && host.GetGuestMemoryBase())
                        host.GetGuestMemoryBase()[dst + len] = 0;
                    jit.Regs()[0] = dst;
                });
            MemoryWrite32(site, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[STRCPY-CAP] bounded strcpy installed at 0x570BB0");
        }

        // addZipFileArchive internal sentinels: the vox loop enters this
        // function once per pass and control never comes back to the loop
        // (M2B_LOOPEXIT=0) while the Java step returns. AZ-ENTRY (0x571254,
        // after writeLock) logs the archive-list span; AZ-EXIT (0x5713DC,
        // LABEL_24) fires only when the function reaches its normal exit.
        // AZ-ENTRY fired + AZ-EXIT missing = the function diverges inside;
        // both fired + M2B missing = the return path is broken.
        {
            uint32_t t1 = m_thunk_manager->RegisterThunk("probe_az_entry",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t begin = host.MemoryRead32(jit.Regs()[9] + 0x30);
                    uint32_t end = host.MemoryRead32(jit.Regs()[9] + 0x34);
                    if (k <= 10 || (k % 1000) == 0)
                        LOGE("[AZ-ENTRY] #%u this=%08X list=[%08X..%08X] archives=%u",
                             k, jit.Regs()[9], begin, end,
                             begin && end > begin ? (end - begin) / 4 : 0u);
                    jit.Regs()[5] = host.MemoryRead32(jit.Regs()[9] + 0x30);
                });
            MemoryWrite32(0x40000000u + 0x571254u, 0xEF000000u | (MemoryRead32(t1) & 0x00FFFFFFu));
            uint32_t t2 = m_thunk_manager->RegisterThunk("probe_az_exit",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 10 || (k % 1000) == 0)
                        LOGE("[AZ-EXIT] #%u reader=%08X lr=%08X",
                             k, host.MemoryRead32(jit.Regs()[13] + 0x24),
                             jit.Regs()[14] & ~1u);
                    jit.Regs()[4] = host.MemoryRead32(jit.Regs()[13] + 0x24);
                });
            MemoryWrite32(0x40000000u + 0x5713DCu, 0xEF000000u | (MemoryRead32(t2) & 0x00FFFFFFu));
            LOGI("[AZ] sentinels installed at 0x571254 (entry) and 0x5713DC (exit)");

            // Preserve the archive path before writeLock/callee code can
            // clobber caller-saved registers, then bracket getFileArchive
            // and the nested CZipReader constructor. These probes replicate
            // their displaced instructions exactly and are diagnostic-only.
            uint32_t path_probe = m_thunk_manager->RegisterThunk("probe_az_path",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 12 || (k % 1000) == 0) {
                        char path[96]{};
                        uint32_t guest_path = jit.Regs()[1];
                        if (guest_path && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + guest_path);
                            size_t i = 0;
                            while (i + 1 < sizeof(path) && p[i]) { path[i] = p[i]; ++i; }
                        }
                        LOGE("[AZ-PATH] #%u path='%s'", k, path);
                    }
                    jit.Regs()[9] = jit.Regs()[0];  // MOV R9, R0
                });
            MemoryWrite32(0x40000000u + 0x57122Cu,
                          0xEF000000u | (MemoryRead32(path_probe) & 0x00FFFFFFu));

            uint32_t lookup_return = m_thunk_manager->RegisterThunk("probe_az_lookup_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t found = host.MemoryRead32(jit.Regs()[13] + 0x28);
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[AZ-LOOKUP-RET] #%u path=%08X archive=%08X result=%08X",
                             k, jit.Regs()[11], jit.Regs()[9], found);
                    jit.Regs()[3] = found;  // LDR R3, [SP,#0x34+var_C]
                });
            MemoryWrite32(0x40000000u + 0x571298u,
                          0xEF000000u | (MemoryRead32(lookup_return) & 0x00FFFFFFu));

            uint32_t ctor_return = m_thunk_manager->RegisterThunk("probe_az_ctor_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[AZ-CTOR-RET] #%u path=%08X reader=%08X",
                             k, jit.Regs()[11], jit.Regs()[4]);
                    jit.Regs()[3] = jit.Regs()[4] + 4;  // ADD R3, R4, #4
                });
            MemoryWrite32(0x40000000u + 0x5712D4u,
                          0xEF000000u | (MemoryRead32(ctor_return) & 0x00FFFFFFu));
            LOGI("[AZ] nested path/lookup/constructor probes installed");

            // The data_N packs use glitch::io::CZipReader (ImportHeader,
            // init, C1 at 0x132D834..0x132DD38), not only io2::CZipReader.
            // Mark each boundary so a retry can be separated from a long
            // metadata import or the subsequent in-memory index sort.
            uint32_t zip_init_entry = m_thunk_manager->RegisterThunk("probe_zip_init_entry",
                [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[CZIP-INIT] #%u this=%08X", k, jit.Regs()[0]);
                    jit.Regs()[8] = jit.Regs()[0];  // MOV R8, R0
                });
            MemoryWrite32(0x40000000u + 0x132D9B4u,
                          0xEF000000u | (MemoryRead32(zip_init_entry) & 0x00FFFFFFu));

            uint32_t zip_serializer_return = m_thunk_manager->RegisterThunk("probe_zip_serializer_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t value = host.MemoryRead32(jit.Regs()[13] + 0x1C);
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[CZIP-SERIALIZER-RET] #%u temp=%08X", k, value);
                    jit.Regs()[0] = value;  // LDR R0, [SP,#0x44+var_28]
                });
            MemoryWrite32(0x40000000u + 0x132DA48u,
                          0xEF000000u | (MemoryRead32(zip_serializer_return) & 0x00FFFFFFu));

            uint32_t zip_import_return = m_thunk_manager->RegisterThunk("probe_zip_import_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t end = host.MemoryRead32(jit.Regs()[8] + 0x14);
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[CZIP-IMPORT-RET] #%u this=%08X entry_end=%08X",
                             k, jit.Regs()[8], end);
                    jit.Regs()[3] = end;  // LDR R3, [R8,#0x14]
                });
            MemoryWrite32(0x40000000u + 0x132DA74u,
                          0xEF000000u | (MemoryRead32(zip_import_return) & 0x00FFFFFFu));

            uint32_t zip_import_count = m_thunk_manager->RegisterThunk("probe_zip_import_count",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t begin = host.MemoryRead32(jit.Regs()[8] + 0x10);
                    uint32_t end = jit.Regs()[3];
                    uint32_t count = end >= begin ? (end - begin) / 12u : 0;
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[CZIP-IMPORT-COUNT] #%u entries=%u", k, count);
                    host.MemoryWrite32(jit.Regs()[13] + 8, jit.Regs()[3]);
                });
            MemoryWrite32(0x40000000u + 0x132DA9Cu,
                          0xEF000000u | (MemoryRead32(zip_import_count) & 0x00FFFFFFu));

            uint32_t zip_init_return = m_thunk_manager->RegisterThunk("probe_zip_init_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t begin = host.MemoryRead32(jit.Regs()[8] + 0x10);
                    uint32_t end = host.MemoryRead32(jit.Regs()[8] + 0x14);
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[CZIP-INIT-RET] #%u entries=%u",
                             k, end >= begin ? (end - begin) / 12u : 0u);
                    jit.Regs()[0] = host.MemoryRead32(jit.Regs()[8] + 8);  // LDR R0, [R8,#8]
                });
            MemoryWrite32(0x40000000u + 0x132DB70u,
                          0xEF000000u | (MemoryRead32(zip_init_return) & 0x00FFFFFFu));
            LOGI("[CZIP] ImportHeader/init boundary probes installed");

            uint32_t zip_list_item = m_thunk_manager->RegisterThunk("probe_az_list_item",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t slot = jit.Regs()[5];
                    uint32_t reader = host.MemoryRead32(slot);
                    if (k <= 24 || (k % 1000) == 0)
                        LOGE("[AZ-LIST-ITEM] #%u slot=%08X reader=%08X path=%08X",
                             k, slot, reader, jit.Regs()[11]);
                    jit.Regs()[1] = reader;  // LDR R1, [R5],#4
                    jit.Regs()[5] = slot + 4;
                });
            MemoryWrite32(0x40000000u + 0x571280u,
                          0xEF000000u | (MemoryRead32(zip_list_item) & 0x00FFFFFFu));

            uint32_t zip_readfile_return = m_thunk_manager->RegisterThunk("probe_az_readfile_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t reader = host.MemoryRead32(jit.Regs()[13] + 0x2C);
                    if (k <= 24 || (k % 1000) == 0)
                        LOGE("[AZ-READFILE-RET] #%u path=%08X reader=%08X vtable=%08X",
                             k, jit.Regs()[11], reader,
                             reader ? host.MemoryRead32(reader) : 0);
                    jit.Regs()[3] = reader;  // LDR R3, [SP,#0x34+var_8]
                });
            MemoryWrite32(0x40000000u + 0x571458u,
                          0xEF000000u | (MemoryRead32(zip_readfile_return) & 0x00FFFFFFu));

            uint32_t zip_candidate_return = m_thunk_manager->RegisterThunk("probe_az_candidate_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t candidate = host.MemoryRead32(jit.Regs()[13] + 0x28);
                    if (k <= 24 || (k % 1000) == 0)
                        LOGE("[AZ-CANDIDATE] #%u path=%08X candidate=%08X",
                             k, jit.Regs()[11], candidate);
                    jit.Regs()[3] = candidate;  // LDR R3, [SP,#0x34+var_C]
                });
            MemoryWrite32(0x40000000u + 0x5714F0u,
                          0xEF000000u | (MemoryRead32(zip_candidate_return) & 0x00FFFFFFu));

            uint32_t zip_ctor_alloc = m_thunk_manager->RegisterThunk("probe_az_ctor_alloc",
                [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 24 || (k % 1000) == 0)
                        LOGE("[AZ-CTOR-ALLOC] #%u path=%08X file=%08X",
                             k, jit.Regs()[11], jit.Regs()[3]);
                    jit.Regs()[0] = 0x2C;  // MOV R0, #0x2C
                });
            MemoryWrite32(0x40000000u + 0x5712A4u,
                          0xEF000000u | (MemoryRead32(zip_ctor_alloc) & 0x00FFFFFFu));

            uint32_t vox_loop_step = m_thunk_manager->RegisterThunk("probe_vox_loop_step",
                [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t old_index = jit.Regs()[4];
                    jit.Regs()[4] = old_index + 0x80;
                    if (k <= 24 || (k % 1000) == 0)
                        LOGE("[VOX-LOOP-STEP] #%u index=%08X -> %08X",
                             k, old_index, jit.Regs()[4]);
                });
            MemoryWrite32(0x40000000u + 0x8A2D14u,
                          0xEF000000u | (MemoryRead32(vox_loop_step) & 0x00FFFFFFu));
            LOGI("[AZ] list/readfile/candidate/loop-step probes installed");
        }

        // FileManager::Init sentinels: passes die between M4 and M5 with
        // this call in between. FM-CTOR (0x5679EC, replicates
        // `ldr r3,[pc,#0x3C70]`) and FM-EXIT (0x5686AC, replicates
        // `pop {r4,pc}` and logs the constructed instance) bracket the
        // deadly zone. If FM-CTOR fires but FM-EXIT never does, the ctor
        // body is the killer; the logged r0 also tells us what to write
        // into s_mgr host-side.
        {
            uint32_t tc = m_thunk_manager->RegisterThunk("probe_fm_ctor",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 4 || (k % 1000) == 0)
                        LOGE("[FM-CTOR] #%u entered r3(literal)=%08X", k,
                             jit.Regs()[3]);
                    // REPLICATE the replaced instruction. 0x5679EC:
                    // ldr r3, [pc, #0xC70]  (PC = addr+8 = 0x5679F4;
                    // literal at 0x5679F4 + 0xC70 = 0x568664, which holds
                    // 0x1237064 = GOT(0x179EA60) - 0x5679FC). The first
                    // version read 0x56A664 -- off by 0x2000, garbage --
                    // which gave the ctor a corrupt GOT base: its string/
                    // map code wrote through wrong pointers and inner
                    // indirect calls trashed R4 (empty-string sentinel)
                    // and R10 (=1), cascading into the 0xAD1 interface
                    // pointer and an empty state automaton.
                    jit.Regs()[3] = host.MemoryRead32(0x40000000u + 0x568664u);
                });
            MemoryWrite32(0x40000000u + 0x5679ECu, 0xEF000000u | (MemoryRead32(tc) & 0x00FFFFFFu));

            uint32_t te = m_thunk_manager->RegisterThunk("probe_fm_exit",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 4 || (k % 1000) == 0)
                        LOGE("[FM-EXIT] #%u mgr=%08X vptr=%08X", k, jit.Regs()[0],
                             jit.Regs()[0] ? host.MemoryRead32(jit.Regs()[0]) : 0);
                    // replicate: pop {r4, pc}
                    uint32_t sp = jit.Regs()[13];
                    jit.Regs()[4] = host.MemoryRead32(sp);
                    jit.Regs()[15] = host.MemoryRead32(sp + 4) & ~1u;
                    jit.Regs()[13] = sp + 8;
                });
            MemoryWrite32(0x40000000u + 0x5686ACu, 0xEF000000u | (MemoryRead32(te) & 0x00FFFFFFu));
            LOGI("[FM] sentinels installed at 0x5679EC (ctor) and 0x5686AC (exit)");
        }

        // FileManager ctor capture (0x567A24, `str r3,[r8]`): the ctor stores
        // the constructed vtable base into the instance BEFORE it diverges.
        // One-shot capture of instance+eventual-vtable; the Init shunt below
        // then hands the cached instance to every later pass.
        {
            uint32_t tc2 = m_thunk_manager->RegisterThunk("probe_fm_vtable",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    host.MemoryWrite32(jit.Regs()[8], jit.Regs()[3]);  // replicate: str r3,[r8]
                    static std::atomic<bool> got{false};
                    if (!got.exchange(true)) {
                        g_fm_captured_instance.store(jit.Regs()[8], std::memory_order_relaxed);
                        LOGE("[FM-VTBL] captured instance=%08X vtbl=%08X",
                             jit.Regs()[8], jit.Regs()[3]);
                    }
                });
            MemoryWrite32(0x40000000u + 0x567A24u, 0xEF000000u | (MemoryRead32(tc2) & 0x00FFFFFFu));
            LOGI("[FM-VTBL] capture probe installed at 0x567A24");
        }

        // FileManager::Init SHUNT (0x56868C): pass 1 enters the real Init
        // (its ctor diverges inside; the capture probe above grabbed the
        // instance+eventual-vtable at 0x567A24). Passes >= 2 get the cached
        // instance at once: r0 = instance, s_mgr (0x417B5BB0) = instance,
        // pc = lr -- M5 then fires and the loader advances with a manager
        // whose map fields exist (partially initialized, acceptable for
        // boot: lookups fall back to createAndOpenFileImproved).
        if (false) {  // DISABLED 2026-09-19: the shunted Init left the FM map
            // empty -- GetId('game_graphml') = -1 and the menu graph never
            // loaded. Let the real Init run now that the competing shunts
            // (PerksMP/LOGFILT/GameSettings) removed the lethal work.
            uint32_t tsh = m_thunk_manager->RegisterThunk("probe_fm_init_shunt",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> captured_inst{0};
                    // The capture probe stores via the lambda below; share the
                    // value through the guest: s_mgr slot or the captured reg.
                    // Simplest: read what the capture probe left in a static.
                    uint32_t inst = g_fm_captured_instance.load(std::memory_order_relaxed);
                    if (inst) {
                        host.MemoryWrite32(0x417B5BB0u, inst);
                        jit.Regs()[0] = inst;
                        jit.Regs()[15] = jit.Regs()[14] & ~1u;
                        static std::atomic<uint32_t> sn{0};
                        uint32_t k = sn.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 4 || (k % 1000) == 0)
                            LOGE("[FM-SHUNT] #%u returning cached mgr=%08X", k, inst);
                        return;
                    }
                    // No capture yet: replicate `push {r4, lr}` and let the
                    // real Init run (its ctor fires the capture probe).
                    uint32_t sp = jit.Regs()[13] - 8;
                    host.MemoryWrite32(sp, jit.Regs()[4]);
                    host.MemoryWrite32(sp + 4, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(0x40000000u + 0x56868Cu, 0xEF000000u | (MemoryRead32(tsh) & 0x00FFFFFFu));
            LOGI("[FM-SHUNT] probe installed at 0x56868C");
        }

        // File-open chain sentinels: every silent pass death lives in this
        // chain. IMPROVED (0x56B7CC, push {r4-r9,lr} = 7 words) and
        // CREATE-READ (0x1339FB8, push {r4-r6,lr} = 4 words) entries.
        {
            uint32_t ti = m_thunk_manager->RegisterThunk("probe_improved",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 10 || (k % 500) == 0) {
                        char buf[72]; size_t q = 0;
                        uint32_t pg = jit.Regs()[1];
                        if (pg && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + pg);
                            while (q + 1 < sizeof(buf) && p[q]) { buf[q] = p[q]; ++q; }
                        }
                        buf[q] = 0;
                        LOGE("[IMPROVED] #%u path='%s'", k, buf);
                    }
                    // replicate: push {r4-r9, lr} (7 words)
                    uint32_t sp = jit.Regs()[13] - 28;
                    for (int i = 0; i < 6; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 24, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(0x40000000u + 0x56B7CCu, 0xEF000000u | (MemoryRead32(ti) & 0x00FFFFFFu));

            uint32_t tc3 = m_thunk_manager->RegisterThunk("probe_createread",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 10 || (k % 2000) == 0) {
                        char buf[72]; size_t q = 0;
                        uint32_t pg = jit.Regs()[1];
                        if (pg && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + pg);
                            while (q + 1 < sizeof(buf) && p[q]) { buf[q] = p[q]; ++q; }
                        }
                        buf[q] = 0;
                        LOGE("[CREATEREAD] #%u name='%s'", k, buf);
                    }
                    // replicate: push {r4-r6, lr} (4 words)
                    uint32_t sp = jit.Regs()[13] - 16;
                    for (int i = 0; i < 3; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 12, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(0x40000000u + 0x1339FB8u, 0xEF000000u | (MemoryRead32(tc3) & 0x00FFFFFFu));
            // createReadFile main epilogue (0x133A038, pop {r4-r6,pc}):
            // fires only when the function completes. Entry fires + exit
            // missing => the divergence is inside the construction.
            {
                uint32_t te2 = m_thunk_manager->RegisterThunk("probe_cr_exit",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> n{0};
                        uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 6 || (k % 2000) == 0)
                            LOGE("[CR-EXIT] #%u r0(result)=%08X", k, jit.Regs()[0]);
                        uint32_t sp = jit.Regs()[13];
                        jit.Regs()[4] = host.MemoryRead32(sp);
                        jit.Regs()[5] = host.MemoryRead32(sp + 4);
                        jit.Regs()[6] = host.MemoryRead32(sp + 8);
                        jit.Regs()[15] = host.MemoryRead32(sp + 12) & ~1u;
                        jit.Regs()[13] = sp + 16;
                    });
                MemoryWrite32(0x40000000u + 0x133A038u, 0xEF000000u | (MemoryRead32(te2) & 0x00FFFFFFu));
                LOGI("[CR-EXIT] probe installed at 0x133A038");
            }
            LOGI("[FILECHAIN] sentinels installed at 0x56B7CC (improved) and 0x1339FB8 (createReadFile)");
        }

        // [GSETBOUND] Keep the original GameSettings constructor and loader.
        // The former shunts returned from both immediately, leaving the
        // settings vtable unconstructed and suppressing the original
        // LoadLanguage route. Observe their entries with exact prologue
        // emulation while testing their restored behavior.
        {
            struct Site { const char* name; uint32_t address; uint32_t expected; };
            const Site sites[] = {
                {"ctor", 0x4089D108u, 0xE92D40F8u},
                {"load", 0x408A0B58u, 0xE92D4FF0u},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected || !arm32::IsProbePush(original)) {
                    LOGE("[GSETBOUND] stale %s expected=%08X got=%08X",
                         site.name, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name, [site, count](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        if (n <= 8 || n % 500 == 0)
                            LOGI("[GSETBOUND] %s #%u this=%08X lr=%08X",
                                 site.name, n, jit.Regs()[0], jit.Regs()[14]);
                        jit.Regs()[13] = arm32::PushRegisters(
                            jit.Regs()[13],
                            static_cast<uint16_t>(site.expected & 0xFFFFu),
                            [&jit](unsigned reg) { return jit.Regs()[reg]; },
                            [&host](uint32_t at, uint32_t value) {
                                host.MemoryWrite32(at, value);
                            });
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

        // [STAGE-1] diagnostics (2026-09-19): does the stage-1 handler
        // (0x88814C, BL InitAndroid then counter++ at 0x888164) complete?
        // M6_SND fires ~1000x/9s yet the counter stays 1 -- count entries
        // vs increments, and perform the counter store host-side so the
        // JIT fast path cannot race it.
        {
            uint32_t ent = 0x40000000u + 0x88814Cu;
            uint32_t t1 = m_thunk_manager->RegisterThunk("probe_stage1_ent",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 10 || (k % 1000) == 0) {
                        uint32_t cnt = host.MemoryRead32(0x417B7D3Cu);
                        LOGE("[STAGE-1] enter #%u counter=%u", k, cnt);
                    }
                    // replicate: MOV R0, R5 (replaced instruction) is NOT
                    // needed -- the SVC sits on the BL InitAndroid site
                    // 0x888150? No: entry 0x88814C = `MOV R0, R5`.
                    // Emulate it: r0 = r5, then fall through to the BL.
                    jit.Regs()[0] = jit.Regs()[5];
                });
            const uint32_t ent_svc = 0xEF000000u | (MemoryRead32(t1) & 0x00FFFFFFu);
            MemoryWrite32(ent, ent_svc);
            g_probe_rewrites.push_back({ent, ent_svc});
            LOGI("[STAGE-1] entry probe installed at 0x88814C");

            uint32_t inc = 0x40000000u + 0x888164u;
            uint32_t t2 = m_thunk_manager->RegisterThunk("probe_stage1_inc",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    // The replaced instruction is STR R3, [R4,#0x18C] where
                    // r3 = old counter + 1. Perform the store host-side.
                    uint32_t newv = jit.Regs()[3];
                    host.MemoryWrite32(0x417B7D3Cu, newv);
                    if (k <= 10 || (k % 1000) == 0) {
                        uint32_t now = host.MemoryRead32(0x417B7D3Cu);
                        LOGE("[STAGE-1] increment #%u -> %u (mem=%u)", k, newv, now);
                    }
                });
            const uint32_t inc_svc = 0xEF000000u | (MemoryRead32(t2) & 0x00FFFFFFu);
            MemoryWrite32(inc, inc_svc);
            g_probe_rewrites.push_back({inc, inc_svc});
            LOGI("[STAGE-1] increment probe installed at 0x888164");
        }

        // Bracket the second Android initialization stage. Static IDA analysis
        // shows InitAndroid(1) dispatches through Application's vtable at
        // 0x7B0A98; the following guest instruction at 0x7B0A9C is its first
        // post-call instruction. Re-emulate BLX and the displaced LDR exactly
        // so a missing return can be distinguished from a bad stage counter.
        {
            uint32_t call = 0x40000000u + 0x7B0A98u;
            uint32_t enter = m_thunk_manager->RegisterThunk("diag_initandroid_virtual_enter",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 12 || (k % 1000) == 0) {
                        uint32_t app = jit.Regs()[0];
                        uint32_t argp = jit.Regs()[1];
                        uint32_t device = argp ? host.MemoryRead32(argp) : 0;
                        LOGE("[INITANDROID] virtual #%u app=%08X mode=1 vptr=%08X target=%08X device=%08X",
                             k, app, host.MemoryRead32(app), jit.Regs()[2], device);
                    }
                    jit.Regs()[14] = 0x40000000u + 0x7B0A9Cu;
                    jit.Regs()[15] = jit.Regs()[2] & ~1u;
                });
            const uint32_t call_svc = 0xEF000000u | (MemoryRead32(enter) & 0x00FFFFFFu);
            MemoryWrite32(call, call_svc);
            g_probe_rewrites.push_back({call, call_svc});

            uint32_t after = 0x40000000u + 0x7B0A9Cu;
            uint32_t returned = m_thunk_manager->RegisterThunk("diag_initandroid_virtual_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t device = host.MemoryRead32(jit.Regs()[13] + 4u);
                    if (k <= 12 || (k % 1000) == 0)
                        LOGE("[INITANDROID] virtual returned #%u app=%08X device=%08X result=%08X",
                             k, jit.Regs()[5], device, jit.Regs()[0]);
                    jit.Regs()[4] = device;  // LDR R4, [SP,#8+var_4]
                });
            const uint32_t return_svc = 0xEF000000u | (MemoryRead32(returned) & 0x00FFFFFFu);
            MemoryWrite32(after, return_svc);
            g_probe_rewrites.push_back({after, return_svc});
            LOGI("[INITANDROID] exact BLX/return probes installed at 0x7B0A98/0x7B0A9C");
        }

        // iFPS::Init has a single ordinary return at 0x8A3288. Replace its
        // POP {R4-R11,PC} with an exact register/stack emulation so the call
        // boundary can be distinguished from an earlier guest exit/unwind.
        {
            const uint32_t ret = 0x40000000u + 0x8A3288u;
            const uint32_t original = MemoryRead32(ret);
            uint32_t probe = m_thunk_manager->RegisterThunk("probe_ifps_return",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    const uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    const uint32_t sp = jit.Regs()[13];
                    for (uint32_t i = 0; i < 8; ++i)
                        jit.Regs()[4 + i] = host.MemoryRead32(sp + i * 4);
                    const uint32_t return_pc = host.MemoryRead32(sp + 32);
                    if (k <= 16 || (k % 1000) == 0)
                        LOGE("[IFPS-RETURN] #%u result=%08X saved_pc=%08X sp=%08X",
                             k, jit.Regs()[0], return_pc, sp);
                    jit.Regs()[13] = sp + 36;
                    uint32_t cpsr = jit.Cpsr();
                    cpsr = (cpsr & ~0x20u) | ((return_pc & 1u) ? 0x20u : 0u);
                    jit.SetCpsr(cpsr);
                    jit.Regs()[15] = return_pc & ~1u;
                });
            if (original == 0xE8BD8FF0u) {
                const uint32_t return_svc = 0xEF000000u | (MemoryRead32(probe) & 0x00FFFFFFu);
                MemoryWrite32(ret, return_svc);
                g_probe_rewrites.push_back({ret, return_svc});
                LOGI("[IFPS-RETURN] exact POP probe installed at 0x8A3288");
            } else {
                LOGE("[IFPS-RETURN] not installed: expected POP {R4-R11,PC}, found %08X", original);
            }
        }

        // [POSTM6] checkpoint bracket: every stage-1 pass enters iFPS::Init
        // and reaches M6_SND (0x8A2DDC) but never reaches A0_SAVEGAME
        // (0x8A2EDC) and never returns to Update (no counter increment).
        // Log the checkpoints between them to find the silent unwind. Each
        // probe re-executes the instruction it replaces (BL emulation via
        // lr/pc, MOV emulation via r0).
        {
            struct Ck { const char* name; uint32_t addr; int kind;
                        uint32_t target; };
            // kind: 0 = MOV r0,#imm ; 1 = BL target ; 2 = BLX r3
            const Ck cks[] = {
                {"gw_isinit",    0x8A2DF4u, 1, 0xCE4D64u},
                {"gw_initialize",0x8A2E08u, 1, 0xCF99CCu},
                {"memobf_alloc", 0x8A2E6Cu, 0, 0x0000001Cu},
                {"mp_ctor",      0x8A2E80u, 0, 0x00000054u},
                {"mp_initialize",0x8A2EA0u, 1, 0x6696D0u},
                {"savegame_call",0x8A2ED8u, 3, 0x00000000u},
            };
            for (const Ck& ck : cks) {
                std::string nm = std::string("probe_postm6_") + ck.name;
                uint32_t guest_next = 0x40000000u + ck.addr + 4u;
                uint32_t target = ck.target;
                int kind = ck.kind;
                uint32_t t = m_thunk_manager->RegisterThunk(nm.c_str(),
                    [nm, guest_next, target, kind](Dynarmic::A32::Jit& jit,
                                                   DynarmicHost& host) {
                        static std::atomic<uint32_t> n{0};
                        uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 10 || (k % 500) == 0)
                            LOGE("[POSTM6] %s #%u", nm.c_str(), k);
                        if (kind == 0) {
                            jit.Regs()[0] = target;
                            return;  // fall through to next instruction
                        }
                        if (kind == 3) {
                            // SaveGame.bin lookup through the device fs:
                            // the real callee throws an exception every
                            // pass in our environment (no savegame exists
                            // on a fresh install anyway). Return 0 (not
                            // found) instead of entering it.
                            jit.Regs()[0] = 0;
                            jit.Regs()[15] = guest_next;
                            return;
                        }
                        jit.Regs()[14] = guest_next;
                        if (kind == 1)
                            jit.Regs()[15] = 0x40000000u + target;
                        else
                            jit.Regs()[15] = jit.Regs()[3] & ~1u;
                    });
                MemoryWrite32(0x40000000u + ck.addr,
                              0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
                LOGI("[POSTM6] checkpoint %s at 0x%08X", ck.name, ck.addr);
            }
        }

        // Disabled state-machine detours. The graph supplied by the host is
        // now a single native FlashMenu state, so the original guest
        // StateAutomat code must own loading, transitions, and menu updates.
#if 0
        // [REQTRANS] StateAutomat::RequestTransitionTo (0x72FC18) probe +
        // full host-side emulation (no prologue; BX LR return). Logs every
        // automaton transition request with its target state index.
        {
            uint32_t entry = 0x40000000u + 0x72FC18u;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_reqtrans",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t autom = jit.Regs()[0];
                    int32_t target = (int32_t)jit.Regs()[1];
                    if (k <= 30 || (k % 500) == 0)
                        LOGE("[REQTRANS] #%u autom=%08X target=%d", k, autom, target);
                    if (target != -1 && autom > 0x1000u) {
                        uint32_t stateset = host.MemoryRead32(autom + 0x34);
                        uint32_t states = host.MemoryRead32(stateset + 4);
                        uint32_t st = host.MemoryRead32(states + 4 * target);
                        host.MemoryWrite32(autom + 0x48, st);
                    } else {
                        host.MemoryWrite32(autom + 0x48, 0);
                    }
                    host.MemoryWrite8(autom + 0x44, 1);
                    // The state switch hands control toward MenuManager::
                    // Update, which stale-reads Gameplay::s_instance (UAF
                    // into reused gameswf data) and virtual-calls through
                    // it -> trap loop. Null it NOW, before the first menu
                    // update runs; a real Gameplay state re-sets the
                    // singleton itself when it engages.
                    host.MemoryWrite32(0x417B5E10u, 0);
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[REQTRANS] probe installed at 0x72FC18");
        }

        // [SA-TICK] liveness probes: iFPS::_Update (0x8A3AF0),
        // StateAutomat::Update (0x72FC3C), StateAutomat::Enter (0x72FEB4).
        // All three prologues replicated on fall-through.
        {
            struct P { const char* name; uint32_t addr; uint32_t startReg; uint32_t regCount; };
            // Prologue layouts (PUSH lists):
            // _Update  push {r3-r9,lr}  -> start r3, 7 regs + lr
            // Update   push {r4-r11,lr} -> start r4, 8 regs + lr
            // Enter    push {lr}        -> 0 regs + lr
            const P ps[] = {
                {"ifps_update", 0x8A3AF0u, 3, 7},
                {"sa_update",   0x72FC3Cu, 4, 8},
                {"sa_enter",    0x72FEB4u, 0, 0},
            };
            for (const P& pp : ps) {
                std::string nm = std::string("probe_sa_") + pp.name;
                uint32_t startReg = pp.startReg;
                uint32_t regCount = pp.regCount;
                uint32_t words = regCount + 1;
                uint32_t t = m_thunk_manager->RegisterThunk(nm.c_str(),
                    [nm, startReg, regCount, words](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        if (nm.find("sa_enter") != std::string::npos &&
                            host.GetGuestMemoryBase()) {
                            static std::atomic<uint32_t> en{0};
                            uint32_t ek = en.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (ek <= 10 || (ek % 2000) == 0) {
                                uint32_t autom = jit.Regs()[0];
                                uint32_t ss = autom ? host.MemoryRead32(autom + 52) : 0;
                                uint32_t arr = ss ? host.MemoryRead32(ss + 4) : 0;
                                uint32_t s0 = arr ? host.MemoryRead32(arr) : 0;
                                uint32_t cur = autom ? host.MemoryRead32(autom + 72) : 0;
                                LOGE("[ENTER] #%u autom=%08X sset=%08X arr=%08X state0=%08X cur=%08X",
                                     ek, autom, ss, arr, s0, cur);
                                // [FORCE-MENU] one-shot: the logo state
                                // (type 9) waits for a video playback flag
                                // that never rises here (no logo video).
                                // Schedule the transition to state 1 (menu)
                                // exactly like RequestTransitionTo:
                                // autom+0x48 = states[1], autom+0x44 = 1.
                                static std::atomic<bool> forced{false};
                                if (!forced.exchange(true) && arr) {
                                    uint32_t st1 = host.MemoryRead32(arr + 4);
                                    if (st1) {
                                        host.MemoryWrite32(autom + 0x48, st1);
                                        host.MemoryWrite8(autom + 0x44, 1);
                                        LOGE("[FORCE-MENU] pending <- states[1] = %08X", st1);
                                    }
                                }
                            }
                        }
                        static std::atomic<uint32_t> n{0};
                        uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 6 || (k % 2000) == 0) {
                            if (nm.find("ifps_update") != std::string::npos)
                                LOGE("[SA-TICK] %s #%u this=%08X lr=%08X",
                                     nm.c_str(), k, jit.Regs()[0], jit.Regs()[14]);
                            else
                                LOGE("[SA-TICK] %s #%u", nm.c_str(), k);
                        }
                        // one-shot deep dump on the iFPS::_Update probe:
                        // automaton = iFPS+0xAD4; {current=+14*4,
                        // stateset=+13*4}; stateset = {count, states[]}
                        static std::atomic<bool> dumped{false};
                        uint32_t s_inst = host.MemoryRead32(0x417B7D88u);
                        uint32_t autom_probe = s_inst ? host.MemoryRead32(s_inst + 0xAD4) : 0;
                        // [FORCE-MENU] retry each frame until states[1]
                        // exists, then schedule the logo->menu transition
                        // exactly like RequestTransitionTo (autom+0x48 =
                        // states[1], autom+0x44 = 1). The logo state (type
                        // 9) waits for a video flag that never rises here.
                        // [FORCE-MENU] direct commit: the pending write gets
                        // clobbered by Enter re-running every frame while
                        // current==0; commit CURRENT directly instead
                        // (current=+56 = states[1], entered flag +68 = 0),
                        // on the s_inst automaton AND any automaton seen at
                        // ENTER time (two automatons exist per boot).
                        if (nm.find("ifps_update") != std::string::npos &&
                            host.GetGuestMemoryBase()) {
                            static std::atomic<bool> forced{false};
                            uint32_t s_inst2 = host.MemoryRead32(0x417B7D88u);
                            uint32_t autom2 = s_inst2 ? host.MemoryRead32(s_inst2 + 0xAD4) : 0;
                            if (!forced.exchange(true) && autom2 > 0x1000u) {
                                g_force_autom_alt.store(autom2,
                                    std::memory_order_relaxed);
                            } else if (autom2 > 0x1000u) {
                                uint32_t ss2 = host.MemoryRead32(autom2 + 52);
                                uint32_t arr2 = ss2 ? host.MemoryRead32(ss2 + 4) : 0;
                                uint32_t st1 = arr2 ? host.MemoryRead32(arr2 + 4) : 0;
                                if (st1) {
                                    // [FORCE-MENU-DISABLED rev 99] The
                                    // per-frame CURRENT commit was needed
                                    // while the automaton was wedged; now
                                    // that the frame loop, AS3 and the menu
                                    // bridge are alive it PREVENTS the
                                    // automaton from completing the
                                    // loading->menu transition. Disabled:
                                    // let the automaton walk its own states.
                                    if (false) {
                                        for (uint32_t target : {autom2,
                                                g_force_autom_alt.load(
                                                    std::memory_order_relaxed)}) {
                                            if (target > 0x1000u) {
                                                host.MemoryWrite32(target + 56, st1);
                                                host.MemoryWrite8(target + 68, 0);
                                            }
                                        }
                                    }
                                    // per-frame commit; log 1-in-600 so the
                                    // probe stays legible in logcat
                                    static std::atomic<uint32_t> fm_logs{0};
                                    if ((fm_logs.fetch_add(
                                             1, std::memory_order_relaxed) %
                                         600) == 0)
                                        LOGE("[FORCE-MENU] CURRENT <- states[1] = %08X "
                                             "(autom %08X / alt %08X)", st1, autom2,
                                             g_force_autom_alt.load(
                                                 std::memory_order_relaxed));
                                    // [MENU-ACTIVATE] MenuManager::Update
                                    // only drives RenderFX::update (the AS3
                                    // enterFrame tick) for menu entries whose
                                    // +40 flag is set; with +40==0 updates run
                                    // only during the +44 countdown and then
                                    // stop forever -- the movie freezes on the
                                    // preloader frame with no AS3 events.
                                    // Force the (single) menu entry active.
                                    if (host.GetGuestMemoryBase()) {
                                        uint32_t mm72 =
                                            host.MemoryRead32(0x417B5E8Cu);
                                        uint32_t nd72 =
                                            mm72 ? host.MemoryRead32(mm72 + 16)
                                                 : 0;
                                        uint32_t mi72 =
                                            nd72 ? host.MemoryRead32(nd72 + 20)
                                                 : 0;
                                        if (mi72 > 0x1000u) {
                                            uint32_t rf72 =
                                                host.MemoryRead32(mi72 + 12);
                                            if (rf72 &&
                                                !host.MemoryRead8(mi72 + 40)) {
                                                host.MemoryWrite8(mi72 + 40, 1);
                                                host.MemoryWrite32(mi72 + 44, 0);
                                                static std::atomic<uint32_t> an{0};
                                                if (an.fetch_add(
                                                        1,
                                                        std::memory_order_relaxed) <
                                                    4)
                                                    LOGE("[MENU-ACTIVATE] "
                                                        "mi=%08X rf=%08X -> "
                                                        "active",
                                                        mi72, rf72);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        static std::atomic<bool> sdump_flag{false};
                        if (nm.find("ifps_update") != std::string::npos &&
                            k == 50 && host.GetGuestMemoryBase() && !sdump_flag.exchange(true)) {
                            LOGE("[SA-DUMP] raw: s_inst=%08X me=%08X me+AD4=%08X s_inst+AD4=%08X",
                                 s_inst, jit.Regs()[0],
                                 host.MemoryRead32(jit.Regs()[0] + 0xAD4),
                                 host.MemoryRead32(s_inst + 0xAD4));
                        }
                        if (nm.find("sa_update") != std::string::npos &&
                            (k % 20000) == 0 && host.GetGuestMemoryBase()) {
                            // menu-manager automaton progress: this==autom?
                            uint32_t s_inst2 = host.MemoryRead32(0x417B7D88u);
                            uint32_t autom = s_inst2 ? host.MemoryRead32(s_inst2 + 0xAD4) : 0;
                            uint32_t cur = autom ? host.MemoryRead32(autom + 72) : 0;
                            uint32_t curtype = 0xDEAD;
                            if (cur) {
                                uint32_t cdata = host.MemoryRead32(cur + 4);
                                curtype = cdata ? host.MemoryRead32(cdata + 4) : 0xDEAD;
                            }
                            uint32_t ls = host.MemoryRead32(0x417B5E0Cu);
                            LOGE("[LSVT] tick=%u this=%08X autom=%08X match=%d cur=%08X ctype=%08X LS=%08X b14=%02X",
                                 k, jit.Regs()[0], autom,
                                 (autom && jit.Regs()[0] == autom) ? 1 : 0,
                                 cur, curtype, ls,
                                 ls ? host.MemoryRead8(ls + 14) : 0);
                        }
                        if (nm.find("ifps_update") != std::string::npos &&
                            autom_probe != 0 && !dumped.exchange(true) &&
                            host.GetGuestMemoryBase()) {
                            uint32_t me = jit.Regs()[0];
                            uint32_t autom = autom_probe;
                            uint32_t cur = autom ? host.MemoryRead32(autom + 72) : 0;
                            uint32_t sset = autom ? host.MemoryRead32(autom + 52) : 0;
                            uint32_t scnt = sset ? host.MemoryRead32(sset) : 0;
                            uint32_t sarr = sset ? host.MemoryRead32(sset + 4) : 0;
                            uint32_t s0 = sarr ? host.MemoryRead32(sarr) : 0;
                            uint32_t s0data = s0 ? host.MemoryRead32(s0 + 4) : 0;
                            uint32_t s0type = s0data ? host.MemoryRead32(s0data + 4) : 0xDEAD;
                            LOGE("[SA-DUMP] me=%08X autom=%08X cur=%08X sset=%08X count=%u arr=%08X state0=%08X type0=%08X",
                                 me, autom, cur, sset, scnt, sarr, s0, s0type);
                        }
                        // Menu-state guard: while a FlashMenu state is
                        // current, Gameplay::s_instance is a stale UAF
                        // pointer (MenuManager::Update virtual-calls through
                        // its vtable into reused gameswf data -> trap loop).
                        // Null it so MenuManager::Update takes its clean
                        // "no gameplay" branch. A real Gameplay state sets
                        // the singleton itself when it engages.
                        // NOTE (rev 50): Gameplay::s_instance
                        // (0x417B5E10) goes stale once the menu runs and
                        // MenuManager::Update (0x5CC224 call site) BLXes
                        // through it into reused gameswf data (trap loop
                        // PC=0x76EAA0). Zeroing it per-tick REGRESSED the
                        // run (28 stalls); the call target itself must be
                        // fixed or the call site guarded guest-side.
                        // Leave untouched until investigated.
                        // replicate the replaced push prologue with REAL
                        // register values (r(startReg)..r(startReg+regCount-1)
                        // then LR); epilogue POP restores them correctly.
                        uint32_t newsp = jit.Regs()[13] - words * 4;
                        for (uint32_t wi = 0; wi < regCount; ++wi)
                            host.MemoryWrite32(newsp + wi * 4, jit.Regs()[startReg + wi]);
                        host.MemoryWrite32(newsp + regCount * 4, jit.Regs()[14]);
                        jit.Regs()[13] = newsp;
                    });
                MemoryWrite32(0x40000000u + pp.addr,
                              0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
                LOGI("[SA-TICK] %s at 0x%08X", pp.name, pp.addr);
            }
        }

#endif

        // [INIT-AD4] observational probe for the original STR
        // R4,[R10,#0xAD4] instruction in iFPS::Init. Keep the write exactly
        // equivalent; do not invent an alternate base or repair unrelated
        // Application fields here.
        {
            constexpr uint32_t kSite = 0x40000000u + 0x8A3164u;
            constexpr uint32_t kExpected = 0xE58A4AD4u; // STR R4,[R10,#0xAD4]
            const uint32_t actual = MemoryRead32(kSite);
            if (actual != kExpected) {
                LOGE("[INIT-AD4] probe not installed: expected %08X, found %08X",
                     kExpected, actual);
            } else {
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t t = m_thunk_manager->RegisterThunk("probe_init_ad4",
                    [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t k = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        host.MemoryWrite32(jit.Regs()[10] + 0xAD4u,
                                           jit.Regs()[4]);
                        if (k <= 8 || (k % 500) == 0)
                            LOGE("[INIT-AD4] #%u base=%08X autom=%08X", k,
                                 jit.Regs()[10], jit.Regs()[4]);
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu);
                MemoryWrite32(kSite, replacement);
                InvalidateGuestCode(kSite, sizeof(uint32_t));
                g_probe_rewrites.push_back({kSite, replacement});
                LOGI("[INIT-AD4] exact STR probe installed at 0x8A3164");
            }
        }

        // [CREATESTATE] probe at iFPS::SA_CreateState (0x8A17E8). Real
        // prologue per IDA: PUSH {R4-R6,LR} (4 words). The SVC replaces the
        // push, so the thunk replicates it; execution resumes at entry+4.
        {
            uint32_t entry = 0x40000000u + 0x8A17E8u;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_createstate",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t data = jit.Regs()[2];
                    uint32_t typ = data ? host.MemoryRead32(data + 4) : 0xDEAD;
                    if (k <= 20 || (k % 500) == 0)
                        LOGE("[CREATESTATE] #%u data=%08X type=%08X", k, data, typ);
                    // replicate: PUSH {R4-R6, LR} (4 words)
                    uint32_t newsp = jit.Regs()[13] - 16;
                    for (int wi = 0; wi < 3; ++wi)
                        host.MemoryWrite32(newsp + wi * 4, jit.Regs()[4 + wi]);
                    host.MemoryWrite32(newsp + 12, jit.Regs()[14]);
                    jit.Regs()[13] = newsp;
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[CREATESTATE] probe installed at 0x8A17E8");
        }

        // [STATESET] Data-parse visibility. An entry probe REPLACES the
        // function's first instruction (the PUSH), so every entry thunk here
        // replicates the real prologue (verified in IDA):
        //   data_ctor     0x7381A4  PUSH {R4-R10,LR} = 8 words
        //   stateset_ctor 0x72F50C  PUSH {R4-R8,LR}  = 6 words
        // Mid-function probes replace one real instruction and must emulate
        // exactly that instruction before resuming at +4.
        {
            // data_ctor entry: log (this, id, Interface) and replicate push
            uint32_t entry = 0x40000000u + 0x7381A4u;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_data_ctor",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 6 || (k % 2000) == 0)
                        LOGE("[STATESET] probe_data_ctor #%u this=%08X id=%08X iface=%08X",
                             k, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
                    // replicate: PUSH {R4-R10, LR} (8 words)
                    uint32_t sp = jit.Regs()[13] - 32;
                    for (int i = 0; i < 7; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 28, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[STATESET] data_ctor at 0x7381A4 (push replicated)");

            // dcount at 0x7381F0 (STR R0,[R6]): emulate the store, log the
            // state count ReadInt actually returned from the graph stream.
            entry = 0x40000000u + 0x7381F0u;
            t = m_thunk_manager->RegisterThunk("probe_dcount",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t cnt = jit.Regs()[0];
                    host.MemoryWrite32(jit.Regs()[6], cnt);  // emulate STR
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 6 || (k % 2000) == 0)
                        LOGE("[STATESET] dcount #%u count=%d iface=%08X vt=%08X",
                             k, (int32_t)cnt, jit.Regs()[8],
                             jit.Regs()[8] > 0x100u
                                 ? host.MemoryRead32(jit.Regs()[8]) : 0);
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[STATESET] dcount at 0x7381F0");

            // dpeek at 0x738220 (LDR R3,[R8]): emulate the load, log the
            // state type Peek4 fed to Interface::CreateState.
            entry = 0x40000000u + 0x738220u;
            t = m_thunk_manager->RegisterThunk("probe_dpeek",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    jit.Regs()[3] = host.MemoryRead32(jit.Regs()[8]);  // emulate LDR
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 6 || (k % 2000) == 0)
                        LOGE("[STATESET] dpeek #%u type=%08X iface=%08X",
                             k, jit.Regs()[0], jit.Regs()[8]);
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[STATESET] dpeek at 0x738220");

            // dcreated at 0x738238 (MOV R5,R0): emulate the move, log the
            // State object returned by Interface::CreateState.
            entry = 0x40000000u + 0x738238u;
            t = m_thunk_manager->RegisterThunk("probe_dcreated",
                [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                    static std::atomic<uint32_t> n{0};
                    jit.Regs()[5] = jit.Regs()[0];  // emulate MOV
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 6 || (k % 2000) == 0)
                        LOGE("[STATESET] dcreated #%u state=%08X", k, jit.Regs()[0]);
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[STATESET] dcreated at 0x738238");

            // stateset_ctor entry (0x72F50C): log and replicate
            // PUSH {R4-R8, LR} (6 words)
            entry = 0x40000000u + 0x72F50Cu;
            t = m_thunk_manager->RegisterThunk("probe_stateset_ctor",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 6 || (k % 2000) == 0)
                        LOGE("[STATESET] probe_stateset_ctor #%u ss=%08X data=%08X",
                             k, jit.Regs()[0], jit.Regs()[2]);
                    uint32_t sp = jit.Regs()[13] - 24;
                    for (int i = 0; i < 5; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 20, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(entry, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[STATESET] stateset_ctor at 0x72F50C (push replicated)");
        }

        // [R10TRACE] iFPS::Init loses its `this` (R10) between the prologue
        // (MOV R10,R0 at 0x8A2AC0) and FileManager::Init (0x8A2DC8) --
        // observed R10=1 in both FileManager::Init and at ADD R1,R10,#0xAD0
        // (interface ptr became 0xAD1). Chain of mid-function probes, each
        // emulating the exact instruction it replaces:
        {
            struct RT { const char* name; uint32_t site; int kind; };
            const RT rts[] = {
                {"t0_sp10",   0x8A2AC8u, 0},  // STR R2,[SP,#0x10]
                {"t1_ldr344", 0x8A2B64u, 1},  // LDR R4,[R10,#0x344]
                {"t2_sgg",    0x8A2AF0u, 2},  // MOV R4,R0
                {"t3_obbpre", 0x8A2C58u, 3},  // MOV R0,R4
                {"t4_obbpost",0x8A2C60u, 4},  // LDRSB R3,[R4] (after JNI thunk)
                {"t5_preadd", 0x8A2C94u, 5},  // LDR R3,[SP,#0xC]
                {"t6_postadd",0x8A2D20u, 6},  // LDR R3,[SP,#0x40]
                {"t7_appinit",0x8A2D94u, 7},  // LDR R4,[SP,#0x44]
                {"t7b_fmret", 0x8A2DCCu, 9},  // MOV R0,#0x214 (after FM::Init)
                {"t8b_alloc", 0x8A2DD4u, 10}, // MOV R6,R0 (after CustomAlloc)
                {"t8c_smvox", 0x8A2DE0u, 11}, // ADD R4,R10,#0xAE0 (after SMVox)
                {"t8d_isinit",0x8A2DF8u, 12}, // MOV R0,R9 (after IsInitialized)
                {"t8e_cs",    0x8A2E00u, 3},  // MOV R0,R4 (after CS ctor)
                {"t8f_initz", 0x8A2E04u, 13}, // MOV R1,R9 (after Initialize)
                {"t8_glwt",   0x8A2E0Cu, 8},  // LDR R3,[SP,#0x78]
            };
            for (const RT& rt : rts) {
                std::string nm = std::string("probe_r10") + rt.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t t = m_thunk_manager->RegisterThunk(nm.c_str(),
                    [nm, cnt, kind = rt.kind](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k = cnt->fetch_add(1, std::memory_order_relaxed) + 1;
                        uint32_t r10 = jit.Regs()[10];
                        // The FileManager ctor smashes its saved-register area
                        // on our env (R10 arrives as 1 downstream); pin the
                        // true iFPS this at first sight and restore it
                        // whenever a later probe sees it broken.
                        if (r10 >= 0x10000u) {
                            uint32_t expect = 0;
                            g_iips_this.compare_exchange_strong(expect, r10,
                                std::memory_order_relaxed);
                        } else {
                            uint32_t good = g_iips_this.load(std::memory_order_relaxed);
                            if (good) jit.Regs()[10] = good;
                        }
                        bool bad = r10 < 0x10000u;
                        switch (kind) {
                        case 0:  // STR R2,[SP,#0x10]
                            host.MemoryWrite32(jit.Regs()[13] + 0x10, jit.Regs()[2]);
                            break;
                        case 1:  // LDR R4,[R10,#0x344]
                            jit.Regs()[4] = host.MemoryRead32(r10 + 0x344);
                            break;
                        case 2:  // MOV R4,R0
                            jit.Regs()[4] = jit.Regs()[0];
                            break;
                        case 3:  // MOV R0,R4
                            jit.Regs()[0] = jit.Regs()[4];
                            break;
                        case 4: {  // LDRSB R3,[R4]
                            uint8_t b = host.GetGuestMemoryBase()
                                ? host.GetGuestMemoryBase()[jit.Regs()[4]] : 0;
                            jit.Regs()[3] = (uint32_t)(int32_t)(int8_t)b;
                            break;
                        }
                        case 5:  // LDR R3,[SP,#0xC]
                            jit.Regs()[3] = host.MemoryRead32(jit.Regs()[13] + 0xC);
                            break;
                        case 6:  // LDR R3,[SP,#0x40]
                            jit.Regs()[3] = host.MemoryRead32(jit.Regs()[13] + 0x40);
                            break;
                        case 7:  // LDR R4,[SP,#0x44]
                            jit.Regs()[4] = host.MemoryRead32(jit.Regs()[13] + 0x44);
                            break;
                        case 8:  // LDR R3,[SP,#0x78]
                            jit.Regs()[3] = host.MemoryRead32(jit.Regs()[13] + 0x78);
                            break;
                        case 9:  // MOV R0,#0x214
                            jit.Regs()[0] = 0x214;
                            break;
                        case 10:  // MOV R6,R0
                            jit.Regs()[6] = jit.Regs()[0];
                            break;
                        case 11:  // ADD R4,R10,#0xAE0
                            jit.Regs()[4] = jit.Regs()[10] + 0xAE0;
                            break;
                        case 12:  // MOV R0,R9
                            jit.Regs()[0] = jit.Regs()[9];
                            break;
                        case 13:  // MOV R1,R9
                            jit.Regs()[1] = jit.Regs()[9];
                            break;
                        }
                        if (k <= 2 || bad)
                            LOGE("[R10TRACE] %s #%u R10=%08X%s", nm.c_str(),
                                 k, r10, bad ? " BAD" : "");
                    });
                MemoryWrite32(0x40000000u + rt.site,
                              0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
                LOGI("[R10TRACE] %s at 0x%08X", rt.name, rt.site);
            }

            // IFACE-AD0 at 0x8A3150 (ADD R1,R10,#0xAD0): the StateAutomat
            // ctor receives Interface& in R1. With R10 smashed by the FM
            // ctor the ctor got 0xAD1 and every state creation failed.
            // Emulate the ADD with the pinned (true) iFPS this.
            {
                uint32_t t = m_thunk_manager->RegisterThunk("probe_iface_ad0",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> n{0};
                        uint32_t r10 = jit.Regs()[10];
                        if (r10 < 0x10000u) {
                            uint32_t good = g_iips_this.load(std::memory_order_relaxed);
                            if (good) { jit.Regs()[10] = good; r10 = good; }
                        } else {
                            uint32_t expect = 0;
                            g_iips_this.compare_exchange_strong(expect, r10,
                                std::memory_order_relaxed);
                        }
                        jit.Regs()[1] = r10 + 0xAD0;  // emulate ADD R1,R10,#0xAD0
                        uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 4 || (k % 1000) == 0)
                            LOGE("[IFACE-AD0] #%u R10=%08X iface=%08X", k, r10,
                                 jit.Regs()[1]);
                    });
                MemoryWrite32(0x40000000u + 0x8A3150u,
                              0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
                LOGI("[IFACE-AD0] probe installed at 0x8A3150");
            }
        }

        // Application::Init performs essential device/renderer setup. Keep
        // its real body enabled and instrument only verified instructions,
        // emulating each displaced instruction exactly.
        {
            constexpr uint32_t kEntry = 0x40000000u + 0x88C660u;
            constexpr uint32_t kEntryExpected = 0xE92D4FF0u; // PUSH {R4-R11,LR}
            const uint32_t entryActual = MemoryRead32(kEntry);
            if (entryActual != kEntryExpected) {
                LOGE("[APPINIT] entry probe not installed: expected %08X, found %08X",
                     kEntryExpected, entryActual);
            } else {
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "probe_appinit_entry",
                    [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t k = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        const uint32_t app = jit.Regs()[0];
                        const uint32_t deviceHolder = jit.Regs()[1];
                        const uint32_t device = deviceHolder
                            ? host.MemoryRead32(deviceHolder) : 0;
                        const uint32_t driver = device > 0x1000u
                            ? host.MemoryRead32(device + 8u) : 0;
                        if (k <= 8 || (k % 500u) == 0)
                            LOGE("[APPINIT] entry #%u app=%08X device-holder=%08X "
                                 "device=%08X driver=%08X caller=%08X",
                                 k, app, deviceHolder, device, driver, jit.Regs()[14]);

                        // Exact PUSH {R4-R11,LR} emulation for this probe.
                        const uint32_t sp = jit.Regs()[13] - 9u * 4u;
                        for (uint32_t i = 0; i < 8; ++i)
                            host.MemoryWrite32(sp + i * 4u, jit.Regs()[4u + i]);
                        host.MemoryWrite32(sp + 8u * 4u, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(kEntry, replacement);
                InvalidateGuestCode(kEntry, sizeof(uint32_t));
                g_probe_rewrites.push_back({kEntry, replacement});
                LOGI("[APPINIT] exact entry probe installed at 0x88C660");
            }

            constexpr uint32_t kDriverStore = 0x40000000u + 0x88C700u;
            constexpr uint32_t kDriverStoreExpected = 0xE584035Cu; // STR R0,[R4,#0x35C]
            const uint32_t storeActual = MemoryRead32(kDriverStore);
            if (storeActual != kDriverStoreExpected) {
                LOGE("[APPINIT] driver-store probe not installed: expected %08X, found %08X",
                     kDriverStoreExpected, storeActual);
            } else {
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "probe_appinit_driver_store",
                    [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t k = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        const uint32_t app = jit.Regs()[4];
                        const uint32_t driver = jit.Regs()[0];
                        host.MemoryWrite32(app + 0x35Cu, driver);
                        if (k <= 8 || (k % 500u) == 0)
                            LOGE("[APPINIT] driver-store #%u app=%08X driver=%08X",
                                 k, app, driver);
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(kDriverStore, replacement);
                InvalidateGuestCode(kDriverStore, sizeof(uint32_t));
                g_probe_rewrites.push_back({kDriverStore, replacement});
                LOGI("[APPINIT] exact driver-store probe installed at 0x88C700");
            }

            constexpr uint32_t kEpilogue = 0x40000000u + 0x88D158u;
            constexpr uint32_t kEpilogueExpected = 0xE28DD06Cu; // ADD SP,SP,#0x6C
            const uint32_t epilogueActual = MemoryRead32(kEpilogue);
            if (epilogueActual != kEpilogueExpected) {
                LOGE("[APPINIT] epilogue probe not installed: expected %08X, found %08X",
                     kEpilogueExpected, epilogueActual);
            } else {
                auto hits = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "probe_appinit_return",
                    [hits](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        const uint32_t k = hits->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        const uint32_t result = jit.Regs()[0];
                        const uint32_t app = jit.Regs()[4];
                        jit.Regs()[13] += 0x6Cu;
                        if (k <= 8 || (k % 500u) == 0) {
                            LOGE("[APPINIT] return #%u app=%08X result=%08X driver=%08X",
                                 k, app, result,
                                 app ? host.MemoryRead32(app + 0x35Cu) : 0);
                            const uint32_t device = app
                                ? host.MemoryRead32(app + 0x344u) : 0;
                            const uint32_t scene = device > 0x1000u
                                ? host.MemoryRead32(device + 0x18u) : 0;
                            LOGE("[APPINIT] linkage #%u device=%08X scene=%08X vtable=%08X driver=%08X",
                                 k, device, scene,
                                 scene > 0x1000u ? host.MemoryRead32(scene) : 0,
                                 scene > 0x1000u
                                     ? host.MemoryRead32(scene + 0x10u) : 0);
                        }
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(kEpilogue, replacement);
                InvalidateGuestCode(kEpilogue, sizeof(uint32_t));
                g_probe_rewrites.push_back({kEpilogue, replacement});
                LOGI("[APPINIT] exact return probe installed at 0x88D158");
            }
        }


        // [MENUGUARD] MenuManager::Update+0x358 (0x5CC1F8, LDR R0,[R3])
        // reads Gameplay::s_instance for the cheat-button "notify gameplay"
        // dispatch. With no Gameplay state the pointer is null (we null it
        // per-tick) and the later BLX R3 slides through zero memory. Probe
        // both loads: when the instance is null, jump straight to
        // loc_5CC218 (MOV R2,#0; B loc_5CBF00) -- the clean no-gameplay
        // path that skips the whole dispatch.
        {
            uint32_t site1 = 0x40000000u + 0x5CC1F8u;
            uint32_t t1 = m_thunk_manager->RegisterThunk("probe_menuguard_ldr",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    uint32_t r3 = jit.Regs()[3];
                    uint32_t v = r3 > 0x100u ? host.MemoryRead32(r3) : 0;
                    jit.Regs()[0] = v;  // emulate LDR R0,[R3]
                });
            MemoryWrite32(site1, 0xEF000000u | (MemoryRead32(t1) & 0x00FFFFFFu));

            uint32_t site2 = 0x40000000u + 0x5CC1FCu;
            uint32_t t2 = m_thunk_manager->RegisterThunk("probe_menuguard_chk",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    if (jit.Regs()[0] == 0) {
                        // null instance: skip to the clean no-gameplay path
                        jit.Regs()[15] = 0x40000000u + 0x5CC218u;
                    } else {
                        jit.Regs()[3] = host.MemoryRead32(jit.Regs()[0]);  // LDR R3,[R0]
                    }
                });
            MemoryWrite32(site2, 0xEF000000u | (MemoryRead32(t2) & 0x00FFFFFFu));
            LOGI("[MENUGUARD] probes installed at 0x5CC1F8/0x5CC1FC");
        }

            // The generic virtual path (loc_5CC2DC: BLX R3) is reached from
            // several entries with a null/invalid R3 -> PC=0 slide. Intercept
            // the BLX itself: invalid target -> continue at 0x5CC2E0, which
            // branches to the clean no-gameplay path; valid target -> emulate
            // the BLX (LR back here, Thumb per bit0).
            {
                uint32_t site3 = 0x40000000u + 0x5CC2DCu;
                uint32_t t3 = m_thunk_manager->RegisterThunk("probe_menuguard_blx",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                        uint32_t r3 = jit.Regs()[3];
                        if (r3 < 0x40000000u || r3 >= 0x41A00000u) {
                            // stale/garbage slot (string ptrs pass >=0x1000!):
                            // take the clean no-gameplay path
                            jit.Regs()[15] = 0x40000000u + 0x5CC2E0u;
                            jit.SetCpsr(jit.Cpsr() & ~0x20u);
                        } else {
                            jit.Regs()[14] = 0x40000000u + 0x5CC2E0u;
                            jit.Regs()[15] = r3 & ~1u;
                            jit.SetCpsr((jit.Cpsr() & ~0x20u) | ((r3 & 1u) ? 0x20u : 0u));
                        }
                    });
                MemoryWrite32(site3, 0xEF000000u | (MemoryRead32(t3) & 0x00FFFFFFu));
                LOGI("[MENUGUARD] BLX guard at 0x5CC2DC");
            }

            // Two more virtual calls share the same stale Gameplay::s_instance:
            // 0x5CC220 (return 0x5CC224: MOV R10,R0) and 0x5CC22C (return
            // 0x5CC230: B +0x2F). Guard both: only emulate when the target
            // is inside the code image; otherwise return null and continue.
            {
                struct SiteFix { uint32_t blx, cont; };
                const SiteFix fixes[] = {
                    {0x5CC220u, 0x5CC224u},
                    {0x5CC22Cu, 0x5CC230u},
                };
                for (const SiteFix& fx : fixes) {
                    uint32_t st = 0x40000000u + fx.blx;
                    uint32_t tt = m_thunk_manager->RegisterThunk("probe_menuguard2",
                        [cont = fx.cont](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                            uint32_t r3 = jit.Regs()[3];
                            if (r3 >= 0x40000000u && r3 < 0x41A00000u) {
                                jit.Regs()[14] = 0x40000000u + cont;
                                jit.Regs()[15] = r3 & ~1u;
                                jit.SetCpsr((jit.Cpsr() & ~0x20u) |
                                            ((r3 & 1u) ? 0x20u : 0u));
                            } else {
                                jit.Regs()[0] = 0;
                                jit.Regs()[15] = 0x40000000u + cont;
                                jit.SetCpsr(jit.Cpsr() & ~0x20u);
                            }
                        });
                    MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                    LOGI("[MENUGUARD] BLX guard at 0x%X", fx.blx);
                }
            }
        // [SWFDBG] gameswf parse diagnostics: logError (0xf97b48, prologue
        // PUSH {R0-R3}) is the fork's error sink -- the menu-SWF read fails
        // silently and this names the reason; MovieDefImpl::read (0xf9bfd8,
        // prologue PUSH {R4-R8,LR}) entry logs each parse attempt.
        {
            uint32_t le = 0x40000000u + 0xf97b48u;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_swf_logerror",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    char buf[160]; size_t q = 0;
                    uint32_t fp = jit.Regs()[0];
                    if (fp > 0x100u && host.GetGuestMemoryBase()) {
                        const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + fp);
                        while (q + 1 < sizeof(buf) && p[q]) { buf[q] = p[q]; ++q; }
                    }
                    buf[q] = 0;
                    uint32_t sp = jit.Regs()[13] - 16;
                    for (int i = 0; i < 4; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[i]);
                    jit.Regs()[13] = sp;
                    if (k <= 20 || (k % 200) == 0)
                        LOGE("[SWF-ERR] #%u %s", k, buf);
                    if (k == 1 && host.GetGuestMemoryBase()) {
                        // Dump the gameswf HostInterface: global object at
                        // 0x17D6724, its vtable, and slot +20 -- the
                        // glf::IOStream factory that fails on the movie path.
                        uint32_t iface = host.MemoryRead32(0x417D6724u);
                        LOGE("[SWF-ERR] HostInterface obj=%08X", iface);
                        if (iface > 0x100u) {
                            uint32_t vt = host.MemoryRead32(iface);
                            LOGE("[SWF-ERR] vtable=%08X", vt);
                            for (uint32_t sl = 0; sl < 40; sl += 4) {
                                uint32_t fn = host.MemoryRead32(vt + sl);
                                LOGE("[SWF-ERR] slot+%02X = %08X", sl, fn);
                            }
                        }
                    }
                });
            MemoryWrite32(le, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));

            uint32_t re = 0x40000000u + 0xf9bfd8u;
            t = m_thunk_manager->RegisterThunk("probe_swf_read",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (k <= 6 || (k % 200) == 0)
                        LOGE("[SWF-READ] #%u def=%08X file=%08X", k,
                             jit.Regs()[0], jit.Regs()[1]);
                    if (k == 1 && host.GetGuestMemoryBase()) {
                        // Dump the Stream object words: find the raw data
                        // buffer gameswf is actually parsing (FWS/CWS sig?).
                        uint32_t fs = jit.Regs()[1];
                        if (fs > 0x1000u) {
                            for (uint32_t woff = 0; woff < 0x40; woff += 4) {
                                uint32_t wv = host.MemoryRead32(fs + woff);
                                LOGE("[SWF-READ] obj+%02X = %08X", woff, wv);
                            }
                        }
                    }
                    uint32_t sp = jit.Regs()[13] - 24;
                    for (int i = 0; i < 5; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 20, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(re, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[SWFDBG] probes installed at 0xf97b48/0xf9bfd8");
        }

        // Observe the already-formatted message, not a host interpretation
        // of ARM32 varargs. The original MenuManager sink is just BX LR.
        {
            constexpr uint32_t site = 0x405B506Cu;
            constexpr uint32_t expected = 0xE12FFF1Eu;
            if (MemoryRead32(site) != expected) {
                LOGE("[SWF-MESSAGE] refusing stale log sink probe");
            } else {
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    "probe_swf_message", [](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        static std::atomic<uint32_t> count[2]{};
                        const uint32_t n = count[jit.Regs()[1] != 0].fetch_add(1) + 1;
                        if (n <= 32 || n % 256 == 0) {
                            char message[256]{};
                            const uint32_t text = jit.Regs()[2];
                            if (text >= 0x40000000u && text < 0xEFFFFF00u) {
                                for (size_t i = 0; i + 1 < sizeof(message); ++i) {
                                    message[i] = static_cast<char>(
                                        host.MemoryRead8(text + i));
                                    if (!message[i]) break;
                                }
                            }
                            LOGI("[SWF-MESSAGE] #%u error=%u text=%08X %s",
                                 n, jit.Regs()[1], text, message);
                        }
                        const uint32_t lr = jit.Regs()[14];
                        jit.Regs()[15] = lr & ~1u;
                        jit.SetCpsr((jit.Cpsr() & ~0x20u) |
                                    ((lr & 1u) ? 0x20u : 0u));
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
            }
        }

#if MC4_ENABLE_NATIVE_LOGGING
        // Observational probes replace hot guest instructions with host SVCs.
        // Release keeps the original instructions; no rendering state depends on these counts.
        // [TEXTPATH] Read-only boundary counts for the missing menu labels.
        // Each entry SVC reproduces precisely the displaced ARM instruction;
        // no string, font, sprite state or return value is fabricated.
        {
            struct Site {
                const char* name;
                uint32_t address;
                uint32_t expected;
                unsigned text_kind;
            };
            const Site sites[] = {
                {"lookup",    0x404F8030u, 0xE92D4038u, 1},
                {"menu_set",  0x405D1378u, 0xE92D4FF0u, 1},
                {"font",      0x405B59E8u, 0xE92D41F0u, 2},
                {"edit_set",  0x40FF4728u, 0xE92D4FF0u, 2},
                {"glyph",     0x40F6577Cu, 0xE92D4FF0u, 3},
                {"edit_draw", 0x40FF8C28u, 0xE5D030A4u, 4},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected ||
                    (site.text_kind != 4 && !arm32::IsProbePush(original))) {
                    LOGE("[TEXTPATH] stale site=%s address=%08X expected=%08X got=%08X",
                         site.name, site.address, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name, [site, count](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(1,
                            std::memory_order_relaxed) + 1;
                        const uint32_t r0 = jit.Regs()[0];
                        const uint32_t r1 = jit.Regs()[1];
                        const uint32_t r2 = jit.Regs()[2];
                        if (n <= 16 || n % 4096 == 0) {
                            auto guest_string = [&host](uint32_t address,
                                                        char (&out)[64]) {
                                out[0] = 0;
                                if (address < 0x40000000u ||
                                    address >= 0xEFFFFFC0u) return;
                                for (size_t i = 0; i + 1 < sizeof(out); ++i) {
                                    out[i] = static_cast<char>(
                                        host.MemoryRead8(address + i));
                                    if (!out[i]) break;
                                }
                                out[sizeof(out) - 1] = 0;
                            };
                            char arg1[64]{}, arg2[64]{};
                            if (site.text_kind == 1) {
                                guest_string(r1, arg1);
                                guest_string(r2, arg2);
                            } else if (site.text_kind == 2 && r1 > 0x1000u) {
                                const int8_t length = static_cast<int8_t>(
                                    host.MemoryRead8(r1));
                                const uint32_t characters = length == -1
                                    ? host.MemoryRead32(r1 + 12) : r1 + 1;
                                guest_string(characters, arg1);
                            }
                            const uint32_t visibility = site.text_kind == 4 &&
                                r0 > 0x1000u ? host.MemoryRead8(r0 + 0xA4u) : 0;
                            const uint32_t layout_count = site.text_kind == 4 &&
                                r0 > 0x1000u ? host.MemoryRead32(r0 + 0xECu) : 0;
                            const uint32_t text_source = site.text_kind == 4 &&
                                r0 > 0x1000u ? host.MemoryRead32(r0 + 0xE8u) : 0;
                            const uint32_t display_cache = site.text_kind == 4 &&
                                r0 > 0x1000u ? host.MemoryRead32(r0 + 0x48u) : 0;
                            LOGI("[TEXTPATH] %s #%u r0=%08X r1=%08X r2=%08X"
                                 " arg1='%s' arg2='%s' visible=%u layout=%u"
                                 " textsrc=%08X cache=%08X lr=%08X",
                                 site.name, n, r0, r1, r2, arg1, arg2,
                                 visibility, layout_count, text_source,
                                 display_cache, jit.Regs()[14]);
                        }
                        if (site.text_kind == 4) {
                            jit.Regs()[3] = host.MemoryRead8(r0 + 0xA4u);
                        } else {
                            jit.Regs()[13] = arm32::PushRegisters(
                                jit.Regs()[13],
                                static_cast<uint16_t>(site.expected & 0xFFFFu),
                                [&jit](unsigned reg) { return jit.Regs()[reg]; },
                                [&host](uint32_t at, uint32_t value) {
                                    host.MemoryWrite32(at, value);
                                });
                        }
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

#endif // TEXTPATH observers

        // [LOCBOUND] Distinguish the integer-ID localization overload used
        // by NativeGetString from the name-based overload in TEXTPATH.
        // Each exact-preimage hook emulates only its displaced instruction.
        {
            struct Site {
                const char* name;
                uint32_t address;
                uint32_t expected;
                unsigned kind;
            };
            const Site sites[] = {
                {"native_get", 0x40589788u, 0xE92D40F0u, 0},
                {"id_get",     0x404FDBB0u, 0xE5903008u, 1},
                {"table_out",  0x404FD4A4u, 0xE1A00004u, 2},
                {"set_lang",   0x404FDBD4u, 0xE59F3330u, 3},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected) {
                    LOGE("[LOCBOUND] stale %s at %08X expected=%08X got=%08X",
                         site.name, site.address, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name, [site, count](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        const uint32_t r0 = jit.Regs()[0];
                        const uint32_t r1 = jit.Regs()[1];
                        if (n <= 24 || n % 4096 == 0) {
                            if (site.kind == 0) {
                                const uint32_t argc = r0 >= 0x40000000u &&
                                    r0 < 0xEFFFFFE0u
                                    ? host.MemoryRead32(r0 + 0x14u) : 0;
                                LOGI("[LOCBOUND] %s #%u call=%08X argc=%u lr=%08X",
                                     site.name, n, r0, argc, jit.Regs()[14]);
                            } else if (site.kind == 1) {
                                const uint32_t tables = r0 >= 0x40000000u &&
                                    r0 < 0xEFFFFFF0u
                                    ? host.MemoryRead32(r0 + 8u) : 0;
                                LOGI("[LOCBOUND] %s #%u mgr=%08X id=%08X"
                                     " table_index=%u tables=%08X lr=%08X",
                                     site.name, n, r0, r1, r1 >> 16,
                                     tables, jit.Regs()[14]);
                            } else if (site.kind == 2) {
                                char value[65]{};
                                const uint32_t p = jit.Regs()[4];
                                if (p >= 0x40000000u && p < 0xEFFFFFBFu) {
                                    for (unsigned i = 0; i < 64; ++i) {
                                        const uint8_t c = host.MemoryRead8(p + i);
                                        if (!c) break;
                                        value[i] = c >= 0x20u && c < 0x7Fu
                                            ? static_cast<char>(c) : '?';
                                    }
                                }
                                LOGI("[LOCBOUND] %s #%u id=%08X result=%08X"
                                     " text='%s' lr=%08X",
                                     site.name, n, r1, p,
                                     value, jit.Regs()[14]);
                            } else {
                                LOGI("[LOCBOUND] %s #%u mgr=%08X lang=%u"
                                     " lr=%08X", site.name, n, r0, r1,
                                     jit.Regs()[14]);
                            }
                        }
                        switch (site.kind) {
                        case 0:
                            jit.Regs()[13] = arm32::PushRegisters(
                                jit.Regs()[13],
                                static_cast<uint16_t>(site.expected & 0xFFFFu),
                                [&jit](unsigned reg) { return jit.Regs()[reg]; },
                                [&host](uint32_t at, uint32_t value) {
                                    host.MemoryWrite32(at, value);
                                });
                            break;
                        case 1:
                            if (uint32_t text = mc4::Phase3SettingsStringOverride(
                                    host, r0, r1, jit.Regs()[14])) {
                                jit.Regs()[0] = text;
                                jit.Regs()[15] = jit.Regs()[14];
                                return;
                            }
                            jit.Regs()[3] = host.MemoryRead32(r0 + 8u);
                            break;
                        case 2:
                            jit.Regs()[0] = jit.Regs()[4];
                            break;
                        case 3:
                            jit.Regs()[3] = host.MemoryRead32(
                                site.address + 8u + 0x330u);
                            break;
                        }
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

#if MC4_ENABLE_NATIVE_LOGGING
        // [FONTCHAIN] Preserve every displaced instruction while measuring
        // whether a resolved font path actually reaches layout/rasterization.
        {
            struct Site {
                const char* name;
                uint32_t address;
                uint32_t expected;
                unsigned kind; // 0=ARM PUSH, 1=MOV R0,#1, 2=PUSH LR, 3=LDRB
            };
            const Site sites[] = {
                {"font_result", 0x405B5B80u, 0xE3A00001u, 1},
                {"edit_format", 0x40FF2F9Cu, 0xE92D40F0u, 0},
                {"edit_preload", 0x40FF09D0u, 0xE92D4FF0u, 0},
                {"glyph_lookup", 0x40F88D40u, 0xE92D4FF0u, 0},
                {"face_find", 0x40F87F08u, 0xE92D4FF0u, 0},
                {"font_file", 0x40F872E4u, 0xE92D4070u, 0},
                {"ft_new", 0x41436C98u, 0xE52DE004u, 2},
                {"static_draw", 0x40FF9778u, 0xE5D130A4u, 3},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected ||
                    (site.kind == 0 && !arm32::IsProbePush(original))) {
                    LOGE("[FONTCHAIN] stale site=%s address=%08X expected=%08X got=%08X",
                         site.name, site.address, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name, [site, count](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(1,
                            std::memory_order_relaxed) + 1;
                        const uint32_t r0 = jit.Regs()[0];
                        const uint32_t r1 = jit.Regs()[1];
                        const uint32_t r2 = jit.Regs()[2];
                        if (n <= 16 || n % 4096 == 0) {
                            auto read_cstr = [&host](uint32_t address,
                                                     char (&out)[96]) {
                                out[0] = 0;
                                if (address < 0x40000000u ||
                                    address >= 0xEFFFFFA0u) return;
                                for (size_t i = 0; i + 1 < sizeof(out); ++i) {
                                    out[i] = static_cast<char>(
                                        host.MemoryRead8(address + i));
                                    if (!out[i]) break;
                                }
                                out[sizeof(out) - 1] = 0;
                            };
                            auto read_string = [&host, &read_cstr](
                                uint32_t address, char (&out)[96]) {
                                out[0] = 0;
                                if (address < 0x40000000u ||
                                    address >= 0xEFFFFFA0u) return;
                                const int8_t length = static_cast<int8_t>(
                                    host.MemoryRead8(address));
                                const uint32_t chars = length == -1
                                    ? host.MemoryRead32(address + 12u)
                                    : address + 1u;
                                read_cstr(chars, out);
                            };
                            char path[96]{};
                            if (site.kind == 1) {
                                read_cstr(jit.Regs()[4], path);
                            } else if (site.address == 0x40F88D40u ||
                                       site.address == 0x40F87F08u) {
                                read_string(site.address == 0x40F88D40u
                                                ? r2 : r1, path);
                            } else if (site.address == 0x40F872E4u) {
                                read_cstr(r0, path);
                            }
                            const uint32_t object = site.kind == 1
                                ? jit.Regs()[6] : 0;
                            char output[96]{};
                            if (object) read_string(object, output);
                            const uint32_t visible = site.kind == 3 &&
                                r1 > 0x1000u ? host.MemoryRead8(r1 + 0xA4u) : 0;
                            LOGI("[FONTCHAIN] %s #%u r0=%08X r1=%08X r2=%08X"
                                 " r4=%08X r6=%08X path='%s' output='%s'"
                                 " visible=%u lr=%08X",
                                 site.name, n, r0, r1, r2, jit.Regs()[4],
                                 jit.Regs()[6], path, output, visible,
                                 jit.Regs()[14]);
                        }
                        switch (site.kind) {
                        case 0:
                            jit.Regs()[13] = arm32::PushRegisters(
                                jit.Regs()[13],
                                static_cast<uint16_t>(site.expected & 0xFFFFu),
                                [&jit](unsigned reg) { return jit.Regs()[reg]; },
                                [&host](uint32_t at, uint32_t value) {
                                    host.MemoryWrite32(at, value);
                                });
                            break;
                        case 1:
                            jit.Regs()[0] = 1;
                            break;
                        case 2:
                            jit.Regs()[13] -= 4u;
                            host.MemoryWrite32(jit.Regs()[13], jit.Regs()[14]);
                            break;
                        case 3:
                            jit.Regs()[3] = host.MemoryRead8(r1 + 0xA4u);
                            break;
                        }
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

        // [FONTRESULT] Distinguish a cached null face from FreeType/bitmap
        // failure. All sites are direct disassembly of the immutable guest.
        {
            struct Site {
                const char* name;
                uint32_t address;
                uint32_t expected;
                unsigned kind; // 0=PUSH, 1=PUSH LR, 2=MOV, 3=ADD SP, 4=LDRSB
            };
            const Site sites[] = {
                {"face_return", 0x40F88120u, 0xE1A0000Au, 2},
                {"glyph_null", 0x40F8916Cu, 0xE3A00000u, 2},
                {"glyph_success", 0x40F88E6Cu, 0xE28DD014u, 3},
                {"file_fallback", 0x40F888B8u, 0xE1D530D0u, 4},
                {"ft_new_face", 0x41436C60u, 0xE52DE004u, 1},
                {"ft_load_char", 0x41435A08u, 0xE92D4038u, 0},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected ||
                    (site.kind == 0 && !arm32::IsProbePush(original))) {
                    LOGE("[FONTRESULT] stale site=%s address=%08X expected=%08X got=%08X",
                         site.name, site.address, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name, [site, count](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(1,
                            std::memory_order_relaxed) + 1;
                        if (n <= 12 || n % 4096 == 0) {
                            char path[96]{};
                            if (site.address == 0x41436C60u) {
                                const uint32_t at = jit.Regs()[1];
                                if (at >= 0x40000000u &&
                                    at < 0xEFFFFFA0u) {
                                    for (size_t i = 0; i + 1 < sizeof(path);
                                         ++i) {
                                        path[i] = static_cast<char>(
                                            host.MemoryRead8(at + i));
                                        if (!path[i]) break;
                                    }
                                }
                            }
                            LOGI("[FONTRESULT] %s #%u r0=%08X r1=%08X"
                                 " r2=%08X r7=%08X r8=%08X r10=%08X"
                                 " path='%s' lr=%08X",
                                 site.name, n, jit.Regs()[0],
                                 jit.Regs()[1], jit.Regs()[2],
                                 jit.Regs()[7], jit.Regs()[8],
                                 jit.Regs()[10], path, jit.Regs()[14]);
                        }
                        switch (site.kind) {
                        case 0:
                            jit.Regs()[13] = arm32::PushRegisters(
                                jit.Regs()[13],
                                static_cast<uint16_t>(site.expected & 0xFFFFu),
                                [&jit](unsigned reg) { return jit.Regs()[reg]; },
                                [&host](uint32_t at, uint32_t value) {
                                    host.MemoryWrite32(at, value);
                                });
                            break;
                        case 1:
                            jit.Regs()[13] -= 4u;
                            host.MemoryWrite32(jit.Regs()[13], jit.Regs()[14]);
                            break;
                        case 2:
                            jit.Regs()[0] = site.address == 0x40F88120u
                                ? jit.Regs()[10] : 0u;
                            break;
                        case 3:
                            jit.Regs()[13] += 20u;
                            break;
                        case 4:
                            jit.Regs()[3] = static_cast<uint32_t>(
                                static_cast<int32_t>(static_cast<int8_t>(
                                    host.MemoryRead8(jit.Regs()[5]))));
                            break;
                        }
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

        // [TEXTRENDER] Track nonzero alpha pixels and submission of the
        // resulting edit-text primitives. No renderer state is modified.
        {
            struct Site {
                const char* name;
                uint32_t address;
                uint32_t expected;
            };
            const Site sites[] = {
                {"alpha_bitmap", 0x40FB81D0u, 0xE92D43F0u},
                {"draw",         0x40FBB1B4u, 0xE92D4FF0u},
                {"flush_list",   0x40FBA1B4u, 0xE92D4FF0u},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected || !arm32::IsProbePush(original)) {
                    LOGE("[TEXTRENDER] stale site=%s address=%08X expected=%08X got=%08X",
                         site.name, site.address, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                auto text_count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name,
                    [site, count, text_count](Dynarmic::A32::Jit& jit,
                                              DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(1,
                            std::memory_order_relaxed) + 1;
                        const uint32_t r0 = jit.Regs()[0];
                        const uint32_t r1 = jit.Regs()[1];
                        const uint32_t r2 = jit.Regs()[2];
                        const uint32_t lr = jit.Regs()[14];
                        const bool from_edit = site.address == 0x40FBB1B4u &&
                            (lr == 0x40FF813Cu || lr == 0x40FF82B0u ||
                             lr == 0x40FF8308u);
                        const uint32_t e = from_edit
                            ? text_count->fetch_add(1,
                                std::memory_order_relaxed) + 1 : 0;
                        if (n <= 12 || n % 8192 == 0 ||
                            (e && (e <= 12 || e % 4096 == 0))) {
                            uint32_t d0 = 0, d1 = 0, d2 = 0, d3 = 0;
                            uint32_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
                            uint32_t c0 = 0, c1 = 0, c2 = 0, c3 = 0;
                            unsigned nonzero = 0, sampled = 0;
                            if (site.address == 0x40FB81D0u &&
                                r0 > 0 && r0 <= 4096u &&
                                r1 > 0 && r1 <= 4096u &&
                                r2 >= 0x40000000u && r2 < 0xEFFFFF00u) {
                                const uint32_t limit = std::min<uint32_t>(
                                    r0 * r1, 128u);
                                sampled = limit;
                                for (uint32_t i = 0; i < limit; ++i) {
                                    if (host.MemoryRead8(r2 + i)) ++nonzero;
                                }
                            } else if (site.address != 0x40FB81D0u &&
                                       r1 >= 0x40000000u &&
                                       r1 < 0xEFFFFFE0u) {
                                d0 = host.MemoryRead32(r1);
                                d1 = host.MemoryRead32(r1 + 4u);
                                d2 = host.MemoryRead32(r1 + 8u);
                                d3 = host.MemoryRead32(r1 + 12u);
                                if (from_edit) {
                                    b0 = host.MemoryRead32(r1 + 20u);
                                    b1 = host.MemoryRead32(r1 + 24u);
                                    b2 = host.MemoryRead32(r1 + 28u);
                                    b3 = host.MemoryRead32(r1 + 32u);
                                    c0 = host.MemoryRead32(r0 + 100u);
                                    c1 = host.MemoryRead32(r0 + 104u);
                                    c2 = host.MemoryRead32(r0 + 108u);
                                    c3 = host.MemoryRead32(r0 + 112u);
                                }
                            }
                            LOGI("[TEXTRENDER] %s #%u edit#%u r0=%08X r1=%08X"
                                 " r2=%08X r3=%08X data=%08X,%08X,%08X,%08X"
                                 " rect=%08X,%08X,%08X,%08X"
                                 " clip=%08X,%08X,%08X,%08X"
                                 " bytes=%u/%u lr=%08X",
                                 site.name, n, e, r0, r1, r2, jit.Regs()[3],
                                 d0, d1, d2, d3, b0, b1, b2, b3,
                                 c0, c1, c2, c3, nonzero, sampled, lr);
                        }
                        jit.Regs()[13] = arm32::PushRegisters(
                            jit.Regs()[13],
                            static_cast<uint16_t>(site.expected & 0xFFFFu),
                            [&jit](unsigned reg) { return jit.Regs()[reg]; },
                            [&host](uint32_t at, uint32_t value) {
                                host.MemoryWrite32(at, value);
                            });
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

        // [TEXTBATCH] This LDR is reached only after draw's rect-visibility
        // checks and after choosing the BatchList for PrimitiveInfo type 3.
        {
            constexpr uint32_t site = 0x40FBB744u;
            constexpr uint32_t expected = 0xE59A6004u;
            const uint32_t original = MemoryRead32(site);
            if (original != expected) {
                LOGE("[TEXTBATCH] stale address=%08X expected=%08X got=%08X",
                     site, expected, original);
                return false;
            }
            auto all = std::make_shared<std::atomic<uint32_t>>(0);
            auto text_count = std::make_shared<std::atomic<uint32_t>>(0);
            const uint32_t thunk = m_thunk_manager->RegisterThunk(
                "text_batch", [all, text_count](Dynarmic::A32::Jit& jit,
                                                DynarmicHost& host) {
                    const uint32_t n = all->fetch_add(1,
                        std::memory_order_relaxed) + 1;
                    const uint32_t primitive = jit.Regs()[4];
                    const uint32_t kind = static_cast<uint8_t>(
                        host.MemoryRead8(primitive));
                    const uint32_t t = kind == 3
                        ? text_count->fetch_add(1,
                            std::memory_order_relaxed) + 1 : 0;
                    const uint32_t list = jit.Regs()[10];
                    const uint32_t length = host.MemoryRead32(list + 4u);
                    if (n <= 12 || n % 8192 == 0 ||
                        (t && (t <= 12 || t % 4096 == 0))) {
                        LOGI("[TEXTBATCH] #%u text#%u kind=%u primitive=%08X"
                             " list=%08X length=%u capacity=%u handler=%08X",
                             n, t, kind, primitive, list, length,
                             host.MemoryRead32(list + 8u), jit.Regs()[11]);
                    }
                    jit.Regs()[6] = length;
                });
            const uint32_t replacement = 0xEF000000u |
                (MemoryRead32(thunk) & 0x00FFFFFFu);
            MemoryWrite32(site, replacement);
            InvalidateGuestCode(site, sizeof(uint32_t));
            g_probe_rewrites.push_back({site, replacement});
        }

        // [EDITLAYOUT] Distinguish background primitive submission from
        // actual text layout/glyph drawing in EditTextCharacter::display.
        {
            struct Site {
                const char* name;
                uint32_t address;
                uint32_t expected;
                unsigned kind; // 0=LDR layout, 1=PUSH,
                               // 2/3=LDR parent, 4=LDR stack arg
            };
            const Site sites[] = {
                {"display_count", 0x40FF83E0u, 0xE59430ECu, 0},
                {"draw_text",     0x40FF6A10u, 0xE92D4FF0u, 1},
                {"past_global",   0x40FF6A94u, 0xE5943020u, 2},
                {"past_arg",      0x40FF6B20u, 0xE5943020u, 3},
                {"past_flag",     0x40FF6B30u, 0xE59D3034u, 4},
            };
            for (const Site& site : sites) {
                const uint32_t original = MemoryRead32(site.address);
                if (original != site.expected ||
                    (site.kind == 1 && !arm32::IsProbePush(original))) {
                    LOGE("[EDITLAYOUT] stale site=%s address=%08X expected=%08X got=%08X",
                         site.name, site.address, site.expected, original);
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.name, [site, count](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
                        const uint32_t n = count->fetch_add(1,
                            std::memory_order_relaxed) + 1;
                        const uint32_t object = site.kind != 1
                            ? jit.Regs()[4] : jit.Regs()[0];
                        const uint32_t length = host.MemoryRead32(object + 0xECu);
                        const uint32_t parent = host.MemoryRead32(object + 0x20u);
                        const uint32_t parent_flag = parent >= 0x40000000u &&
                            parent < 0xEFFFFF00u
                            ? host.MemoryRead8(parent + 0xECu) : 0;
                        if (n <= 16 || n % 4096 == 0) {
                            LOGI("[EDITLAYOUT] %s #%u object=%08X layout=%u"
                                 " source=%08X cache=%08X global=%08X"
                                 " arg8=%08X parent=%08X pflag=%u lr=%08X",
                                 site.name, n, object, length,
                                 host.MemoryRead32(object + 0xE8u),
                                 host.MemoryRead32(object + 0x48u),
                                 jit.Regs()[10],
                                 jit.Regs()[8], parent, parent_flag,
                                 jit.Regs()[14]);
                            if (site.kind == 1) {
                                const uint32_t line = host.MemoryRead32(
                                    object + 0xE8u);
                                if (line >= 0x40000000u &&
                                    line < 0xEFFFFFC8u) {
                                    LOGI("[EDITLINE] #%u object=%08X line=%08X"
                                         " words=%08X,%08X,%08X,%08X,"
                                         "%08X,%08X,%08X,%08X,"
                                         "%08X,%08X,%08X,%08X,"
                                         "%08X,%08X",
                                         n, object, line,
                                         host.MemoryRead32(line),
                                         host.MemoryRead32(line + 4u),
                                         host.MemoryRead32(line + 8u),
                                         host.MemoryRead32(line + 12u),
                                         host.MemoryRead32(line + 16u),
                                         host.MemoryRead32(line + 20u),
                                         host.MemoryRead32(line + 24u),
                                         host.MemoryRead32(line + 28u),
                                         host.MemoryRead32(line + 32u),
                                         host.MemoryRead32(line + 36u),
                                         host.MemoryRead32(line + 40u),
                                         host.MemoryRead32(line + 44u),
                                         host.MemoryRead32(line + 48u),
                                         host.MemoryRead32(line + 52u));
                                }
                            }
                        }
                        if (site.kind == 0) {
                            jit.Regs()[3] = length;
                        } else if (site.kind == 1) {
                            jit.Regs()[13] = arm32::PushRegisters(
                                jit.Regs()[13],
                                static_cast<uint16_t>(site.expected & 0xFFFFu),
                                [&jit](unsigned reg) { return jit.Regs()[reg]; },
                                [&host](uint32_t at, uint32_t value) {
                                    host.MemoryWrite32(at, value);
                                });
                        } else if (site.kind == 2 || site.kind == 3) {
                            jit.Regs()[3] = host.MemoryRead32(object + 0x20u);
                        } else {
                            jit.Regs()[3] = host.MemoryRead32(
                                jit.Regs()[13] + 0x34u);
                        }
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

#endif // Font and text rendering observers

        // [DOINIT] SpriteInstance::doInitActions entry (0xfddde4, PUSH
        // {R4-R10,LR} = 8 words): the devirt check vtable[38] ==
        // getMovieDefinition fails and BLX R2 jumps into a gameswf string.
        // Dump the object + vtable slot to split object-UAF vs
        // corrupted-static-vtable.
        {
            constexpr uint32_t de = 0x40000000u + 0xfddde4u;
            constexpr uint32_t kDoInitExpected = 0xE92D47F0u;
            const uint32_t do_init_actual = MemoryRead32(de);
            if (do_init_actual != kDoInitExpected) {
                LOGE("[DOINIT] refusing stale probe: expected %08X, found %08X",
                     kDoInitExpected, do_init_actual);
            } else {
            uint32_t t = m_thunk_manager->RegisterThunk("probe_doinit",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    uint32_t th = jit.Regs()[0];
                    if (th < 0x100u) {
                        // null sprite: the body would fault at LDR r2,[r4];
                        // skip entirely (nothing to initialize)
                        static std::atomic<uint32_t> zn{0};
                        uint32_t zk = zn.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (zk <= 6 || (zk % 1000) == 0)
                            LOGE("[DOINIT] #%u NULL this - skipped (lr=%08X)",
                                 zk, jit.Regs()[14]);
                        jit.Regs()[15] = jit.Regs()[14] & ~1u;
                        return;
                    }
                    uint32_t vt = host.MemoryRead32(th);
                    uint32_t sl = vt > 0x100u ? host.MemoryRead32(vt + 0x98) : 0;
                    uint32_t gmd = 0x40000000u + 0xFE0E90u;
                    // [DOINIT-FIX] the devirt compares vtable[38] against
                    // getMovieDefinition; on flaky boots the slot holds
                    // garbage and the else-branch BLX jumps into a string.
                    // The sprite is always a plain SpriteInstance here, so
                    // repair BOTH devirt slots (38=getMovieDefinition,
                    // 23=getEnvironment 0xFDD65C) in the vtable itself.
                    if (vt > 0x100u && vt < 0x41A00000u) {
                        if (sl != gmd) {
                            host.MemoryWrite32(vt + 0x98, gmd);
                            static std::atomic<uint32_t> fn{0};
                            uint32_t fk = fn.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (fk <= 8)
                                LOGE("[DOINIT-FIX] #%u vt=%08X slot38 %08X -> %08X",
                                     fk, vt, sl, gmd);
                        }
                        uint32_t ge = host.MemoryRead32(vt + 0x5C);
                        uint32_t genv = 0x40000000u + 0xFDD65Cu;
                        if (ge != genv) {
                            host.MemoryWrite32(vt + 0x5C, genv);
                            static std::atomic<uint32_t> gn{0};
                            uint32_t gk = gn.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (gk <= 8)
                                LOGE("[DOINIT-FIX] #%u vt=%08X slot23 %08X -> %08X",
                                     gk, vt, ge, genv);
                        }
                    }
                    if (k <= 8 || (k % 500) == 0)
                        LOGE("[DOINIT] #%u this=%08X vt=%08X slot38=%08X exp=%08X %s",
                             k, th, vt, sl, gmd,
                             sl == gmd ? "OK" : "MISMATCH");
                    // Observe, but do not mutate, the original init-action
                    // list. Clearing it hid a possible AS2 script and a
                    // later short-return prevented the natural teardown.
                    const uint32_t actions = host.MemoryRead32(th + 312u);
                    if (actions) {
                        static std::atomic<uint32_t> listed{0};
                        const uint32_t observed = listed.fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        if (observed <= 12 || observed % 500 == 0) {
                            const uint32_t movie = host.MemoryRead32(th + 268u);
                            LOGI("[DOINIT-LIST] #%u call=%u this=%08X"
                                 " actions=%08X movie=%08X lr=%08X",
                                 observed, k, th, actions, movie,
                                 jit.Regs()[14]);
                        }
                    }
                    // Exact PUSH {R4-R10,LR} (8 words).
                    uint32_t sp = jit.Regs()[13] - 32;
                    for (int i = 0; i < 7; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 28, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            const uint32_t replacement =
                0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu);
            MemoryWrite32(de, replacement);
            InvalidateGuestCode(de, sizeof(uint32_t));
            g_probe_rewrites.push_back({de, replacement});
            LOGI("[DOINIT] probe installed at 0xfddde4");
            }
        }

        // [TEXGUARD] MenuManager::getTexture (0x5B6520, BLX R3 = vtable
        // slot +0x24 of the driver object at [R11+0x35C]): during the movie
        // parse the texture-creation slot is garbage -> UndefinedInstruction
        // at the target. Guard: emulate the BLX when the slot looks like
        // code, skip the call (return null ITexture) otherwise -- the movie
        // will show without its textures instead of dying.
        {
            uint32_t site = 0x40000000u + 0x5B6520u;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_texguard",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    uint32_t r3 = jit.Regs()[3];
                    bool ok = r3 >= 0x40000000u && r3 < 0x41A00000u;
                    static std::atomic<uint32_t> n{0};
                    uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (ok) {
                        jit.Regs()[14] = 0x40000000u + 0x5B6524u;
                        jit.Regs()[15] = r3 & ~1u;
                        jit.SetCpsr((jit.Cpsr() & ~0x20u) |
                                    ((r3 & 1u) ? 0x20u : 0u));
                    } else {
                        jit.Regs()[0] = 0;  // no texture
                        jit.Regs()[15] = 0x40000000u + 0x5B6524u;
                        jit.SetCpsr(jit.Cpsr() & ~0x20u);
                        if (k <= 12)
                            LOGE("[TEXGUARD] #%u skipped bad slot r3=%08X", k, r3);
                    }
                });
            MemoryWrite32(site, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[TEXGUARD] probe installed at 0x5B6520");
        }

        // [APPFIX] glf::AndroidUpdate (0x1417D1C, PUSH {R4,LR}): the frame
        // pump does obj=[GOT 0x179E67C]; vtable=[obj]; BLX vtable[9]. After
        // the menu movie's entry scripts run, the App object's vptr turns
        // into garbage (0x8400B0) and every frame dies in the relay ->
        // init-retry storm. Capture the first valid vptr and auto-repair.
        {
            uint32_t site = 0x40000000u + 0x1417D1Cu;
            uint32_t t = m_thunk_manager->RegisterThunk("probe_appfix",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    // The GOT holds a POINTER TO the holder variable; the
                    // App object is *holder (heap-allocated by glf init).
                    uint32_t holder = host.MemoryRead32(0x4179E67Cu);
                    uint32_t obj = holder > 0x1000u
                        ? host.MemoryRead32(holder) : 0;
                    if (obj > 0x1000u) {
                        uint32_t vt = host.MemoryRead32(obj);
                        static uint32_t good_obj = 0, good_vt = 0;
                        static std::atomic<uint32_t> n{0};
                        uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                        bool valid = vt >= 0x40000000u && vt < 0x41A00000u &&
                                     host.MemoryRead32(vt) >= 0x40000000u;
                        if (obj != good_obj) {
                            // new object in the holder (re-init): re-capture,
                            // never repair an object we did not fingerprint
                            if (valid) {
                                good_obj = obj; good_vt = vt;
                                if (k <= 4)
                                    LOGI("[APPFIX] capture obj=%08X vt=%08X", obj, vt);
                            }
                        } else if (valid) {
                            if (k <= 4 || (k % 2000) == 0)
                                LOGI("[APPFIX] #%u obj=%08X vt=%08X ok", k, obj, vt);
                        } else if (good_vt) {
                            host.MemoryWrite32(obj, good_vt);
                            static std::atomic<uint32_t> r{0};
                            uint32_t rk = r.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (rk <= 12 || (rk % 1000) == 0)
                                LOGE("[APPFIX] #%u REPAIRED obj=%08X vt %08X -> %08X",
                                     rk, obj, vt, good_vt);
                        }
                    }
                    // replicate: PUSH {R4, LR} (2 words)
                    uint32_t sp = jit.Regs()[13] - 8;
                    host.MemoryWrite32(sp, jit.Regs()[4]);
                    host.MemoryWrite32(sp + 4, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
            MemoryWrite32(site, 0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu));
            LOGI("[APPFIX] probe installed at 0x1417D1C");
        }

        // [SWFFREE-GUARD] gameswf::free_internal (0xF49300, PUSH
        // {R4-R6,LR}): the menu movie's String destructors call it with a
        // near-null buffer pointer (heap-flag set but pointer unset), and
        // the refcount decrements inside land at absolute guest 0x4/0x8/
        // 0x18/0x1C -- clobbering the exit traps and low memory (the
        // LOWMEM-W / PARKDUMP signature), eventually jumping through the
        // trashed pointer (lr=0xFFFE0000 park). Skip frees of near-null
        // pointers entirely.
        {
            uint32_t site = 0x40000000u + 0xF49300u;
            const uint32_t expected = 0xE92D4070u; // push {r4-r6,lr}
            const uint32_t actual = MemoryRead32(site);
            if (actual != expected) {
                LOGE("[SWFFREE-GUARD] refusing stale probe: expected %08X, found %08X",
                     expected, actual);
            } else {
                uint32_t t = m_thunk_manager->RegisterThunk("probe_swffree",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    uint32_t p = jit.Regs()[0];
                    if ((jit.Regs()[14] & ~1u) == 0x41072010u) {
                        const uint32_t sp = jit.Regs()[13];
                        const uint32_t caller_lr = host.MemoryRead32(sp + 36u);
                        tl_findclass_dropref_trace.free_seen = true;
                        tl_findclass_dropref_trace.free_sp = sp;
                        tl_findclass_dropref_trace.free_pointer = p;
                        tl_findclass_dropref_trace.free_size = jit.Regs()[1];
                        LOGE("[FREE-INTERNAL-FINDCLASS] p=%08X size=%08X sp=%08X caller_lr=%08X",
                             p, jit.Regs()[1], sp, caller_lr);
                    }
                    if (p < 0x100000u) {  // 1 MB: the refcount header sits at
                        // p-0xC, so even p just above 0 trashes low memory
                        static std::atomic<uint32_t> n{0};
                        uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 24 || (k % 1000) == 0)
                            LOGE("[SWFFREE-GUARD] #%u skipped near-null free p=%08X lr=%08X",
                                 k, p, jit.Regs()[14]);
                        // one-shot forensic dump: the garbage LR proves wild
                        // execution; the full register file + guest stack
                        // names where control flow derailed before this.
                        if (k == 1 && host.GetGuestMemoryBase()) {
                            uint32_t spv = jit.Regs()[13];
                            char st[400]; int o = 0;
                            for (int i = 0; i < 26 && o < (int)sizeof(st) - 12; ++i)
                                o += snprintf(st + o, sizeof(st) - o,
                                              " %02X:%08X", i * 4,
                                              host.MemoryRead32(spv + i * 4));
                            LOGE("[WILD] r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X sp=%08X stk:%s",
                                 jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                                 jit.Regs()[3], jit.Regs()[4], jit.Regs()[5], spv, st);
                            LOGE("[WILD] r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X",
                                 jit.Regs()[6], jit.Regs()[7], jit.Regs()[8],
                                 jit.Regs()[9], jit.Regs()[10], jit.Regs()[11],
                                 jit.Regs()[12]);
                        }
                        jit.Regs()[0] = 0;
                        jit.Regs()[15] = jit.Regs()[14] & ~1u;
                        return;
                    }
                    // replicate: PUSH {R4-R6, LR} (4 words)
                    uint32_t sp = jit.Regs()[13] - 16;
                    for (int i = 0; i < 3; ++i)
                        host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                    host.MemoryWrite32(sp + 12, jit.Regs()[14]);
                    jit.Regs()[13] = sp;
                });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(t) & 0x00FFFFFFu);
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
                LOGI("[SWFFREE-GUARD] exact probe installed at 0xF49300");
            }
        }

        // Menu traversal must retain its original result. The removed
        // MENUSPIN/HAVISM counters accumulated across completed frames and
        // mistook ordinary repeated queries for a loop. In the measured title
        // run MENUSPIN fabricated a null menu about every 64 frames while
        // frames continued to complete in ~17 ms. Verify the original sites
        // after initialization below; use the external deadline for hangs.

        // [MEDALS-SHUNT] onAskForMedals (0x77A588): an AS native the menu
        // movie calls; it dereferences an unconstructed achievements/social
        // listener -> NULL-VCALL halt killed the frame (black screen). The
        // medals UI is irrelevant offline; return immediately.
        {
            uint32_t m = 0x40000000u + 0x77A588u;
            LOGI("[MEDALS-SHUNT] shunting onAskForMedals at 0x77A588 (was %08X)",
                 MemoryRead32(m));
            MemoryWrite32(m, 0xE12FFF1Eu);  // bx lr
        }

        // [NATIVES] log each menu-movie native call during boot. Entry
        // probes replicate the first instruction; natives run normally.
        {
            struct NP { const char* name; uint32_t site; int kind; };
            const NP nps[] = {
                {"NativeIsAndroid",   0x5728B0u, 0},
                {"NativeIsFlashHD",   0x58A35Cu, 1},
                {"NativeIsFirstTimeInMainMenu", 0x58B2A8u, 1},
            };
            for (const NP& np : nps) {
                std::string nnm = std::string("probe_nat_") + np.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk(nnm.c_str(),
                    [nnm, cnt, kind = np.kind, site = np.site](
                        Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t kk = cnt->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (kk <= 6 || (kk % 500) == 0)
                            LOGE("[NATIVES] %s #%u fn.env(r0)=%08X",
                                 nnm.c_str(), kk, jit.Regs()[0]);
                        if (kind == 0) {
                            // LDR R0,[R0]
                            jit.Regs()[0] = host.MemoryRead32(jit.Regs()[0]);
                        } else {
                            // LDR R3,[PC,#0x10] -> literal at site+8+0x10
                            jit.Regs()[3] = host.MemoryRead32(
                                0x40000000u + site + 0x18u);
                        }
                    });
                MemoryWrite32(0x40000000u + np.site,
                              0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[NATIVES] probe installed at %s (0x%X)", np.name, np.site);
            }

            // Leave MenuFlashBase::onClassInitialized's real PUSH intact.
            // The former CLASSINIT logger saved R4-R11,LR (36 bytes), but
            // the guest instruction is E92D47F0: R4-R10,LR (32 bytes).
            // Its matching POP loaded the extra saved R11 as PC, returning
            // into a heap object instead of to the AS3 class initializer.

            // [ADV72] Does anything drive gameswf per frame? Root::advance
            // (0xFCBD9C) is the only entry into the AS3 timeline; if it
            // never fires the movie stays on frame 1 (eternal preloader,
            // no class init, no natives). Count the driver candidates:
            // RenderFX::update (probed at the PUSH, +4 -- the VMOV before
            // it already ran), MenuManager::Draw, Root::advance,
            // RenderFX::render. Each probe replicates the PUSH prologue.
            {
                struct ADV { const char* name; uint32_t site; uint32_t words; };
                const ADV advs[] = {
                    {"rfx_update",   0x100B13Cu, 7},  // PUSH {R4-R9,LR}
                    {"mm_draw",      0x5CC360u,  9},  // PUSH {R4-R11,LR}
                    {"root_advance", 0xFCBD9Cu,  9},  // PUSH {R4-R11,LR}
                    {"rfx_render",   0x100CF1Cu, 4},  // PUSH {R4-R6,LR}
                };
                for (const ADV& av : advs) {
                    auto c = std::make_shared<std::atomic<uint32_t>>(0);
                    std::string nm2 = std::string("probe_") + av.name;
                    uint32_t tt = m_thunk_manager->RegisterThunk(nm2.c_str(),
                        [nm2, c, words = av.words](Dynarmic::A32::Jit& jit,
                                                   DynarmicHost& host) {
                            uint32_t k =
                                c->fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 10 || (k % 500) == 0)
                                LOGE("[ADV72] %s #%u r0=%08X r1=%08X r2=%08X",
                                     nm2.c_str(), k, jit.Regs()[0],
                                     jit.Regs()[1], jit.Regs()[2]);
                            // replicate PUSH {R4..R(n),LR}
                            uint32_t sp = jit.Regs()[13] - words * 4;
                            for (uint32_t i = 0; i + 1 < words; ++i)
                                host.MemoryWrite32(sp + i * 4,
                                                   jit.Regs()[4 + i]);
                            host.MemoryWrite32(sp + (words - 1) * 4,
                                               jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    MemoryWrite32(0x40000000u + av.site,
                                  0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                    LOGI("[ADV72] probe installed: %s at 0x%X", av.name,
                         av.site);
                }

            // [RH] RenderHandler draw-path counters. GLSTAT showed
            // glDrawArrays frozen at 63 (init only): either the movie
            // display list is empty (draw never fires) or the glitch
            // submission path is dead (draw fires, GL does not).
            {
                struct RHP { const char* name; uint32_t site; uint32_t words; };
                const RHP rhps[] = {
                    {"rh_draw",   0xFBB1B4u, 9},  // PUSH {R4-R11,LR}
                    {"rh_flush",  0xFBABB8u, 2},  // PUSH {R4,LR}
                };
                for (const RHP& rp : rhps) {
                    auto c = std::make_shared<std::atomic<uint32_t>>(0);
                    std::string nm3 = std::string("probe_") + rp.name;
                    uint32_t tt = m_thunk_manager->RegisterThunk(nm3.c_str(),
                        [nm3, c, words = rp.words](Dynarmic::A32::Jit& jit,
                                                   DynarmicHost& host) {
                            uint32_t k =
                                c->fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 12 || (k % 2000) == 0)
                                LOGE("[RH] %s #%u r0=%08X r1=%08X lr=%08X",
                                     nm3.c_str(), k, jit.Regs()[0],
                                     jit.Regs()[1], jit.Regs()[14] & ~1u);
                            uint32_t sp = jit.Regs()[13] - words * 4;
                            for (uint32_t i = 0; i + 1 < words; ++i)
                                host.MemoryWrite32(sp + i * 4,
                                                   jit.Regs()[4 + i]);
                            host.MemoryWrite32(sp + (words - 1) * 4,
                                               jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    MemoryWrite32(0x40000000u + rp.site,
                                  0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                    LOGI("[RH] probe installed: %s at 0x%X", rp.name,
                         rp.site);
                }

            // [DISP] display-walk counters: RenderFX::beginDisplay ->
            // Root::beginDisplay / Root::display, and the glitch scene-graph
            // visit SceneNode::onRegisterSceneNodeInternal. rh_draw==0 with
            // rfx_render firing means the walk dies before any primitive.
            {
                struct DP { const char* name; uint32_t site; uint32_t words; };
                const DP dps[] = {
                    {"root_display",   0xFCC2F0u, 2},  // PUSH {R4,LR}
                    {"scene_regnode",  0xFCE1C4u, 7},  // PUSH {R4-R9,LR}
                    {"root_begindisp", 0xFCB45Cu, 7},  // PUSH {R4-R9,LR}
                    {"rfx_begindisp",  0x100CE8Cu, 2}, // PUSH {R4,LR}
                };
                for (const DP& dp : dps) {
                    auto c = std::make_shared<std::atomic<uint32_t>>(0);
                    std::string nm4 = std::string("probe_") + dp.name;
                    uint32_t tt = m_thunk_manager->RegisterThunk(nm4.c_str(),
                        [nm4, c, words = dp.words](Dynarmic::A32::Jit& jit,
                                                   DynarmicHost& host) {
                            uint32_t k =
                                c->fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 12 || (k % 2000) == 0)
                                LOGE("[DISP] %s #%u r0=%08X r1=%08X lr=%08X",
                                     nm4.c_str(), k, jit.Regs()[0],
                                     jit.Regs()[1], jit.Regs()[14] & ~1u);
                            uint32_t sp = jit.Regs()[13] - words * 4;
                            for (uint32_t i = 0; i + 1 < words; ++i)
                                host.MemoryWrite32(sp + i * 4,
                                                   jit.Regs()[4 + i]);
                            host.MemoryWrite32(sp + (words - 1) * 4,
                                               jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    MemoryWrite32(0x40000000u + dp.site,
                                  0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                    LOGI("[DISP] probe installed: %s at 0x%X", dp.name,
                         dp.site);
                }

            // Visibility belongs to the authored menu/timeline. Do not turn
            // hide requests into show requests or animate hidden subtrees.
            // CharacterHandle::setVisible executes its original guest body.

            // [LOAD] content-pipeline counters: MenuManager::LoadSWF (the
            // per-menu SWF+atlas loader), MenuManager::RegisterMenu,
            // MenuFX::setMenu. TexImage2D==10 at boot says LoadSWF never
            // reached the texture stage: confirm from the guest side.
            {
                struct LP { const char* name; uint32_t site; uint32_t words; };
                const LP lps[] = {
                    {"mm_loadswf", 0x5E10F4u, 9},  // PUSH {R4-R11,LR} (guess)
                    {"mm_regmenu", 0x5CAF70u, 9},  // PUSH {R4-R11,LR} (guess)
                    {"fx_setmenu", 0x1008664u, 9}, // PUSH {R4-R11,LR} (guess)
                };
                for (const LP& lp : lps) {
                    // verify the prologue push reg-mask before arming; if it
                    // does not start with a PUSH, log and skip.
                    uint32_t op0 = MemoryRead32(0x40000000u + lp.site);
                    bool is_push = (op0 & 0xFFFF0000u) == 0xE92D0000u;
                    uint32_t words = 0;
                    if (is_push) {
                        uint32_t regs = op0 & 0xFFFFu;
                        words = 1 + ((regs & 0xFF00u) ? 8 : 0) +
                                (((regs >> 4) & 0x7F)) + ((regs & 2) ? 1 : 0) +
                                ((regs & 4) ? 1 : 0) + ((regs & 1) ? 1 : 0) +
                                ((regs & 0x4000u) ? 1 : 0);
                        // crude: count set bits in low 16
                        words = 0;
                        for (int b = 0; b < 16; ++b)
                            if (regs & (1u << b)) ++words;
                    }
                    if (!is_push || words < 2 || words > 9) {
                        LOGE("[LOAD] %s at 0x%X NOT ARMED: op0=%08X",
                             lp.name, lp.site, op0);
                        continue;
                    }
                    auto c = std::make_shared<std::atomic<uint32_t>>(0);
                    std::string nm6 = std::string("probe_") + lp.name;
                    uint32_t tt = m_thunk_manager->RegisterThunk(nm6.c_str(),
                        [nm6, c, words](Dynarmic::A32::Jit& jit,
                                        DynarmicHost& host) {
                            uint32_t k =
                                c->fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 10 || (k % 200) == 0)
                                LOGE("[LOAD] %s #%u r0=%08X r1=%08X r2=%08X",
                                     nm6.c_str(), k, jit.Regs()[0],
                                     jit.Regs()[1], jit.Regs()[2]);
                            uint32_t sp = jit.Regs()[13] - words * 4;
                            for (uint32_t i = 0; i + 1 < words; ++i)
                                host.MemoryWrite32(sp + i * 4,
                                                   jit.Regs()[4 + i]);
                            host.MemoryWrite32(sp + (words - 1) * 4,
                                               jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    MemoryWrite32(0x40000000u + lp.site,
                                  0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                    LOGI("[LOAD] probe installed: %s at 0x%X words=%u",
                         lp.name, lp.site, words);
                }
            }

            // [FSCMD] MenuBase::onFSCommand(this, cmd, args): the SWF ->
            // C++ dialogue. The 770 preloader must announce completion via
            // fscommand; log everything it says.
            {
                uint32_t st = 0x40000000u + 0x5D609Cu;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_fscmd",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        char cb[40] = {0}, ab[48] = {0};
                        for (int q = 0; q < 39 && 1; ++q) {
                            uint32_t ch = host.MemoryRead8(
                                jit.Regs()[1] + q);
                            if (!ch) break;
                            cb[q] = (char)ch;
                        }
                        if (jit.Regs()[2] > 0x1000u)
                            for (int q = 0; q < 47; ++q) {
                                uint32_t ch = host.MemoryRead8(
                                    jit.Regs()[2] + q);
                                if (!ch) break;
                                ab[q] = (char)ch;
                            }
                        if (k <= 40 || (k % 200) == 0)
                            LOGE("[FSCMD] #%u menu=%08X cmd='%s' args='%s'",
                                 k, jit.Regs()[0], cb, ab);
                        // replicate PUSH {R4-R11,LR} (9 words)
                        uint32_t sp = jit.Regs()[13] - 36;
                        for (int i = 0; i < 8; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[FSCMD] probe installed at 0x5D609C");
            }

            // [EVDISP] CharacterHandle::dispatchEvent(handle, const
            // String& name, data, n): log every C++->AS3 event name so the
            // missing doc-class trigger becomes visible.
            {
                uint32_t st = 0x40000000u + 0xF71FF4u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_evdisp",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        uint32_t sp = jit.Regs()[1];
                        char nb[40] = {0};
                        if (sp > 0x1000u) {
                            uint32_t f0 = host.MemoryRead8(sp);
                            const char* p;
                            if (f0 == 0xFF)
                                p = reinterpret_cast<const char*>(
                                    host.GetGuestMemoryBase() +
                                    host.MemoryRead32(sp + 4));
                            else
                                p = reinterpret_cast<const char*>(
                                    host.GetGuestMemoryBase() + sp + 1);
                            for (int q = 0; q < 39 && p[q]; ++q) nb[q] = p[q];
                        }
                        if (k <= 40 || (k % 500) == 0)
                            LOGE("[EVDISP] #%u h=%08X ev='%s' lr=%08X",
                                 k, jit.Regs()[0], nb,
                                 jit.Regs()[14] & ~1u);
                        // replicate PUSH {R4-R11,LR} (9 words)
                        uint32_t newsp = jit.Regs()[13] - 36;
                        for (int i = 0; i < 8; ++i)
                            host.MemoryWrite32(newsp + i * 4,
                                               jit.Regs()[4 + i]);
                        host.MemoryWrite32(newsp + 32, jit.Regs()[14]);
                        jit.Regs()[13] = newsp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[EVDISP] probe installed at 0xF71FF4");
            }

            // [LOADSYS] AS3 loader pipeline counters: flash.display.Loader
            // load entry, ASLoaderManager addRequest/process. Decides
            // whether SwfMainmenu.init() runs and where the sub-SWF loads
            // stall. Generic push replication from the actual regmask.
            {
                struct LSP { const char* name; uint32_t site; };
                const LSP lps[] = {
                    {"asloader_load",  0x1047358u},
                    {"ldrmgr_addreq",  0x10735F8u},
                    {"ldrmgr_process", 0x10733A8u},
                };
                for (const LSP& lp : lps) {
                    uint32_t op0 = MemoryRead32(0x40000000u + lp.site);
                    if ((op0 & 0xFFFF0000u) != 0xE92D0000u) {
                        LOGE("[LOADSYS] %s at 0x%X NOT A PUSH: %08X",
                             lp.name, lp.site, op0);
                        continue;
                    }
                    uint32_t regmask = op0 & 0xFFFFu;
                    uint32_t words = 0;
                    for (int b = 0; b < 16; ++b)
                        if (regmask & (1u << b)) ++words;
                    auto c = std::make_shared<std::atomic<uint32_t>>(0);
                    uint32_t mask = regmask;
                    std::string nm7 = std::string("probe_") + lp.name;
                    uint32_t tt = m_thunk_manager->RegisterThunk(nm7.c_str(),
                        [nm7, c, words, mask](Dynarmic::A32::Jit& jit,
                                              DynarmicHost& host) {
                            uint32_t k =
                                c->fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 8 || (k % 200) == 0)
                                LOGE("[LOADSYS] %s #%u r0=%08X r1=%08X "
                                     "r2=%08X lr=%08X",
                                     nm7.c_str(), k, jit.Regs()[0],
                                     jit.Regs()[1], jit.Regs()[2],
                                     jit.Regs()[14] & ~1u);
                            uint32_t sp = jit.Regs()[13] - words * 4;
                            uint32_t idx = 0;
                            for (uint32_t b2 = 0; b2 < 16; ++b2) {
                                if (mask & (1u << b2)) {
                                    host.MemoryWrite32(sp + idx * 4,
                                                       jit.Regs()[b2]);
                                    ++idx;
                                }
                            }
                            jit.Regs()[13] = sp;
                        });
                    MemoryWrite32(0x40000000u + lp.site,
                                  0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                    LOGI("[LOADSYS] probe installed: %s at 0x%X words=%u",
                         lp.name, lp.site, words);
                }
                // [CHAIN2] ASDisplayObjectContainer::addChild (0x1046AB4,
                // PUSH {R4-R11,LR} 9 words): pinpoints where ASLoader::load
                // stops. do_init (0xFDDDE4) REMOVED: its push-replication
                // wedged the JIT inside doInitActions itself (watchdog:
                // stuck in thunk=probe_do_init, entry 0x41008E2C) and killed
                // the shell parse in every 20:xx boot.
                {
                    struct C2 { const char* name; uint32_t site; uint32_t words; };
                    const C2 cps[] = {
                        {"add_child", 0x1046AB4u, 9},
                    };
                    for (const C2& cp : cps) {
                        auto c3 = std::make_shared<std::atomic<uint32_t>>(0);
                        std::string nm9 = std::string("probe_") + cp.name;
                        uint32_t tt5 = m_thunk_manager->RegisterThunk(
                            nm9.c_str(),
                            [nm9, c3, words = cp.words](
                                Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                                uint32_t k = c3->fetch_add(
                                    1, std::memory_order_relaxed) + 1;
                                if (k <= 10 || (k % 500) == 0)
                                    LOGE("[CHAIN2] %s #%u r0=%08X r1=%08X",
                                         nm9.c_str(), k, jit.Regs()[0],
                                         jit.Regs()[1]);
                                uint32_t sp = jit.Regs()[13] - words * 4;
                                for (uint32_t i = 0; i + 1 < words; ++i)
                                    host.MemoryWrite32(sp + i * 4,
                                                       jit.Regs()[4 + i]);
                                host.MemoryWrite32(sp + (words - 1) * 4,
                                                   jit.Regs()[14]);
                                jit.Regs()[13] = sp;
                            });
                        MemoryWrite32(0x40000000u + cp.site,
                                      0xEF000000u | (MemoryRead32(tt5) & 0x00FFFFFFu));
                    }
                }
                // [CREATEMOVIE] Player::createMovie(url): log every movie
                // file the loader resolves (this is where the sub-SWF opens
                // must appear).
                {
                    uint32_t cm_site = 0xFB23B8u; // PUSH {R4-R11,LR}
                    auto cc = std::make_shared<std::atomic<uint32_t>>(0);
                    uint32_t tt2 = m_thunk_manager->RegisterThunk("probe_cm",
                        [cc](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                            uint32_t k =
                                cc->fetch_add(1, std::memory_order_relaxed) + 1;
                            char pb[64] = {0};
                            if (jit.Regs()[1] > 0x1000u)
                                for (int z = 0; z < 63; ++z) {
                                    uint32_t ch = host.MemoryRead8(
                                        jit.Regs()[1] + z);
                                    if (!ch) break;
                                    pb[z] = (char)ch;
                                }
                            if (k <= 20 || (k % 100) == 0)
                                LOGE("[CREATEMOVIE] #%u url='%s' lr=%08X",
                                     k, pb, jit.Regs()[14] & ~1u);
                            uint32_t sp = jit.Regs()[13] - 36;
                            for (int i2 = 0; i2 < 8; ++i2)
                                host.MemoryWrite32(sp + i2 * 4,
                                                   jit.Regs()[4 + i2]);
                            host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                            jit.Regs()[13] = sp;
                        });
                    MemoryWrite32(0x40000000u + cm_site,
                                  0xEF000000u | (MemoryRead32(tt2) & 0x00FFFFFFu));
                    LOGI("[CREATEMOVIE] probe installed at 0xFB23B8");
                }

                // Leave createSpriteInstance (0xFAA6B8) and Request::Request
                // (0x10567DC) intact. The former LOADSTAGE callbacks replaced
                // their PUSH instructions without executing them. Their real
                // epilogues then popped unsaved registers/PC, leaking 28/24
                // bytes of stack and returning into caller data.

                // [GWLOG] gameswf::logMsg (0xF97AB4): all internal errors
                // funnel here. Entry probe with generic push replication.
                {
                    uint32_t lm_site = 0xF97AB4u;
                    uint32_t op0 = MemoryRead32(0x40000000u + lm_site);
                    uint32_t lmask = op0 & 0xFFFFu;
                    uint32_t lwords = 0;
                    for (int b = 0; b < 16; ++b)
                        if (lmask & (1u << b)) ++lwords;
                    auto lc = std::make_shared<std::atomic<uint32_t>>(0);
                    uint32_t lt = m_thunk_manager->RegisterThunk("probe_gwlog",
                        [lc, lmask, lwords](Dynarmic::A32::Jit& jit,
                                            DynarmicHost& host) {
                            uint32_t k =
                                lc->fetch_add(1, std::memory_order_relaxed) + 1;
                            char fb[80] = {0};
                            if (jit.Regs()[0] > 0x1000u)
                                for (int z = 0; z < 79; ++z) {
                                    uint32_t ch = host.MemoryRead8(
                                        jit.Regs()[0] + z);
                                    if (!ch || ch > 126) break;
                                    fb[z] = (char)ch;
                                }
                            if (k <= 60 || (k % 200) == 0)
                                LOGE("[GWLOG] #%u '%s' r1=%08X r2=%08X",
                                     k, fb, jit.Regs()[1], jit.Regs()[2]);
                            uint32_t sp = jit.Regs()[13] - lwords * 4;
                            uint32_t idx = 0;
                            for (uint32_t b2 = 0; b2 < 16; ++b2) {
                                if (lmask & (1u << b2)) {
                                    host.MemoryWrite32(sp + idx * 4,
                                                       jit.Regs()[b2]);
                                    ++idx;
                                }
                            }
                            jit.Regs()[13] = sp;
                        });
                    LOGI("[GWLOG] probe installed at 0xF97AB4 mask=%04X words=%u",
                         lmask, lwords);
                }
            }

            }
            }
            }

            // ASEnvironment::~ASEnvironment executes unmodified. The former
            // ENV74 workaround zeroed 0x110 bytes of a 0xD8-byte object at
            // doInitActions SP+0x34. That overwrote its canary at SP+0x10C,
            // all saved registers, saved LR, and 20 bytes of the caller.

            // [AS3RUN] AS3Function::execute (0xF5CDA0, PUSH {R4-R11,LR}) --
            // did the AS3 interpreter actually run (entry script)?
            {
                uint32_t st = 0x40000000u + 0xF5CDA0u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_as3run",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 16 || (k % 4096) == 0)
                            LOGE("[AS3RUN] #%u fn=%08X r1=%08X r2=%08X "
                                 "r3=%08X lr=%08X",
                                 k, jit.Regs()[0], jit.Regs()[1],
                                 jit.Regs()[2], jit.Regs()[3],
                                 jit.Regs()[14] & ~1u);
                        // replicate PUSH {R4-R11,LR} (9 words)
                        uint32_t sp = jit.Regs()[13] - 36;
                        for (int i = 0; i < 8; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[AS3RUN] probe installed at 0xF5CDA0");
            }

            // [TRAITS74] initializeTraitsMapping entry (0x106E39C, PUSH
            // {R4-R11,LR}): the post-corruption freeze spins in its hash
            // chain walk; count invocations and the objectinfo args.
            {
                uint32_t st = 0x40000000u + 0x106E39Cu;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_traits",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 16 || (k % 4096) == 0)
                            LOGE("[TRAITS74] #%u abc=%08X oi=%08X oi2=%08X "
                                 "b=%u lr=%08X",
                                 k, jit.Regs()[0], jit.Regs()[1],
                                 jit.Regs()[2], jit.Regs()[3],
                                 jit.Regs()[14] & ~1u);
                        // replicate PUSH {R4-R11,LR} (9 words)
                        uint32_t sp = jit.Regs()[13] - 36;
                        for (int i = 0; i < 8; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[TRAITS74] probe installed at 0x106E39C");
            }

            // [TRAITSFIX] initializeTraitsMapping hash-chain walk: the BNE
            // at 0x106EF08 loops until the entry key matches; a corrupt
            // traits table makes "next" indices cycle (garbage offsets wrap
            // through wild reads back onto base entries) and the step
            // thread wedges here forever. Emulate the BNE; if one
            // (table,key) walk exceeds 200k iterations, force the loop-exit
            // path so class init finishes.
            {
                uint32_t st = 0x40000000u + 0x106EF08u;
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_traitsfix",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                        static uint32_t last_r1 = 0, last_r0 = 0;
                        static uint32_t iter = 0;
                        uint32_t r0 = jit.Regs()[0], r1 = jit.Regs()[1];
                        if (r1 != last_r1 || r0 != last_r0) {
                            last_r1 = r1;
                            last_r0 = r0;
                            iter = 0;
                        }
                        constexpr uint32_t kZ = 0x40000000u;
                        bool z_set = (jit.Cpsr() & kZ) != 0;
                        if (++iter > 200000u) {
                            static std::atomic<uint32_t> n{0};
                            uint32_t k =
                                n.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 8 || (k % 1000) == 0)
                                LOGE("[TRAITSFIX] broke hash walk #%u "
                                     "table=%08X key=%08X",
                                     k, r1, r0);
                            iter = 0;
                            jit.Regs()[15] = 0x40000000u + 0x106EF0Cu;
                            return;
                        }
                        // replicate BNE loc_106EEF4
                        jit.Regs()[15] = z_set
                                             ? (0x40000000u + 0x106EF0Cu)
                                             : (0x40000000u + 0x106EEF4u);
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[TRAITSFIX] probe installed at 0x106EF08");
            }

            // [MMUPD] MenuManager::Update entry (0x5CBDF8, PUSH {R4-R11,LR}):
            // its walk drives RenderFX::update (the AS3 enterFrame tick);
            // zero calls here would explain the frozen preloader.
            {
                uint32_t st = 0x40000000u + 0x5CBDF8u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_mmupd",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 8 || (k % 2000) == 0)
                            LOGE("[MMUPD] #%u this=%08X dt=%08X m24=%08X",
                                 k, jit.Regs()[0], jit.Regs()[1],
                                 jit.Regs()[0]
                                     ? host.MemoryRead32(jit.Regs()[0] + 24)
                                     : 0);
                        // replicate PUSH {R4-R11,LR} (9 words)
                        uint32_t sp = jit.Regs()[13] - 36;
                        for (int i = 0; i < 8; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[MMUPD] probe installed at 0x5CBDF8");
            }

            // [ASVGUARD] ASValue::dropRefs (0x1000E4C, PUSH {R3-R5,LR}):
            // the entry-script teardown leaves ASValues whose type says
            // object but whose pointer is a small integer; dropRef then
            // does a virtual call through garbage and the exception kills
            // the whole advance (Root+220 never sets, frame 1 re-runs
            // forever). Neutralize object/string values with absurd
            // pointers: zero the 12-byte value and return.
            {
                uint32_t st = 0x40000000u + 0x1000E4Cu;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_asvguard",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t v = jit.Regs()[0];
                        bool bad = false;
                        bool outside = false;
                        // The corrupt frameslot walk calls dropRefs with a
                        // garbage array pointer (0xD64CC83C seen). Anything
                        // outside the guest's real regions cannot be a
                        // value: return without touching it.
                        {
                            const bool in_heap =
                                v >= 0xB8000000u && v < 0xD0000000u;
                            const bool in_stack =
                                v >= 0x7EF00000u && v < 0x80000000u;
                            const bool in_data =
                                v >= 0x41700000u && v < 0x41820000u;
                            outside = !in_heap && !in_stack && !in_data;
                        }
                        int type = 0;
                        if (!outside) {
                            type = (int8_t)host.MemoryRead8(v);
                            if (type < -1 || type > 8) outside = true;
                        }
                        if (outside) {
                            static std::atomic<uint32_t> on{0};
                            uint32_t ok =
                                on.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (ok <= 16 || (ok % 1000) == 0)
                                LOGE("[ASVGUARD] wild this=%08X lr=%08X", v,
                                     jit.Regs()[14]);
                            jit.Regs()[0] = v;
                            jit.Regs()[15] = jit.Regs()[14] & ~1u;
                            return;
                        }
                        if (v > 0x100u && v < 0x7EFFF000u) {
                            uint32_t f1 = host.MemoryRead32(v + 4);
                            uint32_t f2 = host.MemoryRead32(v + 8);
                            // A live RefCounted object only lives in the
                            // guest heap or the image's .data/.bss; anything
                            // else (stack addresses, code, small ints) is a
                            // corrupt value whose dropRef would call through
                            // a garbage vtable.
                            auto obj_ok = [&host](uint32_t p) {
                                if (!((p >= 0xB8000000u && p < 0xD0000000u) ||
                                      (p >= 0x41700000u &&
                                       p < 0x41820000u)))
                                    return false;
                                // A real gameswf object starts with a
                                // vtable pointer into .data.rel.ro.
                                uint32_t vt = host.MemoryRead32(p);
                                return vt >= 0x41700000u &&
                                       vt < 0x41820000u;
                            };
                            if (type == 5)
                                bad = f1 != 0 && !obj_ok(f1);
                            else if (type == 6)
                                bad = f2 != 0 && !obj_ok(f2);
                            else if (type == 4)
                                bad = f1 != 0 && !obj_ok(f1) &&
                                      f1 < 0x7EF00000u;
                        }
                        if (bad) {
                            uint32_t k =
                                c->fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 16 || (k % 1000) == 0)
                                LOGE("[ASVGUARD] #%u neutralized value at "
                                     "%08X",
                                     k, v);
                            host.MemoryWrite32(v, 0);
                            host.MemoryWrite32(v + 4, 0);
                            host.MemoryWrite32(v + 8, 0);
                            jit.Regs()[0] = v;
                            jit.Regs()[15] = jit.Regs()[14] & ~1u;
                            return;
                        }
                        // replicate PUSH {R3-R5,LR} (4 words)
                        uint32_t sp = jit.Regs()[13] - 16;
                        for (int i = 0; i < 3; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[3 + i]);
                        host.MemoryWrite32(sp + 12, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[ASVGUARD] probe installed at 0x1000E4C");
            }

            // [SADISP] iFPS::SA_OnUpdate (0x8A1170, no push; starts
            // MOV R0,R1 / MOV R1,R2): the automaton's per-frame dispatch
            // into the current state's Update. Count invocations.
            {
                uint32_t st = 0x40000000u + 0x8A1170u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_sadisp",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 8 || (k % 5000) == 0)
                            LOGE("[SADISP] #%u state=%08X dt=%08X",
                                 k, jit.Regs()[1], jit.Regs()[2]);
                        // replicate MOV R0,R1 / MOV R1,R2
                        uint32_t r1 = jit.Regs()[1];
                        jit.Regs()[0] = r1;
                        jit.Regs()[1] = jit.Regs()[2];
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[SADISP] probe installed at 0x8A1170");
            }

            // [FMUPD] FlashMenu::Update (0x59EC60, PUSH {R4-R11,LR}): the
            // menu state's per-frame Update; its body calls
            // MenuManager::Update. Zero hits = the automaton dispatch is
            // dead above this point.
            {
                uint32_t st = 0x40000000u + 0x59EC60u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_fmupd",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 8 || (k % 5000) == 0)
                            LOGE("[FMUPD] #%u this=%08X dt=%08X",
                                 k, jit.Regs()[0], jit.Regs()[1]);
                        // replicate PUSH {R4-R11,LR} (9 words)
                        uint32_t sp = jit.Regs()[13] - 36;
                        for (int i = 0; i < 8; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 32, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[FMUPD] probe installed at 0x59EC60");
            }

            // HasVisibleMenu must inspect the actual menu list. The former
            // forced-true return made the update loop ignore hidden state.

            // [REGNAT] gameswf::registerNativeFunction (0xFAEF24, PUSH
            // {R4-R10,LR}): log every native the game registers (FocusGain
            // registers 45 via InitMainMenuNative).
            {
                uint32_t st = 0x40000000u + 0xFAEF24u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_regnat",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 60) {
                            uint32_t np = jit.Regs()[0];
                            char nb[40] = {0};
                            if (np > 0x1000u && host.GetGuestMemoryBase()) {
                                const char* p = reinterpret_cast<const char*>(
                                    host.GetGuestMemoryBase() + np);
                                for (size_t q = 0; q + 1 < sizeof(nb) && p[q]; ++q)
                                    nb[q] = p[q];
                            }
                            LOGE("[REGNAT] #%u '%s'", k, nb);
                        }
                        // replicate PUSH {R4-R10,LR} (8 words)
                        uint32_t sp = jit.Regs()[13] - 32;
                        for (int i = 0; i < 7; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 28, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[REGNAT] probe installed at 0xFAEF24");
            }

            // [THROW] __cxa_throw (0x149DA7C, PUSH {R4-R7,R11,LR}):
            // log every C++ exception thrown by the guest with the
            // type_info name and the throw site -- tells us exactly what
            // AS3/class-init step is failing.
            {
                constexpr uint32_t st = 0x40000000u + 0x149DA7Cu;
                constexpr uint32_t kThrowExpected = 0xE92D48F0u;
                const uint32_t throw_actual = MemoryRead32(st);
                if (throw_actual != kThrowExpected) {
                    LOGE("[THROW] refusing stale probe: expected %08X, found %08X",
                         kThrowExpected, throw_actual);
                } else {
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_throw",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 24 || (k % 500) == 0) {
                            uint32_t ti = jit.Regs()[1];
                            uint32_t np =
                                ti > 0x1000u ? host.MemoryRead32(ti + 4) : 0;
                            char nb[64] = {0};
                            if (np > 0x1000u && host.GetGuestMemoryBase()) {
                                const char* p = reinterpret_cast<const char*>(
                                    host.GetGuestMemoryBase() + np);
                                for (size_t q = 0;
                                     q + 1 < sizeof(nb) && p[q]; ++q)
                                    nb[q] = p[q];
                            }
                            LOGE("[THROW] #%u obj=%08X ti=%08X type='%s' "
                                 "lr=%08X",
                                 k, jit.Regs()[0], ti, nb,
                                 jit.Regs()[14] & ~1u);
                        }
                        // Exact PUSH {R4-R7,R11,LR} (6 words).
                        uint32_t sp = jit.Regs()[13] - 24;
                        for (int i = 0; i < 4; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 16, jit.Regs()[11]);
                        host.MemoryWrite32(sp + 20, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu);
                MemoryWrite32(st, replacement);
                InvalidateGuestCode(st, sizeof(uint32_t));
                g_probe_rewrites.push_back({st, replacement});
                LOGI("[THROW] probe installed at 0x149DA7C");
                }
            }

            // [CALLM] gameswf::call_method (0xF4D67C, PUSH {R4-R7,LR},
            // 5 words): log the method NAME (stack arg @sp+8) -- names
            // every dispatched call, including the "Native*" ones the
            // preloader is expected to make.
            {
                uint32_t st = 0x40000000u + 0xF4D67Cu;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_callm",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        uint32_t sp = jit.Regs()[13];
                        uint32_t namep =
                            sp >= 8 ? host.MemoryRead32(sp + 8) : 0;
                        char nb[44] = {0};
                        if (namep > 0x1000u && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(
                                host.GetGuestMemoryBase() + namep);
                            for (size_t q = 0; q + 1 < sizeof(nb) && p[q]; ++q)
                                nb[q] = p[q];
                        }
                        if (k <= 24 || (k % 2000) == 0)
                            if (k <= 24 || (k % 2000) == 0) {
                            uint32_t fv = jit.Regs()[2];
                            // r2 -> callee ASValue: type byte +0,
                            // payload +4. t==0 means UNDEFINED:
                            // the member never resolved.
                            uint32_t ft = fv > 0x1000u ?
                                host.MemoryRead8(fv) : 0xFFu;
                            uint32_t fvv = fv > 0x1000u ?
                                host.MemoryRead32(fv + 4) : 0;
                            LOGE("[CALLM] #%u name='%s' fv=%08X t=%u v=%08X env=%08X lr=%08X",
                                 k, nb, fv, ft, fvv, jit.Regs()[1],
                                 jit.Regs()[14] & ~1u);
                            }
                        // replicate PUSH {R4-R7,LR} (5 words)
                        uint32_t newsp = sp - 20;
                        for (int i = 0; i < 4; ++i)
                            host.MemoryWrite32(newsp + i * 4,
                                               jit.Regs()[4 + i]);
                        host.MemoryWrite32(newsp + 16, jit.Regs()[14]);
                        jit.Regs()[13] = newsp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[CALLM] probe installed at 0xF4D67C");
            }

            // [INVK] SpriteInstance::invokeConstructor (0xFDE2F0, PUSH
            // {R4-R8,LR}): runs every frame from Root::advance's first-run
            // block; reads the bound class at *(def+84) which stays 0
            // ("method is not a function"). Log the def and slot value.
            {
                uint32_t st = 0x40000000u + 0xFDE2F0u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_invk",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 8 || (k % 5000) == 0) {
                            uint32_t sp2 = jit.Regs()[0];
                            uint32_t sd2 =
                                sp2 > 0x1000u ? host.MemoryRead32(sp2 + 40) : 0;
                            uint32_t cls =
                                sd2 > 0x1000u ? host.MemoryRead32(sd2 + 84) : 0;
                            LOGE("[INVK] #%u sprite=%08X def=%08X cls84=%08X",
                                 k, sp2, sd2, cls);
                        }
                        // replicate PUSH {R4-R8,LR} (6 words)
                        uint32_t sp = jit.Regs()[13] - 24;
                        for (int i = 0; i < 5; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 20, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[INVK] probe installed at 0xFDE2F0");
            }

            // [INSTREG] CharacterDef::instanciateRegisteredClass
            // (0xF93A38, PUSH {R4-R9,LR}): the AS3 class instantiation
            // entry; zero hits = never even tried.
            {
                uint32_t st = 0x40000000u + 0xF93A38u;
                auto c = std::make_shared<std::atomic<uint32_t>>(0);
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_instreg",
                    [c](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t k =
                            c->fetch_add(1, std::memory_order_relaxed) + 1;
                        if (k <= 8 || (k % 5000) == 0)
                            LOGE("[INSTREG] #%u def=%08X sprite=%08X",
                                 k, jit.Regs()[0], jit.Regs()[1]);
                        // replicate PUSH {R4-R9,LR} (7 words)
                        uint32_t sp = jit.Regs()[13] - 28;
                        for (int i = 0; i < 6; ++i)
                            host.MemoryWrite32(sp + i * 4, jit.Regs()[4 + i]);
                        host.MemoryWrite32(sp + 24, jit.Regs()[14]);
                        jit.Regs()[13] = sp;
                    });
                MemoryWrite32(st, 0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu));
                LOGI("[INSTREG] probe installed at 0xF93A38");
            }

            // Bounded observation of RefCounted::dropRef. The original body
            // decrements first and calls vtable[0] only at zero references.
            // The former DRFGUARD checked vtable[2] on EVERY call and skipped
            // valid releases (including Root objects). Never alter lifetime
            // based on a guessed vtable layout or a diagnostic range check.
            {
                uint32_t st = 0x40000000u + 0xF4C858u;
                auto calls = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t expected = 0xE92D4038u; // push {r3-r5,lr}
                const uint32_t actual = MemoryRead32(st);
                if (actual != expected) {
                    LOGE("[DROPREF] refusing stale probe: expected %08X, found %08X",
                         expected, actual);
                } else {
                uint32_t tt = m_thunk_manager->RegisterThunk("probe_dropref",
                    [calls](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        uint32_t obj = jit.Regs()[0];
                        const uint32_t lr = jit.Regs()[14] & ~1u;
                        const uint32_t entry_sp = jit.Regs()[13];
                        const uint32_t refs = obj > 0x1000u
                            ? host.MemoryRead32(obj + 4u) : 0;
                        const uint32_t vt = obj > 0x1000u
                            ? host.MemoryRead32(obj) : 0;
                        const uint32_t fn = vt > 0x1000u
                            ? host.MemoryRead32(vt) : 0;
                        const uint32_t fn_code = fn & ~1u;
                        const uint32_t caller_lr =
                            host.MemoryRead32(entry_sp + 36u);
                        const bool executable = fn_code >= 0x40000000u &&
                                                fn_code < 0x4172AF50u;
                        const uint32_t call_no = calls->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        if (call_no <= 32u || (call_no % 262144u) == 0) {
                            LOGE("[DROPREF-ENTRY] #%u obj=%08X refs=%08X vt=%08X dtor=%08X exec=%u lr=%08X sp=%08X caller_saved_lr=%08X",
                                 call_no, obj, refs, vt, fn,
                                 executable ? 1u : 0u, jit.Regs()[14], entry_sp,
                                 caller_lr);
                        }
                        if (lr == 0x41072010u) {
                            tl_findclass_dropref_trace.drop_seen = true;
                            tl_findclass_dropref_trace.free_seen = false;
                            tl_findclass_dropref_trace.drop_sp = entry_sp;
                            tl_findclass_dropref_trace.drop_saved_lr =
                                caller_lr;
                            tl_findclass_dropref_trace.object = obj;
                            tl_findclass_dropref_trace.ref_count = refs;
                            tl_findclass_dropref_trace.vtable = vt;
                            tl_findclass_dropref_trace.destructor = fn;
                            if (call_no <= 32u && (refs <= 1u || !executable)) {
                                LOGE("[DROPREF-FINDCLASS] obj=%08X refs=%08X vt=%08X dtor=%08X executable=%u caller_sp=%08X caller_lr=%08X",
                                     obj, refs, vt, fn, executable ? 1u : 0u,
                                     entry_sp, caller_lr);
                            }
                        }
                        jit.Regs()[13] = arm32::PushRegisters(
                            jit.Regs()[13], 0x4038u,
                            [&](unsigned reg) { return jit.Regs()[reg]; },
                            [&](uint32_t address, uint32_t value) {
                                host.MemoryWrite32(address, value);
                            });
                    });
                const uint32_t replacement =
                    0xEF000000u | (MemoryRead32(tt) & 0x00FFFFFFu);
                MemoryWrite32(st, replacement);
                InvalidateGuestCode(st, sizeof(uint32_t));
                g_probe_rewrites.push_back({st, replacement});
                LOGI("[DROPREF] observational probe installed; guest lifetime unmodified");
                }
            }
        }

        // Existing null global-parameter fallback. 0x11BE7D4 loads the
        // SShaderParameterDef name pointer; when null, the compiler emits a
        // null dereference followed by UDF. Observe the skipped binding in
        // diagnostic builds, preserving the same switch-default branch.
        {
            constexpr uint32_t site = 0x411BEC4Cu;
            constexpr uint32_t target = 0x411BE870u;
            constexpr uint32_t expected = 0xE5D33009u; // ldrb r3,[r3,#9]
            constexpr uint32_t trap = 0xE7F000F0u;
            constexpr int32_t offset = static_cast<int32_t>(target - (site + 8));
            constexpr uint32_t fallback = 0xEA000000u |
                (static_cast<uint32_t>(offset >> 2) & 0x00FFFFFFu);
            const uint32_t actual = MemoryRead32(site);
            if ((actual != expected && actual != fallback) || MemoryRead32(site + 4) != trap) {
                LOGE("[SHADER-UND] refusing stale fallback: instruction=%08X next=%08X",
                     actual, MemoryRead32(site + 4));
            } else {
                uint32_t replacement = fallback;
#if MC4_ENABLE_NATIVE_LOGGING
                const uint32_t thunk = m_thunk_manager->RegisterThunk("probe_missing_global_shader_parameter",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> calls{0};
                        const uint32_t count = calls.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (count <= 40 || count % 1000 == 0) {
                            const uint32_t binding = jit.Regs()[4];
                            const uint32_t parameter = jit.Regs()[5];
                            const uint32_t pair = jit.Regs()[6];
                            uint32_t binding_words[4] = {}, parameter_words[4] = {}, pair_word = 0;
                            const void* binding_data = GuestSpan(host.GetGuestMemoryBase(),
                                host.GetGuestMemorySize(), binding, sizeof(binding_words));
                            const void* parameter_data = GuestSpan(host.GetGuestMemoryBase(),
                                host.GetGuestMemorySize(), parameter, sizeof(parameter_words));
                            const void* pair_data = GuestSpan(host.GetGuestMemoryBase(),
                                host.GetGuestMemorySize(), pair, sizeof(pair_word));
                            if (binding_data) memcpy(binding_words, binding_data, sizeof(binding_words));
                            if (parameter_data) memcpy(parameter_words, parameter_data, sizeof(parameter_words));
                            if (pair_data) memcpy(&pair_word, pair_data, sizeof(pair_word));
                            uint32_t program = 0;
                            const char* uniform = GuestGLUniformName(binding_words[1], &program);
                            LOGI("[SHADER-NULL] #%u program=%u uniform='%s' binding=%08X"
                                 " words=%08X,%08X,%08X,%08X parameter=%08X"
                                 " words=%08X,%08X,%08X,%08X pair=%08X ids=%08X"
                                 " manager=%08X values=%08X lr=%08X sp=%08X",
                                 count, program, uniform, binding,
                                 binding_words[0], binding_words[1], binding_words[2], binding_words[3],
                                 parameter, parameter_words[0], parameter_words[1],
                                 parameter_words[2], parameter_words[3], pair, pair_word,
                                 jit.Regs()[10], jit.Regs()[11], jit.Regs()[14], jit.Regs()[13]);
                        }
                        // The displaced fallback was an unconditional B, changing only PC.
                        jit.Regs()[15] = 0x411BE870u;
                    });
                replacement = 0xEF000000u | (MemoryRead32(thunk) & 0x00FFFFFFu);
#endif
                MemoryWrite32(site, replacement);
                InvalidateGuestCode(site, sizeof(uint32_t));
                g_probe_rewrites.push_back({site, replacement});
                LOGI("[SHADER-UND] null parameter -> switch default at 0x11BEC4C");
            }
        }

#if MC4_ENABLE_NATIVE_LOGGING
        // CustomSceneManager::drawAll's verified pass-2 sky renderList call.
        // The original sky registration callback also uses pass 2. Bracket
        // only this pass; emulate the displaced BL and LDR without changing
        // any other core/FPU registers or CPSR. No release graphics changes.
        {
            constexpr uint32_t call = 0x4053E194u, after = 0x4053E198u;
            if (MemoryRead32(call) != 0xEB0049FAu || MemoryRead32(after) != 0xE5952074u) {
                LOGE("[GLSKY-PROBE] refusing stale sky call: %08X/%08X",
                     MemoryRead32(call), MemoryRead32(after));
            } else {
                const uint32_t entry_thunk = m_thunk_manager->RegisterThunk("probe_sky_pass_begin",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        GuestGLSkyPass(true);
                        jit.Regs()[14] = 0x4053E198u;
                        jit.Regs()[15] = 0x40550984u;
                    });
                const uint32_t return_thunk = m_thunk_manager->RegisterThunk("probe_sky_pass_end",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        GuestGLSkyPass(false);
                        jit.Regs()[2] = host.MemoryRead32(jit.Regs()[5] + 0x74u);
                        jit.Regs()[15] = 0x4053E19Cu;
                    });
                const uint32_t enter = 0xEF000000u | (MemoryRead32(entry_thunk) & 0x00FFFFFFu);
                const uint32_t leave = 0xEF000000u | (MemoryRead32(return_thunk) & 0x00FFFFFFu);
                MemoryWrite32(call, enter);
                MemoryWrite32(after, leave);
                InvalidateGuestCode(call, sizeof(uint32_t) * 2);
                g_probe_rewrites.push_back({call, enter});
                g_probe_rewrites.push_back({after, leave});
                LOGI("[GLSKY-PROBE] installed exact sky-pass BL/return observations");
            }
        }
#endif

        // __cxa_atexit PLT (0x49A61C): this image's .rel.plt never covers
        // its GOT slot (verified: no JUMP_SLOT targets 0x179EA6C), so the
        // slot keeps raw bytes and the first static-local singleton
        // (glf::Singleton<VersionUpdater>, constructed by the FlashMenu
        // ctor during StateSet creation) jumped into the GOT --
        // UndefinedInstruction at 0x179EA64 killed the core mid-Load,
        // BEFORE StateAutomat::Load could store the stateset pointer.
        // Registering atexit handlers is irrelevant (no dlclose; process
        // exit reaps everything). BX LR: both callers tail-call here.
        {
            uint32_t cxap = 0x40000000u + 0x49A61Cu;
            LOGI("[CXA-ATEXIT] shunting PLT at 0x49A61C (was %08X)",
                 MemoryRead32(cxap));
            MemoryWrite32(cxap, 0xE12FFF1Eu);  // bx lr
        }

        // FileManager::_GetId's real prologue is the PUSH at 0x564CE4.
        // 0x564CE8 is the following `mov r8,r1`; an older probe mistook it
        // for the prologue, pushed another 32 bytes, and skipped R8 setup.
        {
            constexpr uint32_t kGetIdSite = 0x40000000u + 0x564CE8u;
            constexpr uint32_t kGetIdPrologue = 0x40000000u + 0x564CE4u;
            constexpr uint32_t kGetIdPrologueExpected = 0xE92D43F8u;
            constexpr uint32_t kGetIdExpected = 0xE1A08001u; // mov r8,r1
            const uint32_t get_id_prologue = MemoryRead32(kGetIdPrologue);
            const uint32_t get_id_actual = MemoryRead32(kGetIdSite);
            if (get_id_prologue != kGetIdPrologueExpected ||
                get_id_actual != kGetIdExpected) {
                LOGE("[GET-ID] refusing stale probe: prologue %08X (expected %08X), "
                     "instruction %08X (expected %08X)",
                     get_id_prologue, kGetIdPrologueExpected,
                     get_id_actual, kGetIdExpected);
            } else {
            uint32_t gid_tramp = m_thunk_manager->RegisterThunk("probe_get_id",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> c{0};
                    uint32_t n = c.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 40 || (n % 5000) == 0) {
                        uint32_t name_g = jit.Regs()[1];
                        char buf[80]; size_t k = 0;
                        if (name_g && host.GetGuestMemoryBase()) {
                            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + name_g);
                            while (k + 1 < sizeof(buf) && p[k]) { buf[k] = p[k]; ++k; }
                        }
                        buf[k] = 0;
                        LOGI("[GET-ID] #%u this=%08X name='%s'", n, jit.Regs()[0], buf);
                    }
                    // NULL FileManager (MultiplayerManager's ctor reads
                    // FileManager::s_mgr before FileManager::Init populated
                    // it): substitute the last GOOD manager instance so the
                    // real lookup runs against the real index. Returning -1
                    // here fed ResStream(-1) and FileStream::~FileStream then
                    // dropped a never-constructed inner file through a null
                    // vtable -- the 0x41812300 CODE-FETCH that aborted every
                    // loader pass after M6_SND (runs OBB-8 .. lowpc).
                    static std::atomic<uint32_t> s_last_good_mgr{0};
                    uint32_t cur_mgr = jit.Regs()[0];
                    if (cur_mgr) {
                        s_last_good_mgr.store(cur_mgr, std::memory_order_relaxed);
                    } else {
                        uint32_t sub = s_last_good_mgr.load(std::memory_order_relaxed);
                        if (sub) {
                            jit.Regs()[0] = sub;
                            static std::atomic<uint32_t> sn{0};
                            uint32_t k = sn.fetch_add(1, std::memory_order_relaxed) + 1;
                            if (k <= 10 || (k % 2000) == 0)
                                LOGI("[GET-ID] null-this substituted mgr=%08X", sub);
                        } else {
                            // No manager seen yet: take _GetId's own failure
                            // exit (0x564D64: mvn r0,#0; pop {r3-r9,pc}).
                            // The real prologue at 0x564CE4 already saved
                            // those registers; let the guest epilogue pop it.
                            jit.Regs()[0] = 0xFFFFFFFFu;
                            jit.Regs()[15] = 0x40000000u + 0x564D64u;
                            return;
                        }
                    }
                    // NOTE (2026-09-17): the earlier fake-id hack
                    // (r0=0x1234 + HaltExecution for the MP arrays) is
                    // REMOVED -- the halt aborted the whole loader pass,
                    // restarting it from the entry on every lookup (the
                    // infinite M2 loop of run OBB-7). With the fast guest
                    // malloc the zip index builds in ~2 s and the real
                    // GetId resolves the arrays naturally.
                    jit.Regs()[8] = jit.Regs()[1]; // emulate mov r8,r1
                    BridgeSafepointCheck();
                });
            uint32_t s17 = MemoryRead32(gid_tramp) & 0x00FFFFFFu;
            const uint32_t replacement = 0xEF000000u | s17;
            MemoryWrite32(kGetIdSite, replacement);
            InvalidateGuestCode(kGetIdSite, sizeof(uint32_t));
            g_probe_rewrites.push_back({kGetIdSite, replacement});
            LOGI("[GET-ID] probe installed at 0x564CE8 (svc %u)", s17);
            }
        }

        // [GET-ID-RESULT] Observe whether the existing resource index really
        // contains the offline MP names. Hook the two arithmetic instructions
        // immediately before the guest's unmodified POP epilogues.
        {
            struct Site { uint32_t address; uint32_t expected; bool found; };
            const Site sites[] = {
                {0x40564D4Cu, 0xE5960004u, true},  // ldr r0,[r6,#4]
                {0x40564D64u, 0xE3E00000u, false}, // mvn r0,#0
            };
            for (const Site& site : sites) {
                if (MemoryRead32(site.address) != site.expected) {
                    LOGE("[GET-ID-RESULT] stale at %08X expected=%08X got=%08X",
                         site.address, site.expected, MemoryRead32(site.address));
                    return false;
                }
                auto count = std::make_shared<std::atomic<uint32_t>>(0);
                const uint32_t thunk = m_thunk_manager->RegisterThunk(
                    site.found ? "get_id_found" : "get_id_missing",
                    [site, count](Dynarmic::A32::Jit& jit,
                                  DynarmicHost& host) {
                        const uint32_t result = site.found
                            ? host.MemoryRead32(jit.Regs()[6] + 4u)
                            : 0xFFFFFFFFu;
                        const uint32_t n = count->fetch_add(
                            1, std::memory_order_relaxed) + 1;
                        if (n <= 32 || n % 5000 == 0) {
                            char name[80]{};
                            const uint32_t p = jit.Regs()[8];
                            if (p >= 0x40000000u && p < 0xEFFFFFB0u) {
                                for (unsigned i = 0; i < 79; ++i) {
                                    const uint8_t ch = host.MemoryRead8(p + i);
                                    if (!ch) break;
                                    name[i] = ch >= 0x20u && ch < 0x7Fu
                                        ? static_cast<char>(ch) : '?';
                                }
                            }
                            LOGI("[GET-ID-RESULT] %s #%u name='%s' id=%08X"
                                 " lr=%08X", site.found ? "found" : "missing",
                                 n, name, result, jit.Regs()[14]);
                        }
                        jit.Regs()[0] = result;
                    });
                const uint32_t replacement = 0xEF000000u |
                    (MemoryRead32(thunk) & 0x00FFFFFFu);
                MemoryWrite32(site.address, replacement);
                InvalidateGuestCode(site.address, sizeof(uint32_t));
                g_probe_rewrites.push_back({site.address, replacement});
            }
        }

        // Bring-up: CGlfDevice ctor FS-store site (`str r3,[r4,#0x28]`).
        // Shows which device object receives the file system and when.
        {
            uint32_t fs_tramp = m_thunk_manager->RegisterThunk("probe_dev_fs",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> dfs{0};
                    uint32_t n = dfs.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 20 || (n % 2000) == 0)
                        LOGI("[DEV-FS] #%u device=%08X fs=%08X", n, jit.Regs()[4], jit.Regs()[3]);
                    host.MemoryWrite32(jit.Regs()[4] + 0x28, jit.Regs()[3]);
                });
            uint32_t s10 = MemoryRead32(fs_tramp) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x10E7324u, 0xEF000000u | s10);
            LOGI("[DEV-FS] probe installed at 0x10E7324 (svc %u)", s10);
        }

        // Bring-up: createDeviceEx return paths. Success (`mov r0,r5` at
        // 0x10E7528) and post-failure cleanup (`str r3,[r5]` at 0x10E7558)
        // both log the out-cell pointer and its content.
        {
            uint32_t r1t = m_thunk_manager->RegisterThunk("probe_cde_ok",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> c{0};
                    uint32_t n = c.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 12 || (n % 2000) == 0)
                        LOGI("[CDE-OK] #%u out=%08X device=%08X", n,
                             jit.Regs()[5], host.MemoryRead32(jit.Regs()[5]));
                    jit.Regs()[0] = jit.Regs()[5];
                });
            uint32_t s11 = MemoryRead32(r1t) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x10E7528u, 0xEF000000u | s11);
            LOGI("[CDE-OK] probe installed at 0x10E7528 (svc %u)", s11);

            uint32_t r2t = m_thunk_manager->RegisterThunk("probe_cde_fail",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<uint32_t> c{0};
                    uint32_t n = c.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n <= 12 || (n % 2000) == 0)
                        LOGI("[CDE-FAIL] #%u out=%08X device=%08X (about to null)",
                             n, jit.Regs()[5], host.MemoryRead32(jit.Regs()[5]));
                    host.MemoryWrite32(jit.Regs()[5], jit.Regs()[3]);
                });
            uint32_t s12 = MemoryRead32(r2t) & 0x00FFFFFFu;
            MemoryWrite32(0x40000000u + 0x10E7558u, 0xEF000000u | s12);
            LOGI("[CDE-FAIL] probe installed at 0x10E7558 (svc %u)", s12);

            // createDeviceEx "no driver" branch target (`ldr r2,[r4]`).
            {
                uint32_t r3t = m_thunk_manager->RegisterThunk("probe_cde_retry",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> c{0};
                        uint32_t n = c.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (n <= 12 || (n % 2000) == 0)
                            LOGI("[CDE-RETRY] #%u device=%08X driver=%08X", n,
                                 jit.Regs()[4], host.MemoryRead32(jit.Regs()[4] + 8));
                        jit.Regs()[2] = host.MemoryRead32(jit.Regs()[4]);
                    });
                uint32_t s13 = MemoryRead32(r3t) & 0x00FFFFFFu;
                MemoryWrite32(0x40000000u + 0x10E7530u, 0xEF000000u | s13);
                LOGI("[CDE-RETRY] probe installed at 0x10E7530 (svc %u)", s13);
            }
            // InitAndroid(0) global device store (`str r3,[r2,#0x14]`).
            {
                uint32_t r4t = m_thunk_manager->RegisterThunk("probe_init0_store",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> c{0};
                        uint32_t n = c.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (n <= 8 || (n % 2000) == 0)
                            LOGI("[INIT0-STORE] #%u cell=%08X device=%08X", n,
                                 jit.Regs()[2] + 0x14, jit.Regs()[3]);
                        host.MemoryWrite32(jit.Regs()[2] + 0x14, jit.Regs()[3]);
                    });
                uint32_t s14 = MemoryRead32(r4t) & 0x00FFFFFFu;
                MemoryWrite32(0x40000000u + 0x7B0B4Cu, 0xEF000000u | s14);
                LOGI("[INIT0-STORE] probe installed at 0x7B0B4C (svc %u)", s14);
            }
            // InitAndroid(1) global device read (`ldr r3,[r3,#0x14]`).
            {
                uint32_t r5t = m_thunk_manager->RegisterThunk("probe_init1_read",
                    [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                        static std::atomic<uint32_t> c{0};
                        uint32_t n = c.fetch_add(1, std::memory_order_relaxed) + 1;
                        jit.Regs()[3] = host.MemoryRead32(jit.Regs()[3] + 0x14);
                        if (n <= 8 || (n % 2000) == 0)
                            LOGI("[INIT1-READ] #%u device=%08X", n, jit.Regs()[3]);
                    });
                uint32_t s15 = MemoryRead32(r5t) & 0x00FFFFFFu;
                MemoryWrite32(0x40000000u + 0x7B0A5Cu, 0xEF000000u | s15);
                LOGI("[INIT1-READ] probe installed at 0x7B0A5C (svc %u)", s15);
            }
        }
    }
    // NOTE: an old bring-up probe here replaced 0x7B0B14 (`ldr r3,[sp,#4]`,
    // InitAndroid(0)'s reload of the created device) with a bare no-op SVC.
    // The swallowed load left r3 holding 0x2180 (a creation-params constant),
    // which was then stored as the global glitch device and broke every
    // downstream device dereference (iFPS::Init's file-system chain).

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    {
        // Bring-up: name the initializer that zeroes the .text hole at
        // 0x418872EC (expected to hold probe value 0xEF3FFFFF). Remove with
        // the rest of the phase-7 bring-up diagnostics.
        int idx = 0;
        bool hole_named = false;
        for (uint32_t init_func : m_elf_loader->GetInitArray()) {
            RunFunction(init_func);
            if (!hole_named && idx > 0 &&
                MemoryRead32(0x40000000u + 0x8872ECu) != 0xEF3FFFFFu) {
                LOGE("[HOLE] init #%d @0x%08X zeroed the .text probe", idx, init_func);
                hole_named = true;
            }
            ++idx;
        }
    }
        // Re-install probes the .init_array initializers wiped:
    // a guest static ctor zeroes .text regions (observed: the whole
    // W1..A0 window 0x8A2DFC-0x8A2ED8 went silent while M2..M4/A4 fired).
    {
        int wiped = 0;
        for (auto& rw : g_probe_rewrites) {
            if (MemoryRead32(rw.first) != rw.second) {
                MemoryWrite32(rw.first, rw.second);
                InvalidateGuestCode(rw.first, sizeof(uint32_t));
                ++wiped;
                LOGE("[RE-PROBE] restored and invalidated SVC at 0x%08X",
                     rw.first);
            }
        }
        if (wiped)
            LOGE("[RE-PROBE] re-installed %d milestone SVCs wiped by "
                 ".init_array", wiped);
    }

    // These loader prologues must execute as guest instructions. Check after
    // all hooks and static initializers so another diagnostic cannot silently
    // reintroduce the LOADSTAGE stack corruption.
    for (const auto& [site, expected] : {
             std::pair{0x40FAA6B8u, 0xE92D43F0u}, // push {r4-r9,lr}
             std::pair{0x40FAA6BCu, 0xE24DD00Cu}, // sub sp,sp,#12
             std::pair{0x410567DCu, 0xE92D40F8u}, // push {r3-r7,lr}
             std::pair{0x405B67A4u, 0xE92D47F0u}, // push {r4-r10,lr}
             std::pair{0x40F642DCu, 0xE92D43F8u}, // push {r3-r9,lr}
             std::pair{0x40F72AFCu, 0xE92D4038u}, // setVisible
             std::pair{0x405CD40Cu, 0xE92D4FF8u}, // HasVisibleMenu
             std::pair{0x405CA2CCu, 0xE590300Cu}, // GetMenuInfo
             std::pair{0x405CD4D8u, 0xE1A09000u}}) { // list iterator result
        const uint32_t actual = MemoryRead32(site);
        if (actual != expected) {
            LOGE("[LOADER-PROLOGUE] corrupt site=%08X expected=%08X actual=%08X",
                 site, expected, actual);
            return false;
        }
    }
    LOGI("[LOADER-PROLOGUE] loader/lifetime prologues and visibility functions intact");

    // [RELRO] Only protect complete host pages that end before .dynamic/.got.
    // Rounding the end UP used to cover the writable GOT on 4-KiB pages and
    // even more of it on 16-KiB pages. The byte-range MemoryWrite32 guard
    // below still rejects mediated writes into the unprotectable tail;
    // fastmem stores into that partial page cannot be isolated by mprotect.
    if (!g_relro_on.exchange(true, std::memory_order_relaxed)) {
        const long host_page_size = sysconf(_SC_PAGESIZE);
        if (host_page_size != 4096 && host_page_size != 16384) {
            // The preceding-page contents have only been audited for these
            // two Android page sizes. Never protect an unaudited wider page.
            LOGE("[RELRO] unsupported host page size %ld; byte guard only",
                 host_page_size);
        } else {
            const uint32_t mask = static_cast<uint32_t>(host_page_size - 1);
            const uint32_t protect_begin = kRelroStart & ~mask;
            const uint32_t protect_end = kRelroEnd & ~mask;
            if (protect_end <= protect_begin) {
                LOGE("[RELRO] no complete page before writable GOT (page=%ld)",
                     host_page_size);
            } else {
                void* page = m_memory + protect_begin;
                const size_t len = protect_end - protect_begin;
                if (mprotect(page, len, PROT_READ) != 0) {
                    LOGE("[RELRO] mprotect failed errno=%d page=%ld", errno,
                         host_page_size);
                } else {
                    LOGI("[RELRO] protected guest pages %08X..%08X (page=%ld); "
                         "mediated-write guard continues through %08X",
                         protect_begin, protect_end, host_page_size, kRelroEnd);
                }
            }
        }
    }
    LOGI("Game ELF loaded from memory and initialized successfully!");
    return true;
}

bool DynarmicHost::LoadLibraries(const std::string& fmodex_path, const std::string& fmodevent_path, const std::string& game_path) {
    LOGI("Loading libraries: fmodex='%s', fmodevent='%s', game='%s'", fmodex_path.c_str(), fmodevent_path.c_str(), game_path.c_str());

    m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, 0x40400000);
    if (!m_fmodex_loader->Load(fmodex_path)) {
        LOGE("Failed to load libfmodex.so from %s", fmodex_path.c_str());
        return false;
    }

    m_fmodevent_loader = std::make_unique<ElfLoader>(m_memory, 0x40600000);
    if (!m_fmodevent_loader->Load(fmodevent_path)) {
        LOGE("Failed to load libfmodevent.so from %s", fmodevent_path.c_str());
        return false;
    }

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->Load(game_path)) {
        LOGE("Failed to load the guest library from %s", game_path.c_str());
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_fmodex_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodex.so");
        return false;
    }

    if (!m_fmodevent_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodevent.so");
        return false;
    }

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate the guest library");
        return false;
    }

    LOGI("Running initializers for libfmodex.so (%zu funcs)...", m_fmodex_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodex_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for libfmodevent.so (%zu funcs)...", m_fmodevent_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodevent_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for the guest library (%zu funcs)...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("All libraries loaded, relocated, and initialized successfully with sound!");
    return true;
}

bool DynarmicHost::LoadLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                           const uint8_t* fmodevent_data, size_t fmodevent_size,
                                           const uint8_t* game_data, size_t game_size) {
    LOGI("Loading libraries from memory: fmodex=%zu bytes, fmodevent=%zu bytes, game=%zu bytes",
         fmodex_size, fmodevent_size, game_size);

    m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, 0x40400000);
    if (!m_fmodex_loader->LoadFromMemory(fmodex_data, fmodex_size)) {
        LOGE("Failed to load libfmodex.so from memory");
        return false;
    }

    m_fmodevent_loader = std::make_unique<ElfLoader>(m_memory, 0x40600000);
    if (!m_fmodevent_loader->LoadFromMemory(fmodevent_data, fmodevent_size)) {
        LOGE("Failed to load libfmodevent.so from memory");
        return false;
    }

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->LoadFromMemory(game_data, game_size)) {
        LOGE("Failed to load the guest library from memory");
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_fmodex_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodex.so");
        return false;
    }

    if (!m_fmodevent_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodevent.so");
        return false;
    }

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate the guest library");
        return false;
    }

    LOGI("Running initializers for libfmodex.so (%zu funcs)...", m_fmodex_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodex_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for libfmodevent.so (%zu funcs)...", m_fmodevent_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodevent_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for the guest library (%zu funcs)...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("All libraries loaded from memory and initialized successfully with sound!");
    return true;
}

uint32_t DynarmicHost::FindSymbol(const std::string& name) {
    if (m_elf_loader) {
        uint32_t addr = m_elf_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodevent_loader) {
        uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodex_loader) {
        uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    return 0;
}

uint32_t DynarmicHost::RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args) {
    return RunFunction(target_pc, std::span<const uint32_t>(args));
}

uint32_t DynarmicHost::RunFunction(uint32_t target_pc, std::span<const uint32_t> args) {
    return RunFunctionAt(m_stack_top, target_pc, args);
}

bool DynarmicHost::TryRunFunctionAt(uint32_t stack_top, uint32_t target_pc,
                                    const std::vector<uint32_t>& args) {
    if (!m_mutex.try_lock()) return false;
    std::lock_guard<std::recursive_mutex> lk(m_mutex, std::adopt_lock);
    RunFunctionAt(stack_top, target_pc, args);
    return true;
}

uint32_t DynarmicHost::RunFunctionAt(uint32_t stack_top, uint32_t target_pc, const std::vector<uint32_t>& args) {
    return RunFunctionAt(stack_top, target_pc, std::span<const uint32_t>(args));
}

uint32_t DynarmicHost::RunFunctionAt(uint32_t stack_top, uint32_t target_pc,
                                     std::span<const uint32_t> args) {
    if (!m_jit) return 0;
    m_main_run_tid = std::this_thread::get_id();
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // Watchdog: a guest call that outlives 15 s gets its PC logged every 5 s.
    // bring-up only; delete once the game reaches steady state.
    // [TRAP-CHECK] Guest init code has been observed zeroing low memory
    // (the "[HOLE] init zeroed the .text probe" class), which can take out
    // the exit traps at 0x4/0x8; a guest return into the trap region then
    // NOP-slides forever at pc~0x6 while the JIT is effectively parked.
    // Restore the trap words before every host-initiated run.
    if (m_memory) {
        uint32_t arm_trap = *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_ARM);
        uint32_t thumb_trap = *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_THUMB);
        if (arm_trap != 0xEF000000u || thumb_trap != 0xDF00DF00u) {
            LOGE("[TRAP-CHECK] traps clobbered (arm=%08X thumb=%08X) -> restored",
                 arm_trap, thumb_trap);
            *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_ARM) = 0xEF000000u;
            *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_THUMB) = 0xDF00DF00u;
            InvalidateGuestCode(EXIT_TRAP_ARM, 8);
        }
    }

    m_watchdog_pc = target_pc;
    m_watchdog_active = true;
    s_live_host.store(this, std::memory_order_release);
    static std::atomic<bool> wd_thread_started{false};
    if (!wd_thread_started.exchange(true)) {
        std::thread([] {
            pthread_setname_np(pthread_self(), "bridge-watchdg");
            int seconds = 0;
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                DynarmicHost* self = s_live_host.load(std::memory_order_acquire);
                if (!self) { seconds = 0; continue; }
                if (!self->m_watchdog_active.load()) { seconds = 0; continue; }
                // Dynarmic's ARM64 AddressSpace reclaims its cache when less
                // than 1 MiB remains. Clearing every 90 s here also flushes
                // healthy frame calls and forces their blocks to recompile.
                // Keep cache invalidation below only for a frozen guest spin.
                if (self->m_fast_pool_recharge &&
                    seconds >= 30 && (seconds % 30) == 0) {
                    // Recharge an exhausted fast-malloc pool (cur >= end-1MB)
                    // with a fresh 384 MB window so the guest-side bump
                    // allocator never falls back to the slow thunk for long.
                    uint32_t tbl = self->m_fast_pool_table;
                    if (tbl && self->GetGuestMemoryBase()) {
                        for (int slot = 0; slot < 2; ++slot) {
                            uint32_t cur = 0, end = 0;
                            memcpy(&cur, self->GetGuestMemoryBase() + tbl + slot * 8, 4);
                            memcpy(&end, self->GetGuestMemoryBase() + tbl + slot * 8 + 4, 4);
                            if (end > cur && end - cur < (1u << 20)) {
                                uint32_t fresh = self->GuestAlloc(384u << 20, 0x1000);
                                if (fresh) {
                                    memcpy(self->GetGuestMemoryBase() + tbl + slot * 8, &fresh, 4);
                                    uint32_t fend = fresh + (384u << 20);
                                    memcpy(self->GetGuestMemoryBase() + tbl + slot * 8 + 4, &fend, 4);
                                    LOGI("[WATCHDOG] fast pool %d recharged at 0x%08X", slot, fresh);
                                } else {
                                    LOGI("[WATCHDOG] fast pool %d recharge refused (heap full)", slot);
                                }
                            }
                        }
                    }
                }
                if (seconds >= 60 && (seconds % 60) == 0) {
                    // Leak hunt: heap cursor + live blocks + top size classes.
                    LOGE("[HEAP] cur=0x%08X live=%lld frees=%lld b16=%llu b64=%llu b256=%llu b1k=%llu b4k=%llu big=%llu miss=%llu",
                         self->m_heap_current,
                         static_cast<long long>(g_alloc_live.load()),
                         static_cast<long long>(g_alloc_frees.load()),
                         (unsigned long long)g_alloc_buckets[4].load(),
                         (unsigned long long)g_alloc_buckets[6].load(),
                         (unsigned long long)g_alloc_buckets[8].load(),
                         (unsigned long long)g_alloc_buckets[10].load(),
                         (unsigned long long)g_alloc_buckets[12].load(),
                         (unsigned long long)g_alloc_buckets[20].load(),
                         (unsigned long long)g_free_magic_miss.load());
                }
                if (++seconds >= 15 && (seconds - 15) % 5 == 0) {
                    // Live PC: r15 of the (possibly running) JIT. Unsynced read.
                    // Also sample the live guest stack (12 words from sp) - it
                    // names the function chain actually executing.
                    uint32_t live_pc = 0, live_lr = 0;
                    uint32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0, spv = 0;
                    uint8_t at_r0[8] = {0}, at_r1[8] = {0};
                    if (auto* j = self->GetJitForDiagnostics()) {
                        live_pc = j->Regs()[15];
                        live_lr = j->Regs()[14];
                        r0 = j->Regs()[0];
                        r1 = j->Regs()[1];
                        r2 = j->Regs()[2];
                        r3 = j->Regs()[3];
                        spv = j->Regs()[13];
                        if (uint8_t* mem = self->GetGuestMemoryBase()) {
                            auto peek = [&](uint32_t addr, uint8_t* out) {
                                if (addr < self->m_memory_size - sizeof(at_r0)) memcpy(out, mem + addr, sizeof(at_r0));
                            };
                            peek(r0, at_r0);
                            peek(r1, at_r1);
                        }
                    }
                    char stk[200] = "";
                    if (auto* j2 = self->GetJitForDiagnostics(); j2 && self->GetGuestMemoryBase()) {
                        int o = 0;
                        for (int i = 0; i < 12; ++i) {
                            uint32_t w;
                            memcpy(&w, self->GetGuestMemoryBase() + spv + i * 4, 4);
                            o += snprintf(stk + o, sizeof(stk) - o, " +%02X:%08X", i * 4, w);
                        }
                    }
                    LOGI("[WATCHDOG] stuck=%ds entry=%08X pc=%08X lr=%08X sp=%08X r0=%08X r1=%08X thunk=%s stk:%s",
                         seconds, self->m_watchdog_pc.load(), live_pc, live_lr, spv, r0, r1,
                         LastThunkName() ? LastThunkName() : "<none>", stk);
                    LOGI("WATCHDOG: stuck for %ds, entry=0x%08X live PC=0x%08X LR=0x%08X, last thunk=%s, dispatches=%llu "
                         "r0=0x%08X r1=0x%08X r2=0x%08X r3=0x%08X [r0]=%02X %02X %02X %02X %02X %02X %02X %02X [r1]=%02X %02X %02X %02X %02X %02X %02X %02X",
                         seconds, self->m_watchdog_pc.load(), live_pc, live_lr,
                         LastThunkName() ? LastThunkName() : "<none>",
                         static_cast<unsigned long long>(ThunkDispatchCount()),
                         r0, r1, r2, r3,
                         at_r0[0], at_r0[1], at_r0[2], at_r0[3], at_r0[4], at_r0[5], at_r0[6], at_r0[7],
                         at_r1[0], at_r1[1], at_r1[2], at_r1[3], at_r1[4], at_r1[5], at_r1[6], at_r1[7]);
                    // Force-unwind a long guest spin: the FMOD worker waits
                    // for deferred audio callbacks, which only drain when
                    // the main relay re-enters its loop. Kick the core so
                    // the relay unwinds and the queue drains (the relay
                    // re-entered ~10k times per run in earlier builds).
                    // WHITELIST (2026-09-19): the data_N zip indexing is a
                    // LEGITIMATE long loop (~55 s per pack over the
                    // OBB-in-APK VFS); kicking it every 2 s after 8 s made
                    // the index restart forever and game_graphml never
                    // resolved. Parse zones are exempt from the kick.
                    auto in_parse_whitelist = [](uint32_t pc) {
                        return (pc >= 0x41339FB8u && pc < 0x4133A120u) ||  // createReadFile
                               (pc >= 0x4132D834u && pc < 0x4132DD38u) ||  // glitch::io CZipReader ImportHeader/init/C1
                               (pc >= 0x4134E09Cu && pc < 0x4134F2C0u) ||  // CZipReader ctor+init
                               (pc >= 0x40571224u && pc < 0x40571300u);    // addZipFileArchive
                    };
                    // Only kick when the guest is REALLY wedged: the thunk dispatch
                    // counter must be frozen. The stale-regs sampler kept
                    // "kicking" a healthy 60 fps loop (identical end-of-frame
                    // thunk state each sample) and the UserDefined1 halt
                    // murdered whatever was running -- including the
                    // host-driven AS3 tick.
                    static std::atomic<uint64_t> s_wd_last_disp{0};
                    static std::atomic<int> s_wd_frozen{0};
                    uint64_t disp_now = ThunkDispatchCount();
                    if (disp_now != s_wd_last_disp.load(std::memory_order_relaxed)) {
                        s_wd_last_disp.store(disp_now, std::memory_order_relaxed);
                        s_wd_frozen.store(0, std::memory_order_relaxed);
                    } else {
                        s_wd_frozen.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (seconds >= 8 && (seconds % 2) == 0 &&
                        s_wd_frozen.load(std::memory_order_relaxed) >= 10 &&
                        !in_parse_whitelist(live_pc)) {
                        if (self->m_jit) {
                            self->m_jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
                            s_wd_frozen.store(0, std::memory_order_relaxed);
                            // A single huge compiled block can spin on an
                            // internal backward branch forever -- the halt
                            // flag is only checked at block boundaries.
                            // Force a recompile so the very next fetch goes
                            // through MemoryReadCode (and the runaway /
                            // slide guards).
                            self->m_jit->ClearCache();
                            LOGI("[WATCHDOG] kicked main spin at pc=0x%08X (cache cleared)", live_pc);
                        }
                    }
                }
            }
        }).detach();
    }
    struct WdClear {
        std::atomic<bool>& f;
        ~WdClear() { f = false; }
    } wd_clear{m_watchdog_active};

    if (m_is_running_jit) {
        // Jit::Run is not re-entrant (a32_interface.cpp asserts on it), so a call made from
        // inside a thunk cannot run now. Queue it for the next DrainDeferred instead of
        // dropping it -- this is what used to make IAP credit grants do nothing.
        m_deferred.emplace_back(target_pc, std::vector<uint32_t>(args.begin(), args.end()));
        return 0;
    }

    m_is_running_jit = true;
    struct JitRunningGuard {
        bool& flag;
        Dynarmic::A32::Jit* saved_core;
        ~JitRunningGuard() { flag = false; tl_current_core = saved_core; }
    } running_guard{m_is_running_jit, tl_current_core};
    tl_current_core = m_jit.get();

    // Reset CPU registers for call
    for (size_t i = 0; i < args.size() && i < 4; ++i) {
        m_jit->Regs()[i] = args[i];
    }

    // Stack pointer
    m_jit->Regs()[13] = stack_top;

    // If more than 4 arguments, push onto guest stack
    if (args.size() > 4) {
        size_t extra_args = args.size() - 4;
        uint32_t sp = stack_top - static_cast<uint32_t>(extra_args * 4);
        m_jit->Regs()[13] = sp;
        for (size_t i = 0; i < extra_args; ++i) {
            *reinterpret_cast<uint32_t*>(m_memory + sp + i * 4) = args[4 + i];
        }
    }

    // Return address -> exit trap (with Thumb bit if target is Thumb)
    bool is_thumb = (target_pc & 1) != 0;
    m_jit->Regs()[14] = is_thumb ? (EXIT_TRAP_THUMB | 1) : EXIT_TRAP_ARM;

    // Set PC
    m_jit->Regs()[15] = target_pc & ~1u;
    m_jit->SetCpsr((m_jit->Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));

    m_jit->ClearHalt();
    // Bring-up spin hunt: a finite tick budget makes Run() return with the
    // live PC when the guest runs long; the expiry point names the spin loop.
    // Remove once the game reaches steady state (set budget to 0 to disable).
    // The bring-up spin-hunt budget caused a fatal loop during phase 7: the GL
    // driver construction needs more than 400M ticks, so every quantum expired
    // mid-InitAndroid, Java re-called step(), and initialization restarted
    // forever (leaking one device per attempt). 0 = run until the guest
    // actually returns.
    constexpr uint64_t kSpinHuntBudget = 0;
    m_ticks_unbounded = (kSpinHuntBudget == 0);
    m_ticks_remaining = kSpinHuntBudget ? kSpinHuntBudget : (1ull << 62);
    Dynarmic::HaltReason hr;
    uint32_t cache_invalidation_resumes = 0;
    for (;;) {
        hr = m_jit->Run();
        // Dynarmic stops after processing a requested cache invalidation but
        // leaves the guest CPU state intact. This is a yield point, not a
        // guest function return: continue the same call at its saved PC.
        // Keep combined reasons (e.g. watchdog UserDefined1 | CacheInvalidation)
        // as real halts instead of accidentally swallowing them.
        if (hr != Dynarmic::HaltReason::CacheInvalidation) break;
        ++cache_invalidation_resumes;
    }
    if (cache_invalidation_resumes) {
        static std::atomic<uint64_t> total_cache_invalidation_resumes{0};
        const uint64_t total_before = total_cache_invalidation_resumes.fetch_add(
            cache_invalidation_resumes, std::memory_order_relaxed);
        const uint64_t total_after = total_before + cache_invalidation_resumes;
        if (total_after <= 16 || total_before / 256 != total_after / 256) {
            LOGI("[JIT-CACHE] resumed guest call target=0x%08X after %u invalidation(s), total=%llu",
                 target_pc, cache_invalidation_resumes,
                 static_cast<unsigned long long>(total_after));
        }
    }
    uint32_t final_pc = m_jit->Regs()[15];
    if (kSpinHuntBudget && m_ticks_remaining == 0) {
        static std::atomic<int> expiry_logs{0};
        if (expiry_logs.fetch_add(1) < 12) {
            // Ground truth: the guest words AT the reported PC/LR. If they differ
            // from the file disassembly, memory there was rewritten after load.
            uint32_t pc_words[4] = {0, 0, 0, 0};
            uint32_t lr_word = 0, r1 = m_jit->Regs()[1], r2 = m_jit->Regs()[2], r3 = m_jit->Regs()[3];
            uint8_t at_r0[8] = {0}, at_r1[8] = {0};
            if (final_pc + sizeof(pc_words) <= m_memory_size) {
                memcpy(pc_words, m_memory + final_pc, sizeof(pc_words));
            }
            if (m_jit->Regs()[14] + 4 <= m_memory_size) {
                memcpy(&lr_word, m_memory + m_jit->Regs()[14], 4);
            }
            auto peek = [&](uint32_t addr, uint8_t* out) {
                if (addr < m_memory_size - sizeof(at_r0)) memcpy(out, m_memory + addr, sizeof(at_r0));
            };
            peek(m_jit->Regs()[0], at_r0);
            peek(r1, at_r1);
            LOGI("[SPIN-HUNT] budget expired: entry=0x%08X live PC=0x%08X LR=0x%08X SP=0x%08X r0=0x%08X r1=0x%08X r2=0x%08X r3=0x%08X "
                 "code@[PC]=%08X %08X %08X %08X code@[LR]=%08X [r0]=%02X%02X %02X%02X %02X%02X %02X%02X [r1]=%02X%02X %02X%02X %02X%02X %02X%02X",
                 target_pc, final_pc, m_jit->Regs()[14], m_jit->Regs()[13],
                 m_jit->Regs()[0], r1, r2, r3,
                 pc_words[0], pc_words[1], pc_words[2], pc_words[3], lr_word,
                 at_r0[0], at_r0[1], at_r0[2], at_r0[3], at_r0[4], at_r0[5], at_r0[6], at_r0[7],
                 at_r1[0], at_r1[1], at_r1[2], at_r1[3], at_r1[4], at_r1[5], at_r1[6], at_r1[7]);
        }
    }
    if (final_pc != EXIT_TRAP_ARM && final_pc != (EXIT_TRAP_ARM + 4) &&
        final_pc != (EXIT_TRAP_THUMB & ~1u) && final_pc != ((EXIT_TRAP_THUMB & ~1u) + 2)) {
        if (final_pc == 0) {
            // null vtable call: LR names the site that dereferenced it
            LOGE("[NULL-VCALL] step halted at PC=0 (LR=%08X) - gate/listener object unconstructed",
                 m_jit->Regs()[14]);
        }
        static std::atomic<uint32_t> halt_logs{0};
        uint32_t hk = halt_logs.fetch_add(1, std::memory_order_relaxed) + 1;
        if (hk <= 30 || (hk % 5000) == 0)
            LOGI("RunFunction(0x%08X) unexpected halt with reason=0x%X, PC=0x%08X, LR=0x%08X, R0=0x%08X, SP=0x%08X (#%u)",
                 target_pc, static_cast<unsigned>(hr), final_pc, m_jit->Regs()[14], m_jit->Regs()[0], m_jit->Regs()[13], hk);
    }
    m_last_halt_pc = final_pc;
    m_last_halt_lr = m_jit->Regs()[14];

    m_last_r1 = m_jit->Regs()[1];
    // Bring-up: did initNative store the Application object that nativeStart
    // requires? One-shot dump right after its return. Remove with the rest of
    // the phase-7 bring-up diagnostics.
    if (target_pc == 0x404D1FB0u) {
        static bool logged = false;
        if (!logged) {
            logged = true;
            LOGI("[INIT-PROBE] initNative returned r0=%08X var@41812F40=%08X obj=%08X | probeWords=%08X %08X %08X",
                 m_jit->Regs()[0], MemoryRead32(0x41812F40u), MemoryRead32(MemoryRead32(0x41812F40u)),
                 MemoryRead32(0x408872ECu), MemoryRead32(0x408872F8u), MemoryRead32(0x408872E0u));
        }
    }
    return m_jit->Regs()[0];
}

void DynarmicHost::InvalidateGuestCode(uint32_t addr, size_t size) {
    if (m_jit) m_jit->InvalidateCacheRange(addr, size);
    std::lock_guard<std::mutex> lock(m_worker_cores_mutex);
    for (auto& slot : m_worker_cores)
        if (slot.jit) slot.jit->InvalidateCacheRange(addr, size);
}

void DynarmicHost::DrainDeferred() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_is_running_jit || m_deferred.empty()) return;
    auto batch = std::move(m_deferred);
    m_deferred.clear();
    for (auto& call : batch) {
        LOGI("Running deferred call to 0x%08X", call.first);
        RunFunction(call.first, call.second);
    }
}

// -------------------------------------------------------------
// Guest heap
//
// Every block carries a 16-byte header immediately before its payload:
//   [-16] magic  [-12] block base  [-8] capacity  [-4] payload size
// The magic is what makes GuestFree safe: a pointer that does not carry it is
// not ours (module data, an interior pointer, a stack top, something the guest
// invented) and is ignored -- exactly as a no-op free ignored everything.
// Freeing clears the magic, so a double free is ignored too.
//
// A plain bump allocator with an empty GuestFree is the usual first version and
// it is a guaranteed leak: the guest does call free(), nobody listens. Measured
// on a Scaleform title that was ~1 MB/s during gameplay.
// -------------------------------------------------------------
namespace {
constexpr uint32_t kBlockMagic = 0x41524D31; // 'ARM1' - live block
constexpr uint32_t kFreedMagic = 0x41524D46; // 'ARMF' - already on a free list
constexpr uint32_t kHeaderSize = 16;
}

uint32_t DynarmicHost::GuestThreadTls() {
    const auto tid = std::this_thread::get_id();
    {
        std::lock_guard<std::mutex> lk(m_tls_mutex);
        auto it = m_tls_pages.find(tid);
        if (it != m_tls_pages.end()) return it->second;
    }
    // Allocate outside the lock: GuestAlloc takes m_heap_mutex.
    uint32_t page = GuestAlloc(0x8000, 0x1000);
    if (!page) return 0;
    // Bionic's TLS_SLOT_SELF (slot 0) points back to the array.
    MemoryWrite32(page, page);
    std::lock_guard<std::mutex> lk(m_tls_mutex);
    m_tls_pages[tid] = page;
    return page;
}

uint32_t DynarmicHost::ExistingGuestThreadTls() {
    std::lock_guard<std::mutex> lk(m_tls_mutex);
    const auto it = m_tls_pages.find(std::this_thread::get_id());
    return it != m_tls_pages.end() ? it->second : 0;
}

void DynarmicHost::GuestClearTlsSlotForAllThreads(uint32_t slot) {
    if (slot >= 64) return;
    std::lock_guard<std::mutex> lk(m_tls_mutex);
    for (const auto& [thread, page] : m_tls_pages)
        MemoryWrite32(page + slot * 4u, 0);
}

void DynarmicHost::ReleaseGuestThreadTls() {
    uint32_t page = 0;
    {
        std::lock_guard<std::mutex> lk(m_tls_mutex);
        const auto it = m_tls_pages.find(std::this_thread::get_id());
        if (it == m_tls_pages.end()) return;
        page = it->second;
        m_tls_pages.erase(it);
    }
    GuestFree(page);
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    if (size == 0) size = 1;
    if (alignment < 8) alignment = 8;
    // Worst case layout: header, then up to a full alignment step of padding.
    uint64_t need = static_cast<uint64_t>(size) + alignment + kHeaderSize;

    uint32_t base = 0, capacity = 0;
    bool recycled = false;
    {
        std::lock_guard<std::mutex> lk(m_heap_mutex);
        if (need <= kMaxClassSize) {
            int cls = 0;
            while ((1u << (cls + kMinClassShift)) < need) ++cls;
            capacity = 1u << (cls + kMinClassShift);
            auto& fl = m_free_small[cls];
            if (!fl.empty()) { base = fl.back(); fl.pop_back(); recycled = true; }
        } else {
            capacity = static_cast<uint32_t>((need + 15) & ~15ull);
            auto it = m_free_huge.find(capacity);
            if (it != m_free_huge.end() && !it->second.empty()) {
                base = it->second.back();
                it->second.pop_back();
                recycled = true;
            }
        }
        if (!recycled) {
            // Stop before the heap walks into the guest stacks; when the
            // first window fills, jump above them into the second window
            // (0x80000000-0xA0000000) instead of dying.
            if (static_cast<uint64_t>(m_heap_current) + capacity > kHeapLimit) {
                if (m_heap_current < kHeapWindow2 &&
                    static_cast<uint64_t>(kHeapWindow2) + capacity <= kHeapLimit2) {
                    LOGI("GuestAlloc: first window full at 0x%08X, continuing at 0x%08X",
                         m_heap_current, kHeapWindow2);
                    m_heap_current = kHeapWindow2;
                }
                if (static_cast<uint64_t>(m_heap_current) + capacity > kHeapLimit2) {
                    LOGE("GuestAlloc out of guest heap: at 0x%08X, want %u, limit 0x%08X",
                         m_heap_current, capacity, kHeapLimit2);
                    return 0;
                }
            }
            base = m_heap_current;
            m_heap_current = base + capacity;
        }
    }

    {   // leak hunt (2026-09-17): size-class histogram, logged by the watchdog
        unsigned b = 0;
        size_t v = capacity;
        while ((v >>= 1) && b < 31) ++b;
        g_alloc_buckets[b].fetch_add(1, std::memory_order_relaxed);
        g_alloc_live.fetch_add(1, std::memory_order_relaxed);
    }
    uint32_t payload = static_cast<uint32_t>(
        (static_cast<uint64_t>(base) + kHeaderSize + alignment - 1) & ~(static_cast<uint64_t>(alignment) - 1));
    if (recycled && static_cast<uint64_t>(payload) + size <= m_memory_size) {
        // Fresh arena memory has always been zero, and guest code that leaned on
        // that would break in confusing ways the first time it saw a recycled
        // block. Cheap insurance at the observed churn.
        // RE-ENABLED 2026-09-19: the no-recycle-zero experiment produced a
        // 1M-steps/s hot spin with the stage slot (0x417B7D3C) corrupted to
        // a pointer value (run launch_norecycle2, PID 28974) -- stale-pointer
        // reuse without zeroing is worse. Keep zeroing; the stale-singleton
        // problem needs the per-pass re-init to stop, not memory luck.
        memset(m_memory + payload, 0, size);
    }
    MemoryWrite32(payload - 16, kBlockMagic);
    MemoryWrite32(payload - 12, base);
    MemoryWrite32(payload - 8, capacity);
    MemoryWrite32(payload - 4, static_cast<uint32_t>(size));
    return payload;
}

void DynarmicHost::GuestFree(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return;         // cannot be one of ours
    if (MemoryRead32(addr - 16) != kBlockMagic) {       // foreign pointer, or already freed
        g_free_magic_miss.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_alloc_frees.fetch_add(1, std::memory_order_relaxed);
    g_alloc_live.fetch_sub(1, std::memory_order_relaxed);
    uint32_t base = MemoryRead32(addr - 12);
    uint32_t capacity = MemoryRead32(addr - 8);
    MemoryWrite32(addr - 16, kFreedMagic);

    std::lock_guard<std::mutex> lk(m_heap_mutex);
    if (capacity <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < capacity) ++cls;
        m_free_small[cls].push_back(base);
    } else {
        m_free_huge[capacity].push_back(base);
    }
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return 0;
    if (MemoryRead32(addr - 16) != kBlockMagic) return 0;
    return MemoryRead32(addr - 4);
}

// Address space for the mmap thunk. Separate from the malloc heap on purpose -- see the
// declaration. No free list: a file mapping is handed to the engine for the life of the
// process, and the mmap thunk reuses an identical (file, offset, length) mapping instead of
// making a second one, which is what keeps a re-opened expansion file from costing the arena
// twice.
uint32_t DynarmicHost::GuestAllocMapping(size_t size, size_t alignment) {
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    const uint32_t aligned = (m_map_current + static_cast<uint32_t>(alignment - 1)) &
                             ~static_cast<uint32_t>(alignment - 1);
    if (static_cast<uint64_t>(aligned) + size > kMapLimit) {
        LOGE("GuestAllocMapping out of mapping space: at 0x%08X, want %zu", aligned, size);
        return 0;
    }
    m_map_current = aligned + static_cast<uint32_t>(size);
    return aligned;
}

bool DynarmicHost::GuestMappingContains(uint32_t addr, uint64_t length) {
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    const uint64_t end = static_cast<uint64_t>(addr) + length;
    return length != 0 && addr >= kMapBase && end <= m_map_current &&
           end <= m_memory_size;
}

// Runs once at startup. A silently wrong allocator corrupts the guest far away
// from the cause, so pay a few microseconds to fail loudly at the source.
void DynarmicHost::HeapSelfCheck() {
#define HEAP_CHECK(cond) do { if (!(cond)) { LOGE("HeapSelfCheck FAILED: %s", #cond); ok = false; } } while (0)
    bool ok = true;

    uint32_t a = GuestAlloc(100, 8);
    uint32_t b = GuestAlloc(100, 8);
    HEAP_CHECK(a != 0 && b != 0 && a != b);
    HEAP_CHECK((a & 7) == 0 && (b & 7) == 0);
    HEAP_CHECK(a + 100 <= b - kHeaderSize || b + 100 <= a - kHeaderSize); // no overlap
    HEAP_CHECK(GuestAllocSize(a) == 100);

    uint32_t aligned = GuestAlloc(64, 0x1000);
    HEAP_CHECK(aligned != 0 && (aligned & 0xFFF) == 0);

    // Freed blocks come back, and the payload is handed over zeroed.
    MemoryWrite32(a, 0xDEADBEEF);
    GuestFree(a);
    HEAP_CHECK(GuestAllocSize(a) == 0);        // magic cleared
    GuestFree(a);                              // double free: must be a no-op
    uint32_t reused = GuestAlloc(100, 8);
    HEAP_CHECK(reused == a);
    HEAP_CHECK(MemoryRead32(reused) == 0);

    // Pointers we did not hand out must be ignored, not recycled.
    GuestFree(0x40000000);
    GuestFree(kHeapBase + 4);
    GuestFree(b + 8);                          // interior pointer
    HEAP_CHECK(GuestAllocSize(b) == 100);      // b survived all of that

    // Large blocks recycle by exact capacity instead of rounding to a power of two.
    uint32_t big = GuestAlloc(8 * 1024 * 1024, 0x10000);
    HEAP_CHECK(big != 0 && (big & 0xFFFF) == 0);
    GuestFree(big);
    uint32_t big2 = GuestAlloc(8 * 1024 * 1024, 0x10000);
    HEAP_CHECK(big2 == big);
    GuestFree(big2);

    GuestFree(b);
    GuestFree(reused);
    GuestFree(aligned);
    LOGI("HeapSelfCheck %s", ok ? "OK" : "FAILED");
#undef HEAP_CHECK
}

void DynarmicHost::AddExecutableRange(uint32_t base, uint32_t size) {
    if (!size) return;
    m_code_ranges.emplace_back(base, base + size);
    LOGI("Executable range: 0x%08X..0x%08X", base, base + size);
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t vaddr) {
    // Runaway PC containment. The arena is zero-filled and zeros decode as a valid
    // `andeq r0,r0,r0`, so a jump through a garbage pointer makes the JIT translate
    // a fresh block every 0x8000 bytes forever: RSS runs away and the LMK kills the
    // process, a symptom that reads exactly like a memory leak. Feed the JIT a
    // permanently-undefined instruction instead -- ExceptionRaised halts it and
    // prints where the jump came from.
    //
    // Inside a module only PT_EXEC segments count as code: a fetch from a module's
    // data/rodata/dynstr range means the guest branched through a corrupt function
    // pointer, and executing string bytes there spins forever on a garbage block
    // instead of faulting. Halt with full context on the first such fetch.
    {
        constexpr uint32_t kTrampolineEnd = 0x00020000;
        // Slide logging (2026-09-17): a fetch between the early trap pages
        // and the trampoline area means the guest jumped through a null/
        // garbage vtable slot into the zero page. The zeros decode as an
        // andeq slide; the old build survived it (the slide walks into the
        // trampoline cells whose SVC consumes the wild call and whose
        // BX LR returns to the caller). The earlier halt-here containment
        // KILLED that survival path: the halt aborted the loader pass and
        // wedged the state machine in M2 forever (runs OBB-8/9/10).
        if (vaddr >= 0x1000 && vaddr < 0x10000) {
            uint32_t slide_lr =
                tl_current_core ? tl_current_core->Regs()[14] : 0;
            // The entry-script env dtor's wild virtual slides through the
            // whole zero page (hundreds of JIT blocks) and the follow-up
            // chaos std::terminate's the process ~300 ms later. Halt the
            // frame right here when the slide comes from the movie
            // teardown chain (env dtor / doInitActions /
            // invokeConstructor / instanciateRegisteredClass); the Java
            // loop re-enters cleanly.
            const bool teardown_slide =
                (slide_lr >= 0x40F642DCu && slide_lr < 0x40F64600u) ||
                (slide_lr >= 0x40FDDDE4u && slide_lr < 0x40FDE600u) ||
                (slide_lr >= 0x40F93A38u && slide_lr < 0x40F93C00u);
            static thread_local uint32_t slide_cells = 0;
            if (teardown_slide || ++slide_cells > 4096u) {
                slide_cells = 0;
                static std::atomic<int> dtor_slides{0};
                if (dtor_slides.fetch_add(1, std::memory_order_relaxed) < 12)
                    LOGE("[SLIDE] env-dtor slide lr=0x%08X -> halt frame",
                         slide_lr);
                return (uint32_t)0xE7FEDEFF;
            }
            static thread_local uint32_t slide_start = 0;
            if (slide_start == 0 || vaddr < slide_start || vaddr > slide_start + 0x20000) {
                slide_start = vaddr;
                LOGE("[SLIDE] entry fetch 0x%08X core=%s lr=0x%08X", vaddr,
                     tl_current_core && tl_current_core != m_jit.get() ? "worker" : "main",
                     slide_lr);
            }
        }
        bool in_code = vaddr < kTrampolineEnd || vaddr >= 0xFFFF0000;
        for (const auto& r : m_code_ranges) {
            if (vaddr >= r.first && vaddr < r.second) { in_code = true; break; }
        }
        if (!in_code) {
            auto check_module = [vaddr, &in_code](const ElfLoader* l) {
                if (!l) return false;
                const uint32_t base = l->GetBaseAddress();
                if (vaddr < base || vaddr >= base + l->GetImageSize()) return false;
                for (const auto& seg : l->GetSegments()) {
                    if (seg.flags & 0x1 /* PF_X */ &&
                        vaddr >= base + seg.vaddr && vaddr < base + seg.vaddr + seg.memsz) {
                        in_code = true;
                        break;
                    }
                }
                return true;  // address is inside this module either way
            };
            const bool in_module =
                check_module(m_elf_loader.get()) ||
                check_module(m_fmodex_loader.get()) ||
                check_module(m_fmodevent_loader.get());
            if (in_module && !in_code) {
                static thread_local uint32_t last_reported = 0;
                if (last_reported != vaddr) {
                    last_reported = vaddr;
                    uint32_t sp = 0, r0 = 0, r1 = 0;
                    if (m_jit) { sp = m_jit->Regs()[13]; r0 = m_jit->Regs()[0]; r1 = m_jit->Regs()[1]; }
                    LOGE("[CODE-FETCH-DATA] fetch 0x%08X is inside a module but not in an "
                         "executable segment; LR=0x%08X SP=0x%08X r0=0x%08X r1=0x%08X -- "
                         "guest branched through a bad function pointer",
                         vaddr, m_jit ? m_jit->Regs()[14] : 0, sp, r0, r1);
                    // [CFD-CODE] dump the runtime instruction words around
                    // the return address and at the ASValue::toFunction
                    // entry: a constant .bss fetch target with varying LRs
                    // (0x1072010 boot1, 0xFA70D0 setCtor boot3) means the
                    // called code bytes at runtime differ from the file.
                    {
                        uint32_t lr = m_jit ? m_jit->Regs()[14] : 0;
                        if (lr >= 8 && lr < m_memory_size - 32) {
                            char line[160]; int o = 0;
                            for (int w = 0; w < 8 && o < (int)sizeof(line) - 12; ++w) {
                                uint32_t v;
                                memcpy(&v, m_memory + lr - 8 + w * 4, 4);
                                o += snprintf(line + o, sizeof(line) - o,
                                              " %08X", v);
                            }
                            line[o] = 0;
                            LOGE("[CFD-CODE lr-8=%08X]:%s", lr - 8, line);
                        }
                        uint32_t tf = 0x40000000u + 0x1000E00u;
                        char line2[120]; int o2 = 0;
                        for (int w = 0; w < 4 && o2 < (int)sizeof(line2) - 12; ++w) {
                            uint32_t v;
                            memcpy(&v, m_memory + tf + w * 4, 4);
                            o2 += snprintf(line2 + o2, sizeof(line2) - o2,
                                           " %08X", v);
                        }
                        line2[o2] = 0;
                        LOGE("[CFD-TOFUNC 1000E00]:%s", line2);
                    }
                    // [CFD-STACK] words BELOW and above SP: the POPEQ PC
                    // slot lives at SP-4 (SP is captured after the pop);
                    // the earlier dump started AT SP and missed it.
                    {
                        uint32_t spx = sp;
                        if (spx < 0x100u || spx >= m_memory_size - 256) spx = 0;
                        if (spx) {
                            char line3[700]; int o3 = 0;
                            for (int w = 0; w < 12 && o3 < (int)sizeof(line3) - 14; ++w) {
                                uint32_t v;
                                memcpy(&v, m_memory + spx - 48 + w * 4, 4);
                                o3 += snprintf(line3 + o3, sizeof(line3) - o3,
                                               " -%02X:%08X", 48 - w * 4, v);
                            }
                            for (int w = 0; w < 20 && o3 < (int)sizeof(line3) - 14; ++w) {
                                uint32_t v;
                                memcpy(&v, m_memory + spx + w * 4, 4);
                                o3 += snprintf(line3 + o3, sizeof(line3) - o3,
                                               " +%02X:%08X", w * 4, v);
                            }
                            line3[o3] = 0;
                            LOGE("[CFD-STACK sp=%08X]:%s", spx, line3);
                        }
                    }
                    // Object dump: the first 16 words at r0 (the `this` of the
                    // failed virtual call) identify the garbage member.
                    if (r0 && r0 < m_memory_size - 64) {
                        char line[220]; int o = 0;
                        for (int w = 0; w < 16 && o < (int)sizeof(line) - 14; ++w) {
                            uint32_t v;
                            memcpy(&v, m_memory + r0 + w * 4, 4);
                            o += snprintf(line + o, sizeof(line) - o, " %02X:%08X", w * 4, v);
                        }
                        line[o] = 0;
                        LOGE("[CFD-OBJ r0=%08X]:%s", r0, line);
                    }
                    if (r1 && r1 < m_memory_size - 32) {
                        char line[140]; int o = 0;
                        for (int w = 0; w < 8 && o < (int)sizeof(line) - 14; ++w) {
                            uint32_t v;
                            memcpy(&v, m_memory + r1 + w * 4, 4);
                            o += snprintf(line + o, sizeof(line) - o, " %02X:%08X", w * 4, v);
                        }
                        line[o] = 0;
                        LOGE("[CFD-OBJ r1=%08X]:%s", r1, line);
                    }
                }
                return 0xE7FEDEFFu;  // permanently undefined -> ExceptionRaised halts
            }
            if (!in_module && !in_code) {
                // Wild branch into the heap (UAF'd object -> garbage vtable
                // slot). Halting here aborts the loader pass every frame and
                // wedges the state machine forever (the 0xB8413300 storm).
                // Absorb instead: hand back `bx lr`, so the virtual call
                // returns whatever r0 holds (0 at the observed site -- a
                // null getSize). Same survival trick as the zero-page slide
                // path above. Keep the halt only for unmapped-noise fetches.
                const bool in_heap =
                    (vaddr >= 0x50000000u && vaddr < kHeapWindow2) ||
                    (vaddr >= kHeapWindow2 && vaddr < kHeapLimit2);
                // 2026-09-19: the menu movie's entry-script teardown (the
                // stack ASEnvironment dtor inside SpriteInstance::
                // doInitActions) walks frameslot ASValues, one of which
                // holds a corrupt object pointer; dropRef's virtual call
                // then fetched 0x00A575E4. Halting there killed the whole
                // step: MovieDefImpl::read never finished, Player::getRoot
                // stayed 0, and the movie froze on the preloader frame. The
                // corrupt value only leaks one refcount -- absorb low-region
                // fetches the same way as heap ones.
                const bool in_low = vaddr >= 0x100000u && vaddr < 0x40000000u;
                static std::atomic<uint32_t> runaway_n{0};
                uint32_t k = runaway_n.fetch_add(1, std::memory_order_relaxed) + 1;
                if (k <= 5 || (k % 2000) == 0) {
                    uint32_t lr = 0;
                    if (tl_current_core) lr = tl_current_core->Regs()[14];
                    LOGE("[RUNAWAY] code fetch 0x%08X lr=0x%08X #%u %s", vaddr, lr, k,
                         (in_heap || in_low) ? "absorbed(bx lr)" : "halted");
                }
                if (in_heap || in_low) {
                    // A corrupt object can make the guest call back and
                    // forth between wild slots forever (pc stays a heap
                    // address, the frozen-gate kick ignores it because the
                    // pc is out of the image). Break absorb loops: after
                    // 20000 consecutive absorbed fetches, halt the frame.
                    static thread_local uint32_t absorb_run = 0;
                    if (++absorb_run > 20000u) {
                        absorb_run = 0;
                        LOGE("[RUNAWAY] absorb loop broken at 0x%08X", vaddr);
                        return (uint32_t)0xE7FEDEFF;
                    }
                    return 0xE12FFF1Eu;  // bx lr
                }
                return 0xE7FEDEFFu;               // permanently undefined
            }
        }
    }
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) {
        return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    }
    return std::nullopt;
}

std::uint8_t DynarmicHost::MemoryRead8(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) return m_memory[vaddr];
    return 0;
}

std::uint16_t DynarmicHost::MemoryRead16(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) return *reinterpret_cast<uint16_t*>(m_memory + vaddr);
    return 0;
}

std::uint32_t DynarmicHost::MemoryRead32(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    return 0;
}

std::uint64_t DynarmicHost::MemoryRead64(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) return *reinterpret_cast<uint64_t*>(m_memory + vaddr);
    return 0;
}

void DynarmicHost::MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) m_memory[vaddr] = value;
}

void DynarmicHost::MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) *reinterpret_cast<uint16_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) {
    // __stack_chk_guard lives at guest 0x100 (RegisterSymbol guard). If guest
    // code executing in the low/trap pages stores over it, EVERY stack-canary
    // check in every function starts failing at unrelated points -- exactly
    // the nondeterministic createAndOpenFile deaths. Drop the write, log the
    // writer once.
    if (vaddr == 0x100u) {
        static std::atomic<bool> guard_write{false};
        if (!guard_write.exchange(true)) {
            uint32_t pc = 0;
            if (tl_current_core) pc = tl_current_core->Regs()[15];
            LOGE("[GUARD] write to __stack_chk_guard@0x100 value=%08X dropped, writer PC=%08X lr=%08X",
                 value, pc, tl_current_core ? tl_current_core->Regs()[14] : 0);
        }
        return;
    }
    // [STAGE-WP] Application::Update's init-stage counter (0x17B7D3C)
    // oscillates 0<->1 although every in-Update writer only increments.
    // Log the zero-writers to find the resetter. Bring-up only.
    if (vaddr == 0x417B7D3Cu && value == 0) {
        static std::atomic<uint32_t> stage_zero_writes{0};
        uint32_t k = stage_zero_writes.fetch_add(1, std::memory_order_relaxed) + 1;
        if (k <= 12 || (k % 500) == 0) {
            uint32_t pc = tl_current_core ? tl_current_core->Regs()[15] : 0;
            uint32_t lr = tl_current_core ? tl_current_core->Regs()[14] : 0;
            LOGE("[STAGE-WP] #%u counter <- 0 at PC=%08X lr=%08X", k, pc, lr);
        }
    }
    // [DEF84] root movie def's class slot (invokeConstructor reads it;
    // it stays 0 -> "method is not a function" every frame). Log whoever
    // writes it (or the region around it).
    uint32_t d84 = g_def84_addr.load(std::memory_order_relaxed);
    if (d84 && vaddr >= d84 - 16 && vaddr <= d84 + 16) {
        static std::atomic<uint32_t> d84n{0};
        uint32_t dk = d84n.fetch_add(1, std::memory_order_relaxed) + 1;
        if (dk <= 32) {
            uint32_t pc = 0, lr = 0;
            if (tl_current_core) {
                pc = tl_current_core->Regs()[15];
                lr = tl_current_core->Regs()[14];
            }
            LOGE("[DEF84] %08X <- %08X (pc=%08X lr=%08X) #%u",
                 vaddr, value, pc, lr, dk);
        }
    }
    // [ENV74] entry-script env inline ASValue slots (see g_env74_watch)
    if (g_env74_watch.load(std::memory_order_relaxed) &&
        vaddr >= 0x7EFFF574u && vaddr < 0x7EFFF5D4u) {
        uint32_t k = g_env74_hits.fetch_add(1, std::memory_order_relaxed) + 1;
        if (k <= 64) {
            uint32_t pc = 0, lr = 0;
            if (tl_current_core) {
                pc = tl_current_core->Regs()[15];
                lr = tl_current_core->Regs()[14];
            }
            LOGE("[ENV74-W] %08X <- %08X (pc=%08X lr=%08X)", vaddr, value, pc, lr);
        }
    }
    if (g_relro_on.load(std::memory_order_relaxed) &&
        vaddr >= kRelroStart && vaddr < kRelroEnd) {
        static std::atomic<uint32_t> relro_logs{0};
        uint32_t rk = relro_logs.fetch_add(1, std::memory_order_relaxed);
        if (rk < 24 || (rk % 1000) == 0) {
            uint32_t pc = 0, lr = 0;
            if (tl_current_core) {
                pc = tl_current_core->Regs()[15];
                lr = tl_current_core->Regs()[14];
            }
            LOGE("[RELRO] dropped write %08X <- %08X (pc=%08X lr=%08X) #%u",
                 vaddr, value, pc, lr, rk + 1);
        }
        return;
    }
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) *reinterpret_cast<uint32_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) *reinterpret_cast<uint64_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) {
    LOGE("Interpreter Fallback at 0x%08X", pc);
    m_jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

Dynarmic::A32::Jit& DynarmicHost::CurrentCore() {
    if (tl_current_core) return *tl_current_core;
    return *m_jit;
}

void DynarmicHost::CallSVC(std::uint32_t swi) {
    Dynarmic::A32::Jit& core = CurrentCore();
    if (swi == 0 || core.Regs()[15] <= 0x40) {
        core.HaltExecution(Dynarmic::HaltReason::UserDefined1);
        return;
    }
    m_thunk_manager->DispatchThunk(swi, core);
}

void DynarmicHost::ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) {
    static std::atomic<uint32_t> exc_logs{0};
    uint32_t ek = exc_logs.fetch_add(1, std::memory_order_relaxed) + 1;
    if (ek <= 30 || (ek % 5000) == 0)
        LOGE("Exception at PC: 0x%08X (type %d, core=%s) lr=%08X sp=%08X r0=%08X r1=%08X (#%u)",
             pc, static_cast<int>(exception),
             tl_current_core && tl_current_core != m_jit.get() ? "worker" : "main",
             CurrentCore().Regs()[14], CurrentCore().Regs()[13],
             CurrentCore().Regs()[0], CurrentCore().Regs()[1], ek);
    // One-shot forensic dump: guest code jumped into heap window 2. The usual
    // disease is a UAF'd IReadFile whose vptr was overwritten by reuse; dump
    // the object graph the indirect call was launched from (r12 = object,
    // [r12] = vptr) plus the GuestAlloc block headers around both.
    if (static_cast<int>(exception) == 0 && pc >= kHeapWindow2 && pc < kHeapLimit2) {
        static std::atomic<int> heapedump{0};
        if (heapedump.fetch_add(1, std::memory_order_relaxed) < 2) {
            Dynarmic::A32::Jit& core = CurrentCore();
            uint32_t r0 = core.Regs()[0], r1 = core.Regs()[1], r2 = core.Regs()[2],
                     r3 = core.Regs()[3], r12 = core.Regs()[12], sp = core.Regs()[13];
            auto words = [&](uint32_t base, int n, char* out, size_t cap) {
                int o = 0;
                if (base && GetGuestMemoryBase()) {
                    for (int i = 0; i < n && o < (int)cap - 12; ++i)
                        o += snprintf(out + o, cap - o, " %02X:%08X", i * 4, MemoryRead32(base + i * 4));
                } else {
                    o += snprintf(out + o, cap - o, " (null)");
                }
                out[o] = 0;
            };
            char obj[240], vt[240], ohdr[96], vhdr[96];
            words(r12, 12, obj, sizeof(obj));
            words(MemoryRead32(r12), 10, vt, sizeof(vt));
            words(r12 >= 16 ? r12 - 16 : 0, 4, ohdr, sizeof(ohdr));
            uint32_t vtp = MemoryRead32(r12);
            words(vtp >= 16 ? vtp - 16 : 0, 4, vhdr, sizeof(vhdr));
            LOGE("[HEAPEXEC] pc=%08X r0=%08X r1=%08X r2=%08X r3=%08X r12(obj)=%08X sp=%08X", pc, r0, r1, r2, r3, r12, sp);
            LOGE("[HEAPEXEC] obj:%s", obj);
            LOGE("[HEAPEXEC] vt@%08X:%s", MemoryRead32(r12), vt);
            LOGE("[HEAPEXEC] objhdr:%s vthdr:%s", ohdr, vhdr);
        }
    }
    // One-shot dump for wild branches into the low pages (PC=0x2 = a call
    // through a garbage Thumb function pointer): LR names the call site.
    if (pc < 0x1000) {
        static std::atomic<int> lowdump{0};
        if (lowdump.fetch_add(1, std::memory_order_relaxed) < 2) {
            Dynarmic::A32::Jit& core = CurrentCore();
            uint32_t sp = core.Regs()[13];
            char st[560]; int o = 0;
            for (int i = 0; i < 40 && o < (int)sizeof(st) - 12; ++i)
                o += snprintf(st + o, sizeof(st) - o, " %02X:%08X", i * 4, MemoryRead32(sp + i * 4));
            st[o] = 0;
            LOGE("[LOWPC] pc=%08X lr=%08X r0=%08X r1=%08X r2=%08X r3=%08X r12=%08X sp:%s",
                 pc, core.Regs()[14], core.Regs()[0], core.Regs()[1], core.Regs()[2],
                 core.Regs()[3], core.Regs()[12], st);
            LOGE("[LOWPC] r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X",
                 core.Regs()[4], core.Regs()[5], core.Regs()[6], core.Regs()[7],
                 core.Regs()[8], core.Regs()[9], core.Regs()[10], core.Regs()[11]);
            char names[12][48];
            uint32_t n = m_thunk_manager->CopyRecentThunkNames(names, 12);
            char seq[640]; int q = 0;
            for (uint32_t i = 0; i < n && q < (int)sizeof(seq) - 4; ++i)
                q += snprintf(seq + q, sizeof(seq) - q, "%s ", names[i]);
            seq[q] = 0;
            LOGE("[LOWPC] thunk-seq: %s", seq);
        }
    }
    // Halt the core that raised the exception. Halting the main JIT from a
    // worker exception aborted the main run mid-flight over and over (the
    // app-init retry storm of the 2026-09-17 run).
    CurrentCore().HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::AddTicks(std::uint64_t ticks) {
    if (m_ticks_unbounded) return;
    if (m_ticks_remaining > ticks) m_ticks_remaining -= ticks;
    else m_ticks_remaining = 0;
}

std::uint64_t DynarmicHost::GetTicksRemaining() {
    return m_ticks_remaining;
}

// STREX: the ExclusiveMonitor checks the guest reservation, while the final
// compare/store also has to be atomic against __kuser_cmpxchg on another core.
template<typename T>
static bool GuestCompareAndSwap(uint8_t* mem, size_t mem_size, uint32_t vaddr, T value, T expected) {
    return mc4::GuestAtomicCompareExchange(mem, mem_size, vaddr, expected, value);
}

bool DynarmicHost::MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

// Bring-up PC sampler: every 20 ms capture the live guest PC while the JIT
// runs; every 10 s log the top entries. Remove with phase-7 diagnostics.
void DynarmicHost::StartPcSampler() {
    std::thread([this] {
        pthread_setname_np(pthread_self(), "bridge-pcsmp");
        std::unordered_map<uint32_t, uint32_t> hist;
        auto last_log = std::chrono::steady_clock::now();
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            if (m_is_running_jit && m_jit) {
                uint32_t pc = m_jit->Regs()[15];
                ++hist[pc & ~1u];
            }
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_log).count() >= 10000) {
                last_log = now;
                if (hist.empty()) continue;
                std::vector<std::pair<uint32_t, uint32_t>> v(hist.begin(), hist.end());
                std::sort(v.begin(), v.end(),
                          [](auto& a, auto& b) { return a.second > b.second; });
                char line[256];
                int o = snprintf(line, sizeof(line), "[PC-HIST]");
                for (size_t i = 0; i < v.size() && i < 6; ++i)
                    o += snprintf(line + o, sizeof(line) - o, " %08X x%u",
                                  v[i].first, v[i].second);
                LOGI("%s", line);
                hist.clear();
            }
        }
    }).detach();
}

// Real guest thread execution on a leased JIT. Parked guest threads retain
// their register file and exclusive-monitor slot without excluding peers.
bool DynarmicHost::TryRunWorkerFunction(uint32_t target_pc, const std::vector<uint32_t>& args) {
    bool started = false;
    RunWorkerFunction(target_pc, args, &started);
    return started;
}

uint32_t DynarmicHost::RunWorkerFunction(uint32_t target_pc, const std::vector<uint32_t>& args, bool* started) {
    if (started) *started = false;
    if (!m_jit || !m_monitor) return 0;
    // Refuse data-as-code targets: the ELF header/zero pages decode as an
    // infinite andeq slide and burn the core forever (gotcha 15).
    if ((target_pc & ~1u) < 0x40010000u) {
        LOGE("RunWorkerFunction: refusing data target 0x%08X", target_pc);
        return 0;
    }
    size_t slot_index = kMaxWorkerCores;
    Dynarmic::A32::Jit* core = nullptr;
    {
        std::unique_lock<std::mutex> lock(m_worker_cores_mutex);
        auto free_slot = [this] {
            return std::find_if(m_worker_cores.begin(), m_worker_cores.end(),
                                [](const WorkerCoreSlot& slot) { return !slot.in_use; });
        };
        // Audio cannot wait for a core while holding the guest driver mutex.
        if (started && free_slot() == m_worker_cores.end()) return 0;
        if (!started) m_worker_cores_cv.wait(lock, [&] { return free_slot() != m_worker_cores.end(); });
        slot_index = static_cast<size_t>(free_slot() - m_worker_cores.begin());
        auto& slot = m_worker_cores[slot_index];
        slot.in_use = true;
        try {
            if (!slot.jit) {
                Dynarmic::A32::UserConfig config = m_worker_config;
                config.processor_id = slot_index + 1;
                slot.jit = std::make_unique<Dynarmic::A32::Jit>(config);
            }
        } catch (...) {
            slot.in_use = false;
            lock.unlock();
            m_worker_cores_cv.notify_one();
            throw;
        }
        core = slot.jit.get();
        if (started) *started = true;
    }
    auto release_slot = [&] {
        m_monitor->ClearProcessor(slot_index + 1);
        {
            std::lock_guard<std::mutex> lock(m_worker_cores_mutex);
            m_worker_cores[slot_index].in_use = false;
        }
        m_worker_cores_cv.notify_one();
    };
    struct WorkerCoreGuard {
        Dynarmic::A32::Jit* saved_core;
        ~WorkerCoreGuard() { tl_current_core = saved_core; }
    } worker_core_guard{tl_current_core};
    tl_current_core = core;
    try {
        for (size_t i = 0; i < args.size() && i < 4; ++i)
            core->Regs()[i] = args[i];
        for (size_t i = args.size(); i < 4; ++i)
            core->Regs()[i] = 0;
        for (size_t i = 4; i < 16; ++i)
            core->Regs()[i] = 0;

        // Fixed per-slot stack windows prevent long sessions from advancing
        // the old monotonic stack cursor into the deferred-callback stack.
        uint32_t sp = 0x7E800000u + static_cast<uint32_t>((slot_index + 1) * 0x40000u);
        core->Regs()[13] = sp;
        if (args.size() > 4) {
            size_t extra = args.size() - 4;
            uint32_t asp = sp - static_cast<uint32_t>(extra * 4);
            core->Regs()[13] = asp;
            for (size_t i = 0; i < extra; ++i)
                *reinterpret_cast<uint32_t*>(m_memory + asp + i * 4) = args[4 + i];
        }

        bool is_thumb = (target_pc & 1) != 0;
        core->Regs()[14] = is_thumb ? (EXIT_TRAP_THUMB | 1) : EXIT_TRAP_ARM;
        core->Regs()[15] = target_pc & ~1u;
        core->SetCpsr((core->Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));
        core->ClearHalt();
        Dynarmic::HaltReason hr;
        uint32_t cache_invalidation_resumes = 0;
        for (;;) {
            hr = core->Run();
            // Cache invalidation is a yield, not guest pthread completion.
            if (hr != Dynarmic::HaltReason::CacheInvalidation) break;
            ++cache_invalidation_resumes;
            if (cache_invalidation_resumes <= 4) {
                LOGI("[WORKER-CACHE] resumed #%u at pc=0x%08X",
                     cache_invalidation_resumes, core->Regs()[15]);
            }
        }
        if (cache_invalidation_resumes) {
            LOGI("worker resumed after %u JIT cache invalidation(s): pc=0x%08X",
                 cache_invalidation_resumes, core->Regs()[15]);
        }
        LOGI("worker run done: pc=0x%08X hr=%d", core->Regs()[15],
             static_cast<int>(hr));
        const uint32_t result = core->Regs()[0];
        release_slot();
        return result;
    } catch (...) {
        release_slot();
        throw;
    }
}

namespace {
int InitNativeGuestMutex(pthread_mutex_t* native, int type) {
    pthread_mutexattr_t attr;
    int rc = pthread_mutexattr_init(&attr);
    if (rc) return rc;
    rc = pthread_mutexattr_settype(&attr, type);
    if (!rc) rc = pthread_mutex_init(native, &attr);
    pthread_mutexattr_destroy(&attr);
    return rc;
}

int InitNativeGuestCondition(pthread_cond_t* native, uint32_t word) {
    pthread_condattr_t attr;
    int rc = pthread_condattr_init(&attr);
    if (rc) return rc;
    rc = pthread_condattr_setclock(&attr, (word & 2u) ? CLOCK_MONOTONIC : CLOCK_REALTIME);
    if (!rc) rc = pthread_cond_init(native, &attr);
    pthread_condattr_destroy(&attr);
    return rc;
}
}  // namespace

std::shared_ptr<DynarmicHost::GuestMutex> DynarmicHost::FindGuestMutex(
    uint32_t addr, int& error) {
    if (!GuestRangeValid(m_memory_size, addr, 4)) { error = EINVAL; return {}; }
    std::lock_guard<std::mutex> lock(m_guest_sync_mutex);
    auto it = m_guest_mutexes.find(addr);
    if (it != m_guest_mutexes.end()) { error = 0; return it->second; }
    // ARM32 Bionic static initializers: type bits 14..15, 0/1/2.
    const uint32_t word = MemoryRead32(addr);
    const uint32_t type = word >> 14;
    if ((word & ~0xC000u) || type > 2) { error = EINVAL; return {}; }
    auto value = std::make_shared<GuestMutex>();
    value->type = static_cast<int>(type);
    error = InitNativeGuestMutex(&value->native, value->type);
    if (error) return {};
    m_guest_mutexes.emplace(addr, value);
    return value;
}

int DynarmicHost::GuestMutexInit(uint32_t addr, uint32_t attr_addr) {
    if (!GuestRangeValid(m_memory_size, addr, 4) ||
        (attr_addr && !GuestRangeValid(m_memory_size, attr_addr, 4))) return EINVAL;
    const uint32_t type = attr_addr ? MemoryRead32(attr_addr) : 0;
    if (type > 2) return EINVAL;
    std::lock_guard<std::mutex> lock(m_guest_sync_mutex);
    if (m_guest_mutexes.count(addr)) return EBUSY;
    auto value = std::make_shared<GuestMutex>();
    value->type = static_cast<int>(type);
    const int rc = InitNativeGuestMutex(&value->native, value->type);
    if (rc) return rc;
    m_guest_mutexes.emplace(addr, value);
    MemoryWrite32(addr, type << 14);
    return 0;
}

int DynarmicHost::GuestMutexDestroy(uint32_t addr) {
    int error = 0;
    auto value = FindGuestMutex(addr, error);
    if (!value) return error;
    std::lock_guard<std::mutex> lock(m_guest_sync_mutex);
    if (value.use_count() > 2) return EBUSY;  // map + this call + another user
    const int rc = pthread_mutex_destroy(&value->native);
    if (!rc) {
        m_guest_mutexes.erase(addr);
        MemoryWrite32(addr, 0xDEADC0DEu);
    }
    return rc;
}

int DynarmicHost::GuestMutexLock(uint32_t addr) {
    int error = 0;
    auto value = FindGuestMutex(addr, error);
    if (!value) return error;
    const int rc = pthread_mutex_lock(&value->native);
    if (!rc) {
        std::lock_guard<std::mutex> lock(value->owner_guard);
        const auto self = std::this_thread::get_id();
        if (value->owner == self) ++value->depth;
        else { value->owner = self; value->depth = 1; }
    }
    return rc;
}

int DynarmicHost::GuestMutexTryLock(uint32_t addr) {
    int error = 0;
    auto value = FindGuestMutex(addr, error);
    if (!value) return error;
    const int rc = pthread_mutex_trylock(&value->native);
    if (!rc) {
        std::lock_guard<std::mutex> lock(value->owner_guard);
        const auto self = std::this_thread::get_id();
        if (value->owner == self) ++value->depth;
        else { value->owner = self; value->depth = 1; }
    }
    return rc;
}

int DynarmicHost::GuestMutexUnlock(uint32_t addr) {
    int error = 0;
    auto value = FindGuestMutex(addr, error);
    if (!value) return error;
    std::lock_guard<std::mutex> lock(value->owner_guard);
    if (value->owner != std::this_thread::get_id() || !value->depth) return EPERM;
    const int rc = pthread_mutex_unlock(&value->native);
    if (!rc && --value->depth == 0) value->owner = std::thread::id{};
    return rc;
}

std::shared_ptr<DynarmicHost::GuestCondition> DynarmicHost::FindGuestCondition(
    uint32_t addr, int& error) {
    if (!GuestRangeValid(m_memory_size, addr, 4)) { error = EINVAL; return {}; }
    std::lock_guard<std::mutex> lock(m_guest_sync_mutex);
    auto it = m_guest_conditions.find(addr);
    if (it != m_guest_conditions.end()) { error = 0; return it->second; }
    const uint32_t word = MemoryRead32(addr);
    if (word & ~2u) { error = EINVAL; return {}; }
    auto value = std::make_shared<GuestCondition>();
    error = InitNativeGuestCondition(&value->native, word);
    if (error) return {};
    m_guest_conditions.emplace(addr, value);
    return value;
}

int DynarmicHost::GuestCondInit(uint32_t addr, uint32_t attr_addr) {
    if (!GuestRangeValid(m_memory_size, addr, 4) ||
        (attr_addr && !GuestRangeValid(m_memory_size, attr_addr, 4))) return EINVAL;
    const uint32_t word = attr_addr ? MemoryRead32(attr_addr) : 0;
    if (word & ~2u) return EINVAL;
    std::lock_guard<std::mutex> lock(m_guest_sync_mutex);
    if (m_guest_conditions.count(addr)) return EBUSY;
    auto value = std::make_shared<GuestCondition>();
    const int rc = InitNativeGuestCondition(&value->native, word);
    if (rc) return rc;
    m_guest_conditions.emplace(addr, value);
    MemoryWrite32(addr, word);
    return 0;
}

int DynarmicHost::GuestCondDestroy(uint32_t addr) {
    int error = 0;
    auto value = FindGuestCondition(addr, error);
    if (!value) return error;
    std::lock_guard<std::mutex> lock(m_guest_sync_mutex);
    if (value.use_count() > 2) return EBUSY;
    const int rc = pthread_cond_destroy(&value->native);
    if (!rc) {
        m_guest_conditions.erase(addr);
        MemoryWrite32(addr, 0xDEADC0DEu);
    }
    return rc;
}

int DynarmicHost::GuestCondWait(uint32_t cond_addr, uint32_t mutex_addr,
                               uint32_t abstime_addr, bool timed) {
    timespec deadline{};
    if (timed) {
        if (!GuestRangeValid(m_memory_size, abstime_addr, 8)) return EINVAL;
        const int32_t sec = static_cast<int32_t>(MemoryRead32(abstime_addr));
        const int32_t nsec = static_cast<int32_t>(MemoryRead32(abstime_addr + 4));
        if (nsec < 0 || nsec >= 1000000000) return EINVAL;
        deadline = {sec, nsec};
    }
    int error = 0;
    auto condition = FindGuestCondition(cond_addr, error);
    if (!condition) return error;
    auto mutex = FindGuestMutex(mutex_addr, error);
    if (!mutex) return error;
    {
        std::lock_guard<std::mutex> lock(mutex->owner_guard);
        if (mutex->owner != std::this_thread::get_id()) return EPERM;
        if (mutex->depth != 1) return EINVAL;
        mutex->owner = std::thread::id{};
        mutex->depth = 0;
    }
    // pthread_cond_wait/timedwait atomically releases the native mutex and
    // parks the caller, then reacquires it before returning (also on timeout).
    const int rc = timed ? pthread_cond_timedwait(&condition->native, &mutex->native, &deadline)
                         : pthread_cond_wait(&condition->native, &mutex->native);
    {
        std::lock_guard<std::mutex> lock(mutex->owner_guard);
        mutex->owner = std::this_thread::get_id();
        mutex->depth = 1;
    }
    return rc;
}

int DynarmicHost::GuestCondSignal(uint32_t cond_addr, bool all) {
    int error = 0;
    auto value = FindGuestCondition(cond_addr, error);
    if (!value) return error;
    return all ? pthread_cond_broadcast(&value->native)
               : pthread_cond_signal(&value->native);
}
