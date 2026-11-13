#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "thunks_opensles.h"
#include "elf_loader.h"
#include "mc4_phase3.h"
#include "arm32_printf.h"
#include "apk_vfd_map.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <android/log.h>
#include <atomic>
#include <array>
#include <unordered_map>
#include <set>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <utility>
#include <thread>
#include <chrono>
#include <string>
#include <sstream>

uint32_t ResolveGuestGLProcAddress(DynarmicHost& host, const char* name);

#include <cwchar>
#include <wctype.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <pwd.h>
#include <android/asset_manager.h>
#include <link.h>
#include <sys/system_properties.h>

#define LOG_TAG "Arm32Bridge_Libc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" FILE *funopen(const void *cookie,
                         int (*readfn)(void *, char *, int),
                         int (*writefn)(void *, const char *, int),
                         fpos_t (*seekfn)(void *, fpos_t, int),
                         int (*closefn)(void *));

struct ApkEntry {
    char name[128];
    off_t data_offset;
    off_t file_size;
};

static ApkEntry g_apk_entries[128];
static int g_num_apk_entries = 0;
static char g_apk_indexed_path[1024] = {0};
static int g_apk_indexed_fd = -1;

static std::vector<GuestThreadWorker> g_thread_workers;

// Guest pthread_t is a 32-bit identity, not the host's 64-bit pthread_t.
// Use one allocation source for pthread_create and pthread_self so lock-owner
// comparisons cannot alias every guest worker to the main emulation thread.
static std::atomic<uint32_t> g_next_guest_pthread_id{0x1001u};
static thread_local uint32_t g_current_guest_pthread_id = 0;

struct GuestOnceContinuation {
    uint32_t control;
    uint32_t return_address;
};
static thread_local std::vector<GuestOnceContinuation> g_guest_once_continuations;

struct GuestThreadCompletion {
    std::condition_variable changed;
    uint32_t result = 0;
    bool finished = false;
    bool detached = false;
    bool joining = false;
};
static std::mutex g_guest_threads_mutex;
static std::unordered_map<uint32_t, std::shared_ptr<GuestThreadCompletion>>
    g_guest_threads;

static uint32_t CurrentGuestPthreadId() {
    if (!g_current_guest_pthread_id) {
        g_current_guest_pthread_id = g_next_guest_pthread_id.fetch_add(
            1u, std::memory_order_relaxed);
    }
    return g_current_guest_pthread_id;
}

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers() {
    return g_thread_workers;
}

void AddGuestThreadWorker(uint32_t start_func, uint32_t arg) {
    g_thread_workers.push_back({start_func, arg});
}

struct ApkCookie {
    off_t base_offset;
    off_t file_size;
    off_t current_offset;
};

static int ApkRead(void* cookie, char* buf, int size) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (size <= 0 || !c || g_apk_indexed_fd < 0) return 0;

    if (c->current_offset + size > c->file_size) {
        size = static_cast<int>(c->file_size - c->current_offset);
    }
    if (size <= 0) return 0;

    ssize_t n = pread(g_apk_indexed_fd, buf, size, c->base_offset + c->current_offset);
    if (n > 0) {
        c->current_offset += n;
        return static_cast<int>(n);
    }
    LOGI("ApkRead: size=%d, offset=%lld, n=%zd", size, static_cast<long long>(c->current_offset), n);
    return 0;
}

static fpos_t ApkSeek(void* cookie, fpos_t offset, int whence) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (!c) return -1;
    off_t target = 0;

    if (whence == SEEK_SET) target = offset;
    else if (whence == SEEK_CUR) target = c->current_offset + offset;
    else if (whence == SEEK_END) target = c->file_size + offset;
    else return -1;

    if (target < 0) return -1;
    if (target > c->file_size) target = c->file_size;
    c->current_offset = target;
    return target;
}

static int ApkClose(void* cookie) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (c) {
        free(c);
    }
    return 0;
}

extern "C" int IndexApk(const char* apk_path) {
    if (!apk_path) return -1;
    strncpy(g_apk_indexed_path, apk_path, sizeof(g_apk_indexed_path) - 1);
    if (g_apk_indexed_fd >= 0) close(g_apk_indexed_fd);
    g_apk_indexed_fd = open(g_apk_indexed_path, O_RDONLY);
    if (g_apk_indexed_fd < 0) {
        LOGE("IndexApk: Failed to open APK: %s (errno %d)", g_apk_indexed_path, errno);
        return -1;
    }

    off_t file_len = lseek(g_apk_indexed_fd, 0, SEEK_END);
    if (file_len < 22) return -1;

    off_t search_len = file_len < 65536 + 22 ? file_len : 65536 + 22;
    off_t search_start = file_len - search_len;
    unsigned char* buf = static_cast<unsigned char*>(malloc(search_len));
    if (!buf) return -1;

    pread(g_apk_indexed_fd, buf, search_len, search_start);
    off_t eocd_offset = -1;
    for (ssize_t i = search_len - 22; i >= 0; --i) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4b && buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            eocd_offset = search_start + i;
            break;
        }
    }
    free(buf);

    if (eocd_offset < 0) {
        LOGE("IndexApk: EOCD not found in APK!");
        return -1;
    }

    unsigned char eocd[22];
    pread(g_apk_indexed_fd, eocd, 22, eocd_offset);
    uint16_t num_entries = *reinterpret_cast<uint16_t*>(eocd + 10);
    uint32_t cd_size = *reinterpret_cast<uint32_t*>(eocd + 12);
    uint32_t cd_offset = *reinterpret_cast<uint32_t*>(eocd + 16);

    unsigned char* cd = static_cast<unsigned char*>(malloc(cd_size));
    if (!cd) return -1;
    pread(g_apk_indexed_fd, cd, cd_size, cd_offset);

    g_num_apk_entries = 0;
    uint32_t pos = 0;
    for (int i = 0; i < num_entries && pos + 46 <= cd_size; ++i) {
        if (*reinterpret_cast<uint32_t*>(cd + pos) != 0x02014b50) break;
        uint16_t method = *reinterpret_cast<uint16_t*>(cd + pos + 10);
        uint32_t usize = *reinterpret_cast<uint32_t*>(cd + pos + 24);
        uint16_t fn_len = *reinterpret_cast<uint16_t*>(cd + pos + 28);
        uint16_t extra_len = *reinterpret_cast<uint16_t*>(cd + pos + 30);
        uint16_t comm_len = *reinterpret_cast<uint16_t*>(cd + pos + 32);
        uint32_t local_hdr_offset = *reinterpret_cast<uint32_t*>(cd + pos + 42);

        char fn[256] = {0};
        int cpy = fn_len < 255 ? fn_len : 255;
        memcpy(fn, cd + pos + 46, cpy);

        // Which entries are worth indexing is per-game -- widen this for the archives your
        // engine opens by path. The audio names below came from an FMOD Ex title; ".obb" is
        // here because an expansion file can ship inside the APK instead of being copied to
        // /sdcard/Android/obb (see the fopen fallback and the mmap thunk).
        //
        // Whatever you add MUST be stored uncompressed in the APK (apktool: doNotCompress,
        // aapt: -0): everything below reads raw bytes at the entry offset, so a deflated
        // entry hands the engine compressed garbage with no error anywhere.
        if (strstr(fn, "FMOD") != nullptr || strstr(fn, ".fsb") != nullptr || strstr(fn, ".fev") != nullptr
            || strstr(fn, "assets/data/audio") != nullptr || strstr(fn, ".obb") != nullptr) {
            unsigned char local_hdr[30];
            pread(g_apk_indexed_fd, local_hdr, 30, local_hdr_offset);
            uint16_t l_fn_len = *reinterpret_cast<uint16_t*>(local_hdr + 26);
            uint16_t l_extra_len = *reinterpret_cast<uint16_t*>(local_hdr + 28);
            off_t raw_data_offset = local_hdr_offset + 30 + l_fn_len + l_extra_len;

            if (g_num_apk_entries < 128) {
                strncpy(g_apk_entries[g_num_apk_entries].name, fn, 127);
                g_apk_entries[g_num_apk_entries].data_offset = raw_data_offset;
                g_apk_entries[g_num_apk_entries].file_size = usize;
                LOGI("IndexApk entry [%d]: %s (method=%d, size=%u, offset=%lld)",
                     g_num_apk_entries, fn, method, usize, static_cast<long long>(raw_data_offset));
                g_num_apk_entries++;
            }
        }
        pos += 46 + fn_len + extra_len + comm_len;
    }
    free(cd);
    LOGI("IndexApk: Indexed %d audio entries from APK: %s", g_num_apk_entries, apk_path);
    return 0;
}

static ApkEntry* FindApkEntry(const char* path) {
    if (!path || g_num_apk_entries == 0) return nullptr;
    const char* slash = strrchr(path, '/');
    const char* base = slash ? slash + 1 : path;

    char preferred[256];
    snprintf(preferred, sizeof(preferred), "assets/data/audio/%s", base);
    // Plain assets/<basename>: this is the rule that catches an absolute path the engine
    // built for a file that no longer exists on disk -- e.g. an expansion file the engine
    // still looks for under /storage/emulated/0/Android/obb/<pkg>/ while it actually ships
    // as assets/main.<ver>.<pkg>.obb inside the APK.
    char in_assets[256];
    snprintf(in_assets, sizeof(in_assets), "assets/%s", base);
    for (int i = 0; i < g_num_apk_entries; ++i) {
        if (strcmp(g_apk_entries[i].name, preferred) == 0 || strcmp(g_apk_entries[i].name, path) == 0
            || strcmp(g_apk_entries[i].name, in_assets) == 0) {
            return &g_apk_entries[i];
        }
    }

    // 3. Language suffix fallback (e.g. VOICE.fsb -> VOICE_eng.fsb)
    std::string base_str(base);
    if (base_str.size() > 4 && base_str.substr(base_str.size() - 4) == ".fsb") {
        std::string stem = base_str.substr(0, base_str.size() - 4);
        std::string eng_variant = "assets/data/audio/" + stem + "_eng.fsb";
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (g_apk_entries[i].name == eng_variant || strstr(g_apk_entries[i].name, (stem + "_eng").c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (strstr(g_apk_entries[i].name, stem.c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
    }
    return nullptr;
}

// A file region already laid into the guest arena. The mmap thunk consults this before
// making a new mapping: the arena is bump-allocated, so mapping the same 345 MB expansion
// file a second time is a second permanent hole. Engines do exactly that -- a "reinstall"
// or "reload paks" path closes every archive and reopens it.
struct GuestFileMapping {
    dev_t  dev;
    ino_t  ino;
    off_t  off;      // page-aligned file offset
    size_t span;     // page-aligned length
    uint32_t va;     // guest address
};
static std::vector<GuestFileMapping> g_guest_file_maps;
// APK members are virtual files: their offset/EOF are not those of base.apk.
// Keep their copied views separate from raw-file MAP_FIXED cache entries.
struct GuestVirtualMapping {
    dev_t dev;
    ino_t ino;
    off_t member_offset;
    size_t member_size;
    off_t virtual_offset;
    size_t span;
    uint32_t va;
};
static std::vector<GuestVirtualMapping> g_guest_virtual_maps;
static std::mutex g_mapping_mutex;

struct VirtualFd {
    int real_apk_fd;
    size_t file_size;
    off_t file_offset; // offset within APK
    off_t current_pos; // 0 .. file_size
};
static std::unordered_map<int, VirtualFd> g_vfd_map;
// 1000..1127 belongs to the phase3 VFS host port (VFD_BASE=1000, 128 handles);
// generic APK-stream vfds start above that range.
static int g_next_vfd = 2000;
static std::mutex g_vfd_mutex;

// Guest address of the real archive-open function, resolved by
// InstallAssetOverrideHook and tail-called from the veneer.
static uint32_t g_asset_override_real_fn = 0;

struct GuestFile {
    explicit GuestFile(FILE* value) : stream(value) {}
    FILE* stream;
    std::recursive_mutex mutex;
};
using GuestFileRef = std::shared_ptr<GuestFile>;
static std::unordered_map<uint32_t, GuestFileRef> g_file_map;
static std::mutex g_file_map_mutex;
static uint32_t g_next_file_handle = 0x10001000;

static uint32_t PublishGuestFile(FILE* stream) {
    if (!stream) return 0;
    auto file = std::make_shared<GuestFile>(stream);
    std::lock_guard<std::mutex> lock(g_file_map_mutex);
    uint32_t handle;
    do {
        handle = g_next_file_handle++;
    } while (handle == 0 || g_file_map.find(handle) != g_file_map.end());
    g_file_map.emplace(handle, std::move(file));
    return handle;
}

static GuestFileRef FindGuestFile(uint32_t handle) {
    std::lock_guard<std::mutex> lock(g_file_map_mutex);
    auto it = g_file_map.find(handle);
    return it == g_file_map.end() ? GuestFileRef{} : it->second;
}

static int CloseGuestFile(uint32_t handle) {
    GuestFileRef file;
    {
        std::lock_guard<std::mutex> lock(g_file_map_mutex);
        auto it = g_file_map.find(handle);
        if (it == g_file_map.end()) return -1;
        file = std::move(it->second);
        g_file_map.erase(it);
    }
    std::lock_guard<std::recursive_mutex> lock(file->mutex);
    if (!file->stream) return -1;
    FILE* stream = file->stream;
    file->stream = nullptr;
    return fclose(stream);
}

template <typename Result, typename Operation>
static Result WithGuestFile(uint32_t handle, Result fallback, Operation operation) {
    GuestFileRef file = FindGuestFile(handle);
    if (!file) return fallback;
    std::lock_guard<std::recursive_mutex> lock(file->mutex);
    return file->stream ? operation(file->stream) : fallback;
}

template <typename Operation>
static bool WithGuestFileVoid(uint32_t handle, Operation operation) {
    GuestFileRef file = FindGuestFile(handle);
    if (!file) return false;
    std::lock_guard<std::recursive_mutex> lock(file->mutex);
    if (!file->stream) return false;
    operation(file->stream);
    return true;
}

// Historical 32-bit Bionic uses one 64-slot TLS array per thread. Slots 0..6
// are reserved and pthread_key_create scans 7..63, reusing deleted keys.
// Store values in GuestThreadTls(), not an unrelated host thread_local map:
// the guest may also read the array through __kuser_get_tls.
struct GuestTlsKey {
    bool allocated = false;
    uint32_t destructor = 0;
};
static std::mutex g_guest_tls_keys_mutex;
static std::array<GuestTlsKey, 64> g_guest_tls_keys{};

static void RunGuestTlsDestructors(DynarmicHost& host) {
    const uint32_t tls = host.ExistingGuestThreadTls();
    if (!tls) return;
    // Bionic/POSIX allow destructors to establish values again. Finish each
    // round before deciding whether another pass is needed (maximum four).
    for (unsigned round = 0; round < 4; ++round) {
        unsigned invoked = 0;
        for (uint32_t key = 7; key < g_guest_tls_keys.size(); ++key) {
            uint32_t destructor = 0;
            uint32_t value = 0;
            {
                std::lock_guard lock(g_guest_tls_keys_mutex);
                const GuestTlsKey& entry = g_guest_tls_keys[key];
                if (entry.allocated && entry.destructor) {
                    value = host.MemoryRead32(tls + key * 4u);
                    if (value) {
                        host.MemoryWrite32(tls + key * 4u, 0);
                        destructor = entry.destructor;
                    }
                }
            }
            if (!destructor) continue;
            // Do not hold the key-map lock while running arbitrary guest code.
            host.RunWorkerFunction(destructor, {value});
            ++invoked;
        }
        if (!invoked) break;
    }
}

#undef st_atime
#undef st_mtime
#undef st_ctime
#undef st_atime_nsec
#undef st_mtime_nsec
#undef st_ctime_nsec

// 32-bit ARM Linux/Android struct stat layout
struct Arm32Stat {
    uint32_t st_dev;
    uint32_t st_ino;
    uint16_t st_mode;
    uint16_t st_nlink;
    uint16_t st_uid;
    uint16_t st_gid;
    uint32_t st_rdev;
    uint32_t st_size;
    uint32_t st_blksize;
    uint32_t st_blocks;
    uint32_t st_atime;
    uint32_t st_atime_nsec;
    uint32_t st_mtime;
    uint32_t st_mtime_nsec;
    uint32_t st_ctime;
    uint32_t st_ctime_nsec;
};

static void WriteArm32Stat(uint8_t* guest_base, uint32_t gaddr, const struct stat& st) {
    if (!gaddr) return;
    Arm32Stat* arm_st = reinterpret_cast<Arm32Stat*>(GuestToHost(guest_base, gaddr));
    if (!arm_st) return;
    memset(arm_st, 0, sizeof(Arm32Stat));
    arm_st->st_dev = static_cast<uint32_t>(st.st_dev);
    arm_st->st_ino = static_cast<uint32_t>(st.st_ino);
    arm_st->st_mode = static_cast<uint16_t>(st.st_mode);
    arm_st->st_nlink = static_cast<uint16_t>(st.st_nlink);
    arm_st->st_uid = static_cast<uint16_t>(st.st_uid);
    arm_st->st_gid = static_cast<uint16_t>(st.st_gid);
    arm_st->st_rdev = static_cast<uint32_t>(st.st_rdev);
    arm_st->st_size = static_cast<uint32_t>(st.st_size);
    arm_st->st_blksize = static_cast<uint32_t>(st.st_blksize);
    arm_st->st_blocks = static_cast<uint32_t>(st.st_blocks);
    arm_st->st_atime = static_cast<uint32_t>(st.st_atim.tv_sec);
    arm_st->st_mtime = static_cast<uint32_t>(st.st_mtim.tv_sec);
    arm_st->st_ctime = static_cast<uint32_t>(st.st_ctim.tv_sec);
}

struct GuestPrintfMemory {
    DynarmicHost& host;
    uint32_t Read32(uint32_t address) { return host.MemoryRead32(address); }
    char* Pointer(uint32_t address) {
        return reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), address));
    }
};
struct ScopedHostFd {
    int fd = -1;
    ~ScopedHostFd() { if (fd >= 0) close(fd); }
    ScopedHostFd(const ScopedHostFd&) = delete;
    ScopedHostFd& operator=(const ScopedHostFd&) = delete;
    ScopedHostFd() = default;
};

// This guest uses Bionic's 32-bit TLS layout: slot 2 holds errno. Reuse the
// same per-thread page exposed by __kuser_get_tls, so direct TLS reads and
// __errno() observe exactly one cell for the calling guest thread.
static uint32_t GuestErrnoAddress(DynarmicHost& host) {
    const uint32_t tls = host.GuestThreadTls();
    return tls ? tls + 2u * sizeof(uint32_t) : 0u;
}

static uint32_t ReadGuestErrno(DynarmicHost& host) {
    const uint32_t address = GuestErrnoAddress(host);
    return address ? host.MemoryRead32(address) : 0u;
}

static void WriteGuestErrno(DynarmicHost& host, int error) {
    errno = error;
    const uint32_t address = GuestErrnoAddress(host);
    if (address) host.MemoryWrite32(address, static_cast<uint32_t>(error));
}

static arm32::PrintfResult FinishGuestPrintf(arm32::PrintfResult result, DynarmicHost& host) {
    if (result.error) {
        WriteGuestErrno(host, result.error);
        LOGE("[PRINTF-ABI] format rejected errno=%d", result.error);
    }
    return result;
}

static arm32::PrintfResult FormatGuestString(Dynarmic::A32::Jit& jit,
        DynarmicHost& host, const char* fmt, int first_arg_reg) {
    GuestPrintfMemory memory{host};
    const std::array<uint32_t, 4> registers{
        jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]};
    return FinishGuestPrintf(arm32::FormatPrintf(fmt,
        arm32::PrintfArguments(memory, registers, first_arg_reg, jit.Regs()[13]),
        static_cast<int>(ReadGuestErrno(host))), host);
}

static arm32::PrintfResult FormatGuestVaList(DynarmicHost& host,
        const char* fmt, uint32_t va_list) {
    GuestPrintfMemory memory{host};
    return FinishGuestPrintf(arm32::FormatPrintf(fmt,
        arm32::PrintfArguments(memory, va_list),
        static_cast<int>(ReadGuestErrno(host))), host);
}

// ARM32 bionic sem_t is one 32-bit word: a signed count in bits 1..31 and
// the process-shared flag in bit 0. Using a host LP64 sem_t or a non-atomic
// load/store would change both the ABI and the inter-thread handoff.
static uint32_t* GuestSemWord(DynarmicHost& host, uint32_t addr) {
    if ((addr & 3u) || !GuestRangeValid(host.GetGuestMemorySize(), addr, 4))
        return nullptr;
    return reinterpret_cast<uint32_t*>(host.GetGuestMemoryBase() + addr);
}

static uint32_t GuestSemError(DynarmicHost& host, int error) {
    WriteGuestErrno(host, error);
    return UINT32_MAX;
}

static int32_t GuestSemCount(uint32_t word) {
    return static_cast<int32_t>(word) >> 1;
}

static uint32_t GuestSemInit(DynarmicHost& host, uint32_t addr,
                             uint32_t shared, uint32_t value) {
    uint32_t* word = GuestSemWord(host, addr);
    if (!word || value > SEM_VALUE_MAX) return GuestSemError(host, EINVAL);
    __atomic_store_n(word, (value << 1) | (shared ? 1u : 0u), __ATOMIC_RELAXED);
    return 0;
}

static uint32_t GuestSemTryWait(DynarmicHost& host, uint32_t addr) {
    uint32_t* word = GuestSemWord(host, addr);
    if (!word) return GuestSemError(host, EINVAL);
    uint32_t old = __atomic_load_n(word, __ATOMIC_RELAXED);
    for (;;) {
        if (GuestSemCount(old) <= 0) return GuestSemError(host, EAGAIN);
        const uint32_t next = old - 2u;
        if (__atomic_compare_exchange_n(word, &old, next, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
            return 0;
    }
}

static uint32_t GuestSemWait(DynarmicHost& host, uint32_t addr) {
    uint32_t* word = GuestSemWord(host, addr);
    if (!word) return GuestSemError(host, EINVAL);
    for (;;) {
        uint32_t old = __atomic_load_n(word, __ATOMIC_RELAXED);
        const int32_t count = GuestSemCount(old);
        if (count > 0) {
            if (__atomic_compare_exchange_n(word, &old, old - 2u, false,
                                            __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                return 0;
            continue;
        }
        if (count == 0) {
            const uint32_t waiting = 0xfffffffeu | (old & 1u);
            if (!__atomic_compare_exchange_n(word, &old, waiting, false,
                                             __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                continue;
            old = waiting;
        } else if (count != -1) {
            return GuestSemError(host, EINVAL);
        }
        const int operation = (old & 1u) ? FUTEX_WAIT : FUTEX_WAIT_PRIVATE;
        if (::syscall(SYS_futex, word, operation, old, nullptr, nullptr, 0) == -1 &&
            errno == EINTR)
            return GuestSemError(host, EINTR);
        // EAGAIN means a post arrived before sleep; spurious wakes are also
        // legal. In both cases retry the atomic decrement of the guest word.
    }
}

static uint32_t GuestSemPost(DynarmicHost& host, uint32_t addr) {
    uint32_t* word = GuestSemWord(host, addr);
    if (!word) return GuestSemError(host, EINVAL);
    uint32_t old = __atomic_load_n(word, __ATOMIC_RELAXED);
    for (;;) {
        const int32_t count = GuestSemCount(old);
        if (count == SEM_VALUE_MAX) return GuestSemError(host, EOVERFLOW);
        if (count < -1) return GuestSemError(host, EINVAL);
        const uint32_t next = count < 0 ? (2u | (old & 1u)) : old + 2u;
        if (__atomic_compare_exchange_n(word, &old, next, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)) {
            if (count < 0) {
                const int operation = (old & 1u) ? FUTEX_WAKE : FUTEX_WAKE_PRIVATE;
                ::syscall(SYS_futex, word, operation, INT_MAX, nullptr, nullptr, 0);
            }
            return 0;
        }
    }
}

void ThunkManager::RegisterLibcThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    *reinterpret_cast<uint32_t*>(mem + 0x100) = 0xDEADBEEF;

    RegisterSymbol("__stack_chk_guard", 0x100);
    RegisterSymbol("__sF", 0x200);

    RegisterThunk("__errno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestErrnoAddress(host);
    });

    // -------------------------------------------------------------
    // Additional POSIX & Math Thunks for FMOD
    // -------------------------------------------------------------

    auto read_double_01 = [](const Dynarmic::A32::Jit& jit) -> double {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        return val;
    };
    auto write_double_01 = [](Dynarmic::A32::Jit& jit, double val) {
        uint64_t raw;
        memcpy(&raw, &val, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((raw >> 32) & 0xFFFFFFFF);
    };

    RegisterThunk("sin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sin(read_double_01(jit)));
    });
    RegisterThunk("cos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, cos(read_double_01(jit)));
    });
    RegisterThunk("tan", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, tan(read_double_01(jit)));
    });
    RegisterThunk("acos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, acos(read_double_01(jit)));
    });
    RegisterThunk("atan2", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double y = read_double_01(jit);
        uint64_t raw_x = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double x;
        memcpy(&x, &raw_x, sizeof(double));
        write_double_01(jit, atan2(y, x));
    });
    RegisterThunk("exp", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, exp(read_double_01(jit)));
    });
    RegisterThunk("log", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log(read_double_01(jit)));
    });
    RegisterThunk("log10", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log10(read_double_01(jit)));
    });
    RegisterThunk("log10f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = log10f(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });
    RegisterThunk("pow", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = read_double_01(jit);
        uint64_t raw_y = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double y;
        memcpy(&y, &raw_y, sizeof(double));
        write_double_01(jit, pow(x, y));
    });
    RegisterThunk("sqrt", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sqrt(read_double_01(jit)));
    });
    RegisterThunk("floor", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, floor(read_double_01(jit)));
    });
    RegisterThunk("rint", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, rint(read_double_01(jit)));
    });
    RegisterThunk("lrintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(lrintf(val));
    });
    RegisterThunk("frexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        uint32_t exp_ptr = jit.Regs()[2];
        int exp_val = 0;
        double res = frexp(val, &exp_val);
        if (exp_ptr) host.MemoryWrite32(exp_ptr, static_cast<uint32_t>(exp_val));
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });
    RegisterThunk("ldexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        int exp_val = static_cast<int>(jit.Regs()[2]);
        double res = ldexp(val, exp_val);
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });

    // Memory & Strings
    RegisterThunk("memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        void* h_dst = GuestToHost(host.GetGuestMemoryBase(), dst);
        const void* h_src = GuestToHost(host.GetGuestMemoryBase(), src);
        // Range clamp: see the [MEMCLAMP] note on memset.
        const size_t arena = host.GetGuestMemorySize();
        if (h_dst && h_src && n > 0 &&
            (!GuestRangeValid(arena, dst, n) || !GuestRangeValid(arena, src, n))) {
            uint32_t lim = static_cast<uint32_t>(arena);
            if (dst < lim) lim = dst;
            if (src < lim) lim = src;
            if (lim >= arena) { jit.Regs()[0] = dst; return; }
            n = arena - lim;
        }
        if (h_dst && h_src && n > 0) memmove(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("memmem", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t haystack = jit.Regs()[0];
        uint32_t hlen = jit.Regs()[1];
        uint32_t needle = jit.Regs()[2];
        uint32_t nlen = jit.Regs()[3];
        const void* h_hay = GuestToHost(host.GetGuestMemoryBase(), haystack);
        const void* h_nee = GuestToHost(host.GetGuestMemoryBase(), needle);
        if (h_hay && h_nee && hlen >= nlen) {
            const void* found = memmem(h_hay, hlen, h_nee, nlen);
            if (found) {
                uint32_t offset = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(found) - reinterpret_cast<const uint8_t*>(h_hay));
                jit.Regs()[0] = haystack + offset;
                return;
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("strcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src) strcat(h_dst, h_src);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src && n > 0) strncpy(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s1 = jit.Regs()[0];
        uint32_t s2 = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        const char* h_s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s1));
        const char* h_s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s2));
        jit.Regs()[0] = (h_s1 && h_s2) ? static_cast<uint32_t>(strncasecmp(h_s1, h_s2, n)) : 0;
    });
    RegisterThunk("strtol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t nptr = jit.Regs()[0];
        uint32_t endptr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        const char* h_nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), nptr));
        if (!h_nptr) { jit.Regs()[0] = 0; return; }
        char* h_end = nullptr;
        long val = strtol(h_nptr, &h_end, base);
        if (endptr && h_end) {
            uint32_t offset = static_cast<uint32_t>(h_end - h_nptr);
            host.MemoryWrite32(endptr, nptr + offset);
        }
        jit.Regs()[0] = static_cast<uint32_t>(val);
    });
    RegisterThunk("puts", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s = jit.Regs()[0];
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s));
        if (str) LOGI("[puts] %s", str);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("vsnprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t buf = jit.Regs()[0];
        uint32_t size = jit.Regs()[1];
        uint32_t fmt = jit.Regs()[2];
        char* h_buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), buf));
        const char* h_fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), fmt));
        const auto formatted = FormatGuestVaList(host, h_fmt, jit.Regs()[3]);
        jit.Regs()[0] = static_cast<uint32_t>(
            arm32::CopyPrintfResult(h_buf, size, formatted));
    });

    // Time & Threading
    RegisterThunk("gettimeofday", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t tv_ptr = jit.Regs()[0];
        if (tv_ptr) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            host.MemoryWrite32(tv_ptr + 0, static_cast<uint32_t>(tv.tv_sec));
            host.MemoryWrite32(tv_ptr + 4, static_cast<uint32_t>(tv.tv_usec));
        }
        jit.Regs()[0] = 0;
    });
    // Guest VoxThread::Sleep(1) reaches this with 1000 microseconds while
    // waiting for an AccessController writer. Returning immediately turns
    // the guest's bounded wait into a CPU-intensive spin, delaying other
    // threads without making progress on the writer flag.
    RegisterThunk("usleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const useconds_t microseconds = static_cast<useconds_t>(jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(::usleep(microseconds));
    });
    RegisterThunk("lrand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(lrand48());
    });
    RegisterThunk("srand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        srand48(static_cast<long>(jit.Regs()[0]));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("utime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("unlink", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("chown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("fcntl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // Semaphores & Pthread
    RegisterThunk("sem_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestSemInit(host, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
    });
    RegisterThunk("sem_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestSemWord(host, jit.Regs()[0]) ? 0u : GuestSemError(host, EINVAL);
    });
    RegisterThunk("sem_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestSemWait(host, jit.Regs()[0]);
    });
    RegisterThunk("sem_trywait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestSemTryWait(host, jit.Regs()[0]);
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestSemPost(host, jit.Regs()[0]);
    });
    RegisterThunk("sem_getvalue", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t* word = GuestSemWord(host, jit.Regs()[0]);
        const uint32_t value_out = jit.Regs()[1];
        if (!word || !GuestRangeValid(host.GetGuestMemorySize(), value_out, 4)) {
            jit.Regs()[0] = GuestSemError(host, EINVAL);
            return;
        }
        const int32_t count = GuestSemCount(__atomic_load_n(word, __ATOMIC_SEQ_CST));
        host.MemoryWrite32(value_out, static_cast<uint32_t>(std::max(count, 0)));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_self", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t id = CurrentGuestPthreadId();
        static thread_local bool logged = false;
        if (!logged) {
            LOGI("[PTHREAD-ID] pthread_self guest=0x%08X", id);
            logged = true;
        }
        jit.Regs()[0] = id;
    });
    RegisterThunk("pthread_attr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 4)) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        // flags is word zero of bionic's 32-bit pthread_attr_t.
        host.MemoryWrite32(jit.Regs()[0], 0);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 4) ? 0 : EINVAL;
    });
    RegisterThunk("pthread_attr_setdetachstate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t attr = jit.Regs()[0];
        const uint32_t state = jit.Regs()[1];
        if (!GuestRangeValid(host.GetGuestMemorySize(), attr, 4) ||
            state > PTHREAD_CREATE_DETACHED) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        const uint32_t flags = host.MemoryRead32(attr);
        host.MemoryWrite32(attr, (flags & ~1u) | state);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setstacksize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestMutexInit(jit.Regs()[0], jit.Regs()[1]);
    });
    RegisterThunk("pthread_mutex_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestMutexDestroy(jit.Regs()[0]);
    });
    RegisterThunk("pthread_mutexattr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 4)) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        host.MemoryWrite32(jit.Regs()[0], PTHREAD_MUTEX_NORMAL);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_settype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 4) ||
            jit.Regs()[1] > PTHREAD_MUTEX_ERRORCHECK) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        host.MemoryWrite32(jit.Regs()[0], jit.Regs()[1]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t thread_out = jit.Regs()[0];
        uint32_t attr = jit.Regs()[1];
        uint32_t start_func = jit.Regs()[2];
        uint32_t arg = jit.Regs()[3];
        if (!GuestRangeValid(host.GetGuestMemorySize(), thread_out, 4) ||
            (attr && !GuestRangeValid(host.GetGuestMemorySize(), attr, 4)) ||
            !start_func) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        const bool detached = attr && (host.MemoryRead32(attr) & 1u);
        uint32_t id = g_next_guest_pthread_id.fetch_add(
            1u, std::memory_order_relaxed);
        auto completion = std::make_shared<GuestThreadCompletion>();
        completion->detached = detached;
        {
            std::lock_guard lock(g_guest_threads_mutex);
            g_guest_threads.emplace(id, completion);
        }
        LOGI("pthread_create: REAL guest thread id=0x%08X func=0x%08X arg=0x%08X",
             id, start_func, arg);
        // A dedicated worker JIT/monitor slot runs this entry concurrently
        // with the main core and other live guest workers.
        try {
            std::thread([host_ptr = &host, start_func, arg, id, completion]() {
                g_current_guest_pthread_id = id;
                std::string name = "guest-t" + std::to_string(id - 0x1000u);
                pthread_setname_np(pthread_self(), name.c_str());
                BridgeAttachCurrentThread();
                uint32_t result = UINT32_MAX;
                try {
                    result = host_ptr->RunWorkerFunction(start_func, {arg});
                    LOGI("guest thread #%u finished, r0=0x%08X", id, result);
                    RunGuestTlsDestructors(*host_ptr);
                } catch (const std::exception& e) {
                    LOGE("guest thread #%u threw: %s", id, e.what());
                } catch (...) {
                    LOGE("guest thread #%u threw (non-std)", id);
                }
                host_ptr->ReleaseGuestThreadTls();
                {
                    std::lock_guard lock(g_guest_threads_mutex);
                    completion->result = result;
                    completion->finished = true;
                    if (completion->detached) g_guest_threads.erase(id);
                }
                completion->changed.notify_all();
            }).detach();
        } catch (const std::system_error& e) {
            std::lock_guard lock(g_guest_threads_mutex);
            g_guest_threads.erase(id);
            LOGE("pthread_create host thread failed: %s", e.what());
            jit.Regs()[0] = EAGAIN;
            return;
        }
        host.MemoryWrite32(thread_out, id);
        jit.Regs()[0] = 0;
    });

    // Sockets & Net (Stubs)
    RegisterThunk("socket", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("bind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("listen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("accept", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("connect", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("send", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("recv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("select", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("setsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("inet_addr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("gethostbyname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Android & Runtime
    RegisterThunk("__android_log_write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        uint32_t tag_ptr = jit.Regs()[1];
        uint32_t msg_ptr = jit.Regs()[2];
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), tag_ptr));
        const char* msg = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), msg_ptr));
        if (tag && msg) __android_log_write(prio, tag, msg);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("__aeabi_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_pure_virtual", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("__cxa_pure_virtual called!");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("__cxa_type_match", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_begin_cleanup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_call_unexpected", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_Unwind_Find_exidx", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t name_ptr = jit.Regs()[0];
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), name_ptr));
        LOGI("dlopen('%s', %d)", name ? name : "NULL", jit.Regs()[1]);
        jit.Regs()[0] = 0x50005000; // Non-null handle
    });
    RegisterThunk("dlclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlsym", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sym_ptr = jit.Regs()[1];
        const char* sym = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), sym_ptr));
        LOGI("dlsym(handle, '%s')", sym ? sym : "NULL");
        if (sym) {
            if (strncmp(sym, "gl", 2) == 0 && sym[2] >= 'A' && sym[2] <= 'Z') {
                jit.Regs()[0] = ResolveGuestGLProcAddress(host, sym);
                return;
            }
            if (strncmp(sym, "SL_IID_", 7) == 0) {
                uint32_t iid_ptr = GetOpenSLESInterfacePointer(sym);
                if (iid_ptr != 0) {
                    jit.Regs()[0] = iid_ptr;
                    return;
                }
            }
            if (strcmp(sym, "slCreateEngine") == 0) {
                jit.Regs()[0] = host.GetThunkManager().GetOrCreateThunkAddress("slCreateEngine");
                return;
            }
            auto it = host.GetThunkManager().GetThunkSymbolTable().find(sym);
            if (it != host.GetThunkManager().GetThunkSymbolTable().end()) {
                jit.Regs()[0] = it->second;
                return;
            }
            if (host.GetFmodEventLoader()) {
                uint32_t addr = host.GetFmodEventLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            if (host.GetFmodExLoader()) {
                uint32_t addr = host.GetFmodExLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            uint32_t addr = host.GetThunkManager().GetOrCreateThunkAddress(sym);
            jit.Regs()[0] = addr;
            return;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("__system_property_get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t val_ptr = jit.Regs()[1];
        LOGI("__system_property_get('%s')", name ? name : "null");
        if (name && val_ptr) {
            char* out = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), val_ptr));
            if (strcmp(name, "ro.build.version.sdk") == 0) {
                strcpy(out, "28");
                jit.Regs()[0] = 2;
                return;
            }
            strcpy(out, "");
        }
        jit.Regs()[0] = 0;
    });

    // C++ Memory Allocation operators
    RegisterThunk("_Znaj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_Znwj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnajRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnwjRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZdaPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZdlPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZNSt8ios_base4InitC1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_ZNSt8ios_base4InitD1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // Bring-up: install a fake glitch::os::ILogger so the engine's own
    // Printer::logf/log diagnostics print through the bridge. The logger
    // object pointer lives in the GOT slot at guest 0x179D384; Printer::logf
    // calls vtbl[9] (0x24) as logf(logger, level, fmt, va). Remove with
    // the rest of the phase-7 bring-up diagnostics.
    {
        uint32_t sink = RegisterThunk("glitch_ILogger_sink",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                uint32_t level = jit.Regs()[1];
                uint32_t fmt_g = jit.Regs()[2];
                uint32_t va_g = jit.Regs()[3];
                char a1[16] = "?", a2[16] = "?", a3[16] = "?";
                if (host.GetGuestMemoryBase() && va_g) {
                    snprintf(a1, sizeof(a1), "%08X", host.MemoryRead32(va_g));
                    snprintf(a2, sizeof(a2), "%08X", host.MemoryRead32(va_g + 4));
                    snprintf(a3, sizeof(a3), "%08X", host.MemoryRead32(va_g + 8));
                }
                const char* fmt = fmt_g ? reinterpret_cast<const char*>(host.GetGuestMemoryBase() + fmt_g) : "(null)";
                LOGE("[GLITCH] lvl=%u fmt='%s' va=[%s %s %s]", level, fmt, a1, a2, a3);
                jit.Regs()[0] = 0;
            });
        uint32_t vtbl = m_host.GuestAlloc(64, 4);
        for (int i = 0; i < 16; ++i) m_host.MemoryWrite32(vtbl + i * 4, sink);
        uint32_t obj = m_host.GuestAlloc(8, 4);
        m_host.MemoryWrite32(obj, vtbl);
        m_host.MemoryWrite32(0x40000000u + 0x179D384u, obj);
        LOGI("[GLITCH] fake ILogger installed: obj=%08X vtbl=%08X sink=%08X", obj, vtbl, sink);
    }

    // Memory Allocation inside guest space
    RegisterThunk("malloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        // Bring-up heap probe: every 128 MiB of fresh arena, report the top
        // return addresses so a runaway allocation names its caller. Remove
        // with the rest of the phase-7 bring-up diagnostics.
        static std::mutex m;
        static uint64_t total = 0;
        static std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>> sites;
        {
            std::lock_guard<std::mutex> lock(m);
            total += size;
            // Bring-up stage watchpoint: catch the counter's transitions and the
            // return address active when it drops back to zero. Remove with the
            // rest of the phase-7 bring-up diagnostics.
            if (host.GetGuestMemoryBase()) {
                static uint32_t shadow = 0xFFFFFFFFu;
                static int seen = 0;
                uint32_t stage = *reinterpret_cast<uint32_t*>(host.GetGuestMemoryBase() + 0x417B7D3Cu);
                if (stage != shadow) {
                    if (++seen <= 60) {
                        LOGI("[STAGE-WATCH] %08X -> %08X at LR=%08X SP=%08X",
                             shadow, stage, jit.Regs()[14], jit.Regs()[13]);
                    }
                    shadow = stage;
                }
                // Tamper check: did anything restore the probe instructions?
                static int probe_checked = 0;
                if (probe_checked < 3) {
                    ++probe_checked;
                    auto R = [&](uint32_t va) {
                        return *reinterpret_cast<uint32_t*>(host.GetGuestMemoryBase() + va);
                    };
                    LOGI("[MEM-CHECK] nS=%08X nS+0x10=%08X drmLog=%08X drmLog+4=%08X Update=%08X PLT=%08X",
                         R(0x404D21DCu), R(0x404D21ECu), R(0x404D2B28u), R(0x404D2B2Cu),
                         R(0x40886E20u), R(0x4049A608u));
                }
            }
            auto& s = sites[jit.Regs()[14]];
            s.first += 1;
            s.second += size;
            // Walk: dump caller chain for the top churn author (operator new
            // caller inside the leaking path). Remove with phase-7 diagnostics.
            if (jit.Regs()[14] == 0x404F6148u) {
                static uint32_t nw_count = 0;
                if (++nw_count == 4000000u) {
                    std::string stk;
                    uint32_t sp2 = jit.Regs()[13];
                    for (int i = -2; i < 24; ++i) {
                        char b[24];
                        snprintf(b, sizeof(b), " %+d:%08X", i * 4, host.MemoryRead32(sp2 + i * 4));
                        stk += b;
                    }
                    LOGE("[NEW-WALK] op-new caller stack (sp=%08X):%s", sp2, stk.c_str());
                }
            }
            // Bring-up: the GL driver construction site (createOpenGLES2Driver)
            // is the leak's author; count its mallocs and pair them with the
            // Application::Update stage counter. Remove with phase-7 diagnostics.
            if (jit.Regs()[14] == 0x41175D24u) {
                static uint32_t drv_mallocs = 0;
                if (++drv_mallocs % 500 == 0) {
                    uint32_t stage = 0;
                    if (host.GetGuestMemoryBase()) {
                        stage = *reinterpret_cast<uint32_t*>(host.GetGuestMemoryBase() + 0x417B7D3Cu);
                    }
                    // Compact stack dump: only non-zero words within the first
                    // 2800 bytes above sp (Update's own frame is ~1.8 KB).
                    std::string stk;
                    uint32_t sp = jit.Regs()[13];
                    for (int i = 0; i < 700; ++i) {
                        uint32_t w = host.MemoryRead32(sp + i * 4);
                        if (w) {
                            char b[24];
                            snprintf(b, sizeof(b), " +%03X:%08X", i * 4, w);
                            stk += b;
                        }
                    }
                    LOGI("[DRIVER-LOOP] m=%u stage=%u SP=%08X nz:%s",
                         drv_mallocs, stage, sp, stk.c_str());
                }
            }
            if (total / (128ull << 20) != (total - size) / (128ull << 20)) {
                std::vector<std::pair<uint32_t, std::pair<uint64_t, uint64_t>>> top(sites.begin(), sites.end());
                std::partial_sort(top.begin(), top.begin() + std::min<size_t>(8, top.size()), top.end(),
                                  [](const auto& a, const auto& b) { return a.second.second > b.second.second; });
                std::string line;
                for (size_t i = 0; i < std::min<size_t>(8, top.size()); ++i) {
                    char buf[48];
                    snprintf(buf, sizeof(buf), " LR=0x%08X n=%llu b=%llu", top[i].first,
                             (unsigned long long)top[i].second.first, (unsigned long long)top[i].second.second);
                    line += buf;
                }
                LOGI("[HEAP] cumulative %.1f MiB, heaptop authors:%s",
                     total / 1048576.0, line.c_str());
            }
        }
        // Size cap (mirrors the guest fast-malloc stub): a garbage request
        // (PerksMP count*8 = 4.27 GB) that bypasses the stub enters the host
        // allocator directly and wedged it for 40 s per call
        // (WATCHDOG: thunk=malloc r0=0xFDE00001, run 2026-09-19 00:47).
        if (size > (64u << 20)) {
            static std::atomic<uint32_t> cap_n{0};
            uint32_t k = cap_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 6 || (k % 1000) == 0)
                LOGE("[MALLOCCAP] malloc(%zu) from LR=%08X capped to 64 bytes #%u",
                     size, jit.Regs()[14], k);
            size = 0x40;
        }
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("calloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t num = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        size_t bytes = num * size;
        if (bytes > (64u << 20)) {
            static std::atomic<uint32_t> cap_n{0};
            uint32_t k = cap_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 6 || (k % 1000) == 0)
                LOGE("[MALLOCCAP] calloc(%zu,%zu) from LR=%08X capped to 64 bytes #%u",
                     num, size, jit.Regs()[14], k);
            bytes = 0x40;
        }
        uint32_t addr = host.GuestAlloc(bytes, 8);
        if (addr) {
            memset(GuestToHost(host.GetGuestMemoryBase(), addr), 0, bytes);
        }
        jit.Regs()[0] = addr;
    });

    RegisterThunk("realloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t old_addr = jit.Regs()[0];
        size_t new_size = jit.Regs()[1];
        uint32_t new_addr = host.GuestAlloc(new_size, 8);
        if (old_addr && new_addr) {
            // Standard realloc copies min(old, new) and releases the old block;
            // leaking it here drained the guest arena during menu load.
            size_t old_size = host.GuestAllocSize(old_addr);
            memcpy(GuestToHost(host.GetGuestMemoryBase(), new_addr),
                   GuestToHost(host.GetGuestMemoryBase(), old_addr),
                   std::min(old_size, new_size));
            host.GuestFree(old_addr);
        }
        jit.Regs()[0] = new_addr;
    });

    RegisterThunk("free", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("memalign", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t alignment = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        if (size > (64u << 20)) {
            static std::atomic<uint32_t> cap_n{0};
            uint32_t k = cap_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 6 || (k % 1000) == 0)
                LOGE("[MALLOCCAP] memalign(%zu,%zu) capped to 64 bytes #%u",
                     alignment, size, k);
            size = 0x40;
        }
        jit.Regs()[0] = host.GuestAlloc(size, alignment);
    });

    // Logging & Formatted output
    RegisterThunk("__android_log_print", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const auto formatted = FormatGuestString(jit, host, fmt, 3);
        if (!formatted.error)
            __android_log_print(prio, tag ? tag : "Arm32Bridge_Guest", "[GUEST] %s", formatted.text.c_str());
        jit.Regs()[0] = static_cast<uint32_t>(formatted.Count());
    });

    RegisterThunk("printf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const auto formatted = FormatGuestString(jit, host, fmt, 1);
        if (!formatted.error) LOGI("[printf] %s", formatted.text.c_str());
        jit.Regs()[0] = static_cast<uint32_t>(formatted.Count());
    });

    RegisterThunk("fprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const auto formatted = FormatGuestString(jit, host, fmt, 2);
        if (!formatted.error) LOGI("[fprintf] %s", formatted.text.c_str());
        jit.Regs()[0] = static_cast<uint32_t>(formatted.Count());
    });

    RegisterThunk("sprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const auto formatted = FormatGuestString(jit, host, fmt, 2);
        jit.Regs()[0] = static_cast<uint32_t>(arm32::CopyPrintfResult(
            str, formatted.text.size() + 1, formatted));
    });

    RegisterThunk("snprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t size = jit.Regs()[1];
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const auto formatted = FormatGuestString(jit, host, fmt, 3);
        jit.Regs()[0] = static_cast<uint32_t>(arm32::CopyPrintfResult(str, size, formatted));
    });

    // Minimal ANSI sscanf: the Glitch version checks (GL_VERSION/GLSL parse in
    // CGLSLShaderHandler::doVersionCheck) die without it - a returning-0 stub
    // made doVersionCheck fail forever and the driver re-created every frame.
    // Supports whitespace, literals, %% , %d/%i/%u/%x/%o, %f/%g/%e (host float
    // written as float), %s, '*' suppression, field width, 'l'/'h' length.
    RegisterThunk("sscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* f = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!s || !f) { jit.Regs()[0] = 0; return; }
        uint32_t args[6] = { jit.Regs()[2], jit.Regs()[3],
                             host.MemoryRead32(jit.Regs()[13]),
                             host.MemoryRead32(jit.Regs()[13] + 4),
                             host.MemoryRead32(jit.Regs()[13] + 8),
                             host.MemoryRead32(jit.Regs()[13] + 12) };
        int assigned = 0, ai = 0;
        auto skipws = [&s]() { while (*s == ' ' || (*s >= 9 && *s <= 13)) ++s; };
        while (*f) {
            if (*f == ' ') { skipws(); ++f; continue; }
            if (*f != '%') { if (*s == *f) { ++s; ++f; continue; } break; }
            ++f;
            bool sup = false;
            if (*f == '*') { sup = true; ++f; }
            int width = 0;
            while (*f >= '0' && *f <= '9') { width = width * 10 + (*f - '0'); ++f; }
            bool lng = false;
            while (*f == 'l' || *f == 'h') { lng |= (*f == 'l'); ++f; }
            char conv = *f;
            if (!conv) break;
            ++f;
            if (conv == '%') { if (*s == '%') ++s; else break; continue; }
            skipws();
            if (!*s) break;
            if (conv == 'd' || conv == 'i' || conv == 'u' || conv == 'x' || conv == 'o') {
                long long v = 0; bool neg = false, any = false; int base = 10;
                if (conv == 'x' || conv == 'o') base = (conv == 'x') ? 16 : 8;
                if (*s == '-') { neg = true; ++s; } else if (*s == '+') ++s;
                if (*s == '0' && (s[1] == 'x' || s[1] == 'X') && base != 8) { base = 16; s += 2; }
                for (; *s; ++s) {
                    int d; char c = *s;
                    if (c >= '0' && c <= '9') d = c - '0';
                    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                    else break;
                    if (d >= base) break;
                    v = v * base + d; any = true;
                    (void)width;
                }
                (void)any;
                if (neg) v = -v;
                if (!sup && ai < 6) { host.MemoryWrite32(args[ai], (uint32_t)(v & 0xFFFFFFFFu)); ++assigned; ++ai; }
                else if (sup) { ++assigned; }
                continue;
            }
            if (conv == 'f' || conv == 'g' || conv == 'e') {
                // parse double: [-]digits[.digits][eE[+-]digits]
                const char* start = s;
                if (*s == '-' || *s == '+') ++s;
                const char* digits = s;
                while (*s >= '0' && *s <= '9') ++s;
                if (*s == '.') { ++s; while (*s >= '0' && *s <= '9') ++s; }
                if (s == digits) break;
                if (*s == 'e' || *s == 'E') { ++s; if (*s == '+' || *s == '-') ++s; while (*s >= '0' && *s <= '9') ++s; }
                double v = strtod(start, nullptr);
                if (!sup && ai < 6) {
                    if (lng) *reinterpret_cast<double*>(GuestToHost(host.GetGuestMemoryBase(), args[ai])) = v;
                    else *reinterpret_cast<float*>(GuestToHost(host.GetGuestMemoryBase(), args[ai])) = (float)v;
                    ++assigned; ++ai;
                }
                continue;
            }
            if (conv == 's') {
                if (!sup && ai < 6) {
                    char* out = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), args[ai]));
                    int n = 0;
                    while (*s && *s != ' ' && (*s < 9 || *s > 13)) {
                        if (width && n >= width) break;
                        if (out && n < 4095) out[n] = *s;
                        ++s; ++n;
                    }
                    if (out && n < 4096) out[n] = 0;
                    ++assigned; ++ai;
                }
                continue;
            }
            break; // unsupported conversion
        }
        jit.Regs()[0] = static_cast<uint32_t>(assigned);
    });
    RegisterThunk("vfprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("vasprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("putc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });
    RegisterThunk("fputc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });

    // fputs(const char *s, FILE *stream). Lesson 2.16: on Android fd 1 and 2 go nowhere, and
    // that is exactly where a C++ runtime writes the reason it is giving up. A stream the
    // guest really opened is written for real; anything else goes to the log instead of being
    // swallowed. In Angry Birds Go this was the last default stub still firing on a cold
    // start, and the first run with a real thunk printed what had been thrown away for
    // weeks: "io::IOException".
    RegisterThunk("fputs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!s) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        if (auto file = FindGuestFile(jit.Regs()[1])) {
            std::lock_guard<std::recursive_mutex> lock(file->mutex);
            if (file->stream) {
                jit.Regs()[0] = static_cast<uint32_t>(fputs(s, file->stream));
                return;
            }
        }
        LOGI("[guest fputs] %s", s);
        jit.Regs()[0] = static_cast<uint32_t>(strlen(s));
    });

    // Math functions
    RegisterThunk("sinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sinf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("cosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = cosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("sqrtf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sqrtf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("atanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = atanf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("acosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = acosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("powf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float base = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float exp = *reinterpret_cast<float*>(&jit.Regs()[1]);
        float res = powf(base, exp);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    // String & Memory functions
    RegisterThunk("strcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcmp(s1, s2) : 0;
    });

    RegisterThunk("strncmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? strncmp(s1, s2, n) : 0;
    });

    RegisterThunk("strcasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcasecmp(s1, s2) : 0;
    });

    RegisterThunk("strlen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // Bring-up containment: the movie-load path reaches strlen with a
        // CORRUPTED return address (lr=0x61 -- not code) and r0 pointing at
        // a NUL byte; the guest then spins on the same dispatch forever.
        // When lr is not a code address, the call itself is garbage: return
        // 0 (empty string) and jump back to the (still returned) lr.
        uint32_t lr = jit.Regs()[14];
        if (lr < 0x40000000u || lr >= 0x41A00000u) {
            static std::atomic<uint32_t> n{0};
            uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 12 || (k % 1000) == 0)
                LOGE("[STRLEN-GUARD] #%u lr=%08X r0=%08X -> 0", k, lr, jit.Regs()[0]);
            jit.Regs()[0] = 0;
            jit.Regs()[15] = lr & ~1u;
            return;
        }
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(strlen(s)) : 0;
    });

    RegisterThunk("strcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (dest && src) strcpy(dest, src);
    });

    RegisterThunk("strdup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!src) { jit.Regs()[0] = 0; return; }
        size_t len = strlen(src) + 1;
        uint32_t dest_addr = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest_addr), src, len);
        jit.Regs()[0] = dest_addr;
    });

    RegisterThunk("strrchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = static_cast<int>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strrchr(s, c);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });

    // strerror hands back storage the caller does not own and never frees, so a
    // fresh block per call is a block per failed open - and a guest that probes
    // for files that are not there does that constantly. One block per errno.
    RegisterThunk("strerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::mutex m;
        static std::unordered_map<int, uint32_t> cache;
        int err_no = static_cast<int>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(m);
        auto it = cache.find(err_no);
        if (it == cache.end()) {
            const char* err = strerror(err_no);
            size_t len = strlen(err) + 1;
            uint32_t dest = host.GuestAlloc(len);
            if (dest) memcpy(GuestToHost(host.GetGuestMemoryBase(), dest), err, len);
            it = cache.emplace(err_no, dest).first;
        }
        jit.Regs()[0] = it->second;
    });

    RegisterThunk("strerror_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int err_no = static_cast<int>(jit.Regs()[0]);
        char* buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t buflen = jit.Regs()[2];
        if (buf && buflen > 0) {
            strerror_r(err_no, buf, buflen);
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("strtoul", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int base = static_cast<int>(jit.Regs()[2]);
        jit.Regs()[0] = nptr ? static_cast<uint32_t>(strtoul(nptr, nullptr, base)) : 0;
    });

    RegisterThunk("atoi", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = str ? atoi(str) : 0;
    });

    RegisterThunk("islower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = islower(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("isxdigit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = isxdigit(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("memset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        // A guest memset with a corrupt length (freed-buffer junk) once ran
        // host-side past the guest mapping and killed the process
        // (SIGSEGV SEGV_ACCERR, tombstone_01, 2026-09-18). Clamp every
        // mem* range to the arena; the guest sees a truncated op instead
        // of a host crash.
        const size_t arena = host.GetGuestMemorySize();
        const uint32_t gaddr = jit.Regs()[0];
        if (s && !GuestRangeValid(arena, gaddr, n)) {
            static std::atomic<uint32_t> clamp_n{0};
            uint32_t k = clamp_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 8 || (k % 1000) == 0)
                LOGE("[MEMCLAMP] memset gaddr=%08X n=%zu (arena=%zu) clamped #%u",
                     gaddr, n, arena, k);
            // Absurd length (garbage count, e.g. PerksMP ctor): zeroing
            // "up to the arena end" wiped ~900 MB of live heap and the
            // loader phases after M6 died on the destroyed objects, which
            // reset the pass to M2 forever. No-op the whole call instead.
            if (n > (64u << 20)) return;
            if (gaddr < arena) n = arena - gaddr;
            else { jit.Regs()[0] = 0; return; }
        }
        if (s) memset(s, c, n);
    });

    RegisterThunk("memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* dest = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* src = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        const size_t arena = host.GetGuestMemorySize();
        if (dest && src && (!GuestRangeValid(arena, jit.Regs()[0], n) ||
                            !GuestRangeValid(arena, jit.Regs()[1], n))) {
            static std::atomic<uint32_t> clamp_n{0};
            uint32_t k = clamp_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 8 || (k % 1000) == 0)
                LOGE("[MEMCLAMP] memcpy dst=%08X src=%08X n=%zu clamped #%u",
                     jit.Regs()[0], jit.Regs()[1], n, k);
            uint32_t lim = arena;
            if (jit.Regs()[0] < lim) lim = jit.Regs()[0];
            if (jit.Regs()[1] < lim) lim = jit.Regs()[1];
            if (lim >= arena) { jit.Regs()[0] = 0; return; }
            n = arena - lim;
        }
        if (dest && src) memcpy(dest, src, n);
    });

    RegisterThunk("memcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s1 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s2 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        const size_t arena = host.GetGuestMemorySize();
        if (s1 && s2 && (!GuestRangeValid(arena, jit.Regs()[0], n) ||
                         !GuestRangeValid(arena, jit.Regs()[1], n))) {
            uint32_t lim = arena;
            if (jit.Regs()[0] < lim) lim = jit.Regs()[0];
            if (jit.Regs()[1] < lim) lim = jit.Regs()[1];
            if (lim >= arena) { jit.Regs()[0] = 0; return; }
            n = arena - lim;
        }
        jit.Regs()[0] = (s1 && s2) ? memcmp(s1, s2, n) : 0;
    });

    RegisterThunk("memchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        const size_t arena = host.GetGuestMemorySize();
        if (s && !GuestRangeValid(arena, jit.Regs()[0], n)) {
            uint32_t gaddr = jit.Regs()[0];
            if (gaddr >= arena) { jit.Regs()[0] = 0; return; }
            n = arena - gaddr;
        }
        void* res = s ? const_cast<void*>(memchr(s, c, n)) : nullptr;
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), res) : 0;
    });

    RegisterThunk("qsort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // ARM AEABI Helpers
    RegisterThunk("__aeabi_idiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_uidiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_idivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uidivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uldivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t num = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        uint64_t den = static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            uint64_t q = num / den;
            uint64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__gnu_ldivmod_helper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t num = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        int64_t den = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            int64_t q = num / den;
            int64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__aeabi_memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });
    RegisterThunk("__aeabi_memcpy4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });
    RegisterThunk("__aeabi_memcpy8", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });

    RegisterThunk("__aeabi_memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memmove(d, s, n);
    });
    RegisterThunk("__aeabi_memmove4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memmove(d, s, n);
    });

    RegisterThunk("__aeabi_memclr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memclr4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memclr8", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memset4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (d) memset(d, c, n);
    });

    RegisterThunk("__aeabi_f2lz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        int64_t i = static_cast<int64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(i & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(i >> 32);
    });

    RegisterThunk("__aeabi_f2ulz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        uint64_t u = static_cast<uint64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    RegisterThunk("__aeabi_l2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(i);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_ul2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t u = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(u);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_l2d", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        double d = static_cast<double>(i);
        uint64_t u = *reinterpret_cast<uint64_t*>(&d);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    // AEABI memory functions
    auto aeabi_memclr_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), 0, n);
        }
    };
    RegisterThunk("__aeabi_memclr", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr4", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr8", aeabi_memclr_handler);

    auto aeabi_memset_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), c, n);
        }
    };
    RegisterThunk("__aeabi_memset", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset4", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset8", aeabi_memset_handler);

    auto aeabi_memcpy_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), dest),
                   GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memcpy", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy4", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy8", aeabi_memcpy_handler);

    auto aeabi_memmove_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memmove(GuestToHost(host.GetGuestMemoryBase(), dest),
                    GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memmove", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove4", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove8", aeabi_memmove_handler);

    // Pthreads
    RegisterThunk("pthread_mutex_lock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestMutexLock(jit.Regs()[0]);
    });
    RegisterThunk("pthread_mutex_unlock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestMutexUnlock(jit.Regs()[0]);
    });
    RegisterThunk("pthread_cond_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestCondWait(jit.Regs()[0], jit.Regs()[1], 0, false);
    });
    RegisterThunk("pthread_cond_broadcast", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestCondSignal(jit.Regs()[0], true);
    });
    RegisterThunk("pthread_cond_signal", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestCondSignal(jit.Regs()[0], false);
    });

    // Returning from the guest initializer must publish the completed state,
    // not merely entering it. This private trampoline runs on that return.
    const uint32_t once_complete = RegisterThunk(
        "__mc4_pthread_once_complete", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            if (g_guest_once_continuations.empty()) {
                LOGE("pthread_once completion without an initializer");
                jit.Regs()[0] = EINVAL;
                return;
            }
            const GuestOnceContinuation frame = g_guest_once_continuations.back();
            g_guest_once_continuations.pop_back();
            uint32_t* word = reinterpret_cast<uint32_t*>(
                host.GetGuestMemoryBase() + frame.control);
            __atomic_store_n(word, 2u, __ATOMIC_RELEASE);
            ::syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, INT_MAX, nullptr, nullptr, 0);
            jit.Regs()[0] = 0;
            jit.Regs()[14] = frame.return_address;
            jit.Regs()[15] = frame.return_address & ~1u;
            jit.SetCpsr((jit.Cpsr() & ~0x20u) |
                        ((frame.return_address & 1u) ? 0x20u : 0u));
        });
    RegisterThunk("pthread_once", [once_complete](Dynarmic::A32::Jit& jit,
                                                   DynarmicHost& host) {
        const uint32_t control_addr = jit.Regs()[0];
        const uint32_t init_routine = jit.Regs()[1];
        if (!control_addr || (control_addr & 3u) || !init_routine ||
            !GuestRangeValid(host.GetGuestMemorySize(), control_addr, 4)) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        uint32_t* word = reinterpret_cast<uint32_t*>(
            host.GetGuestMemoryBase() + control_addr);
        for (;;) {
            uint32_t state = __atomic_load_n(word, __ATOMIC_ACQUIRE);
            if (state == 2u) {
                jit.Regs()[0] = 0;
                return;
            }
            if (state == 0u) {
                // Reserve the continuation before claiming initialization so
                // allocation failure cannot strand another thread at state 1.
                g_guest_once_continuations.push_back({control_addr, jit.Regs()[14]});
                if (__atomic_compare_exchange_n(word, &state, 1u, false,
                                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                    jit.Regs()[14] = once_complete;
                    jit.Regs()[15] = init_routine & ~1u;
                    jit.SetCpsr((jit.Cpsr() & ~0x20u) |
                                ((init_routine & 1u) ? 0x20u : 0u));
                    jit.Regs()[0] = 0;
                    return;
                }
                g_guest_once_continuations.pop_back();
                continue;
            }
            if (state != 1u) {
                jit.Regs()[0] = EINVAL;
                return;
            }
            // The guest lives inside this process: all participants share the
            // same mapped word, so the private futex operation is sufficient.
            ::syscall(SYS_futex, word, FUTEX_WAIT_PRIVATE, 1u,
                      nullptr, nullptr, 0);
            // A wake may be spurious, or completion may win before the wait.
            // Reload with acquire semantics before observing initialized data.
        }
    });

    RegisterThunk("pthread_key_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t key_ptr = jit.Regs()[0];
        if (!GuestRangeValid(host.GetGuestMemorySize(), key_ptr, 4)) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        std::lock_guard lock(g_guest_tls_keys_mutex);
        for (uint32_t key = 7; key < g_guest_tls_keys.size(); ++key) {
            if (g_guest_tls_keys[key].allocated) continue;
            g_guest_tls_keys[key] = {true, jit.Regs()[1]};
            host.MemoryWrite32(key_ptr, key);
            jit.Regs()[0] = 0;
            return;
        }
        jit.Regs()[0] = ENOMEM;
    });

    RegisterThunk("pthread_setspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t key = jit.Regs()[0];
        std::lock_guard lock(g_guest_tls_keys_mutex);
        if (key < 7 || key >= g_guest_tls_keys.size() ||
            !g_guest_tls_keys[key].allocated) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        const uint32_t tls = host.GuestThreadTls();
        if (!tls) {
            jit.Regs()[0] = ENOMEM;
            return;
        }
        host.MemoryWrite32(tls + key * 4u, jit.Regs()[1]);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_getspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t key = jit.Regs()[0];
        std::lock_guard lock(g_guest_tls_keys_mutex);
        if (key < 7 || key >= g_guest_tls_keys.size() ||
            !g_guest_tls_keys[key].allocated) {
            jit.Regs()[0] = 0;
            return;
        }
        const uint32_t tls = host.GuestThreadTls();
        jit.Regs()[0] = tls ? host.MemoryRead32(tls + key * 4u) : 0;
    });

    RegisterThunk("fopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* mode = reinterpret_cast<const char*>(jit.Regs()[1] ? reinterpret_cast<char*>(host.GetGuestMemoryBase() + jit.Regs()[1]) : "r");
        if (!path) { jit.Regs()[0] = 0; return; }
        // Diagnostic: log all data/ and Res paths to find the Res.array location
        if (path && (strstr(path, "Res.") || strstr(path, "data/") || strstr(path, "array"))) {
            static std::atomic<uint32_t> fo_n{0};
            uint32_t fk = fo_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (fk <= 30 || (fk % 500) == 0)
                LOGI("[FOPEN-PATH] '%s' mode=%s", path, mode ? mode : "r");
        }

        // A recognized virtual path must never fall through to a host file
        // when its VFS handle allocation fails.
        bool vfs_handled = false;
        FILE* vf = mc4::Phase3VfsHookFopen(path, mode ? mode : "r", &vfs_handled);
        if (vfs_handled) {
            if (!vf) { jit.Regs()[0] = 0; return; }
            // Bring-up: name every file the guest loads through the VFS view.
            {
                static std::mutex vm;
                static std::set<std::string> vseen;
                std::lock_guard<std::mutex> lk(vm);
                if (vseen.insert(path).second && vseen.size() <= 80)
                    LOGI("[FOPEN-VFS] '%s' mode=%s", path, mode ? mode : "r");
            }
            jit.Regs()[0] = PublishGuestFile(vf);
            return;
        }

        FILE* f = fopen(path, mode ? mode : "r");
        if (!f) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry && g_apk_indexed_fd >= 0) {
                ApkCookie* cookie = static_cast<ApkCookie*>(malloc(sizeof(ApkCookie)));
                cookie->base_offset = entry->data_offset;
                cookie->file_size = entry->file_size;
                cookie->current_offset = 0;

                f = funopen(cookie, ApkRead, nullptr, ApkSeek, ApkClose);
                if (f) {
                    LOGI("fopen: APK direct stream opened '%s' -> '%s' (size %lld, offset %lld)",
                         path, entry->name, static_cast<long long>(entry->file_size), static_cast<long long>(entry->data_offset));
                }
                // If your engine mmap()s or fstat()s the file it just fopen()ed -- archive
                // formats usually do -- a funopen stream is not enough on its own: it has no
                // descriptor. Publish a virtual fd for it the same way the open() thunk below
                // does, and make sure that vfd carries a real dup(g_apk_indexed_fd), not -1.
                // With -1 the mmap thunk returns MAP_FAILED and the archive mounts empty:
                // every file inside it looks missing, which reads as "the download is
                // incomplete", not as an error. Publishing it also needs a place to put the
                // descriptor the guest will call fileno() on -- see 5.3 of the guide.
            }
        }

        if (f) {
            jit.Regs()[0] = PublishGuestFile(f);
        } else {
            jit.Regs()[0] = 0;
        }
    });

    // funopen: guest passes GUEST function pointers (phase3_vfs.c:887). Host funopen
    // needs 64-bit C callbacks, so re-enter the JIT for each callback invocation.
    struct GuestFunopenCookie {
        uint32_t cookie_gaddr;
        uint32_t readfn, writefn, seekfn, closefn;
        DynarmicHost* host;
    };
    RegisterThunk("funopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t cookie_gaddr = jit.Regs()[0];
        uint32_t readfn = jit.Regs()[1];
        uint32_t writefn = jit.Regs()[2];
        uint32_t seekfn = jit.Regs()[3];
        uint32_t closefn = host.MemoryRead32(jit.Regs()[13]); // sp+0
        auto* ck = new GuestFunopenCookie{cookie_gaddr, readfn, writefn, seekfn, closefn, &host};
        FILE* f = funopen(ck,
            [](void* c, char* buf, int n) -> int {
                auto* k = static_cast<GuestFunopenCookie*>(c);
                if (!k->readfn || n <= 0) return 0;
                uint32_t gbuf = k->host->GuestAlloc(static_cast<size_t>(n), 4);
                uint32_t res = k->host->RunFunction(k->readfn, {k->cookie_gaddr, gbuf, static_cast<uint32_t>(n)});
                if (static_cast<int32_t>(res) > 0)
                    memcpy(buf, GuestToHost(k->host->GetGuestMemoryBase(), gbuf), res);
                k->host->GuestFree(gbuf);
                return static_cast<int32_t>(res);
            },
            [](void* c, const char* buf, int n) -> int {
                auto* k = static_cast<GuestFunopenCookie*>(c);
                if (!k->writefn || n <= 0) return 0;
                uint32_t gbuf = k->host->GuestAlloc(static_cast<size_t>(n), 4);
                memcpy(GuestToHost(k->host->GetGuestMemoryBase(), gbuf), buf, static_cast<size_t>(n));
                uint32_t res = k->host->RunFunction(k->writefn, {k->cookie_gaddr, gbuf, static_cast<uint32_t>(n)});
                k->host->GuestFree(gbuf);
                return static_cast<int32_t>(res);
            },
            [](void* c, fpos_t off, int whence) -> fpos_t {
                auto* k = static_cast<GuestFunopenCookie*>(c);
                if (!k->seekfn) return static_cast<fpos_t>(-1);
                uint32_t res = k->host->RunFunction(k->seekfn, {k->cookie_gaddr,
                                                                static_cast<uint32_t>(static_cast<int64_t>(off)),
                                                                static_cast<uint32_t>(whence)});
                return static_cast<fpos_t>(static_cast<int64_t>(static_cast<int32_t>(res)));
            },
            [](void* c) -> int {
                auto* k = static_cast<GuestFunopenCookie*>(c);
                int32_t res = 0;
                if (k->closefn)
                    res = static_cast<int32_t>(k->host->RunFunction(k->closefn, {k->cookie_gaddr}));
                delete k;
                return res;
            });
        if (f) {
            jit.Regs()[0] = PublishGuestFile(f);
        } else {
            delete ck;
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("fdopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        FILE* f = nullptr;
        if (mc4::Phase3VfsHookFdopen(fd, &f) != 0) {
            f = fdopen(fd, mode);
        }
        if (f) {
            jit.Regs()[0] = PublishGuestFile(f);
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("fclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(CloseGuestFile(jit.Regs()[0]));
    });

    RegisterThunk("fread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        size_t res = ptr ? WithGuestFile<size_t>(handle, 0,
            [ptr, size, count](FILE* file) { return fread(ptr, size, count, file); }) : 0;
        jit.Regs()[0] = res;
    });

    RegisterThunk("fwrite", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        jit.Regs()[0] = ptr ? WithGuestFile<size_t>(handle, 0,
            [ptr, size, count](FILE* file) { return fwrite(ptr, size, count, file); }) : 0;
    });

    RegisterThunk("fseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        long offset = static_cast<long>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        int res = WithGuestFile<int>(handle, -1,
            [offset, whence](FILE* file) { return fseek(file, offset, whence); });
        jit.Regs()[0] = res;
    });

    RegisterThunk("fseeko", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        int res = WithGuestFile<int>(handle, -1,
            [offset, whence](FILE* file) { return fseeko(file, offset, whence); });
        jit.Regs()[0] = res;
    });

    RegisterThunk("ftell", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = static_cast<uint32_t>(WithGuestFile<long>(handle, 0L,
            [](FILE* file) { return ftell(file); }));
    });

    RegisterThunk("ftello", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        off_t res = WithGuestFile<off_t>(handle, static_cast<off_t>(-1),
            [](FILE* file) { return ftello(file); });
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("fileno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = WithGuestFile<int>(handle, -1,
            [](FILE* file) { return fileno(file); });
    });

    RegisterThunk("clearerr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        WithGuestFileVoid(handle, [](FILE* file) { clearerr(file); });
    });

    RegisterThunk("ferror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = WithGuestFile<int>(handle, 0,
            [](FILE* file) { return ferror(file); });
    });

    RegisterThunk("open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int flags = static_cast<int>(jit.Regs()[1]);
        int mode = static_cast<int>(jit.Regs()[2]);
        // Diagnostic: log open() calls for data/ and Res paths
        if (path && (strstr(path, "Res.") || strstr(path, "data/") || strstr(path, "array"))) {
            static std::atomic<uint32_t> op_n{0};
            uint32_t ok = op_n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (ok <= 30 || (ok % 500) == 0)
                LOGI("[OPEN-PATH] '%s' flags=%x", path, flags);
        }

        // phase3 VFS first (host port of phase3_vfs.c hook_open).
        if (path && (flags & O_CREAT) == 0 && (flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0) {
            bool handled = false;
            int vfd = mc4::Phase3VfsHookOpen(path, flags, &handled);
            if (handled) {
                jit.Regs()[0] = static_cast<uint32_t>(vfd);
                return;
            }
        }

        int fd = -1;
        if (path && (flags & O_CREAT) == 0 && (flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0) {
            // Bring-up: log read-open failures so a missing data file names
            // itself. Remove with the rest of the phase-7 diagnostics.
            {
                static int open_miss_logs = 0;
                if (open_miss_logs < 40 && path &&
                    strncmp(path, "/dev/", 5) != 0 && strncmp(path, "/sys/", 5) != 0 &&
                    strncmp(path, "/proc/", 6) != 0 && strncmp(path, "/system", 7) != 0 &&
                    strncmp(path, "/apex/", 6) != 0 && strncmp(path, "/vendor", 7) != 0) {
                    ++open_miss_logs;
                    LOGI("[OPEN] '%s' flags=%o indexed=%d", path, flags,
                         FindApkEntry(path) ? 1 : 0);
                }
            }
            ApkEntry* entry = FindApkEntry(path);
            if (entry && g_apk_indexed_fd >= 0) {
                int dup_fd = dup(g_apk_indexed_fd);
                if (dup_fd >= 0) {
                    std::lock_guard<std::mutex> lock(g_vfd_mutex);
                    int vfd = g_next_vfd++;
                    g_vfd_map[vfd] = { dup_fd, static_cast<size_t>(entry->file_size), entry->data_offset, 0 };
                    LOGI("open: APK direct stream opened '%s' -> '%s' (vfd %d, size %zu, offset %lld)",
                         path, entry->name, vfd, entry->file_size, static_cast<long long>(entry->data_offset));
                    jit.Regs()[0] = static_cast<uint32_t>(vfd);
                    return;
                }
            }
        }

        fd = open(path ? path : "", flags, mode);
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(fd) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        if (mc4::Phase3VfsHookClose(fd) == 0) {
            jit.Regs()[0] = 0;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                close(it->second.real_apk_fd);
                g_vfd_map.erase(it);
                jit.Regs()[0] = 0;
                return;
            }
        }
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(close(fd)) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        if (!buf) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

        if (ssize_t n = mc4::Phase3VfsHookRead(fd, buf, count); n >= 0) {
            jit.Regs()[0] = static_cast<uint32_t>(n);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                if (vfd.current_pos >= static_cast<off_t>(vfd.file_size)) {
                    jit.Regs()[0] = 0; // EOF
                    return;
                }
                size_t avail = vfd.file_size - vfd.current_pos;
                size_t to_read = (count < avail) ? count : avail;
                ssize_t nread = pread(vfd.real_apk_fd, buf, to_read, vfd.file_offset + vfd.current_pos);
                if (nread > 0) {
                    vfd.current_pos += nread;
                }
                jit.Regs()[0] = (nread >= 0) ? static_cast<uint32_t>(nread) : static_cast<uint32_t>(-1);
                return;
            }
        }

        ssize_t res = (fd >= 0) ? read(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        ssize_t res = (buf && fd >= 0) ? write(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);

        if (off64_t n = mc4::Phase3VfsHookLseek(fd, offset, whence); n >= 0) {
            jit.Regs()[0] = static_cast<uint32_t>(n);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                off_t new_pos = vfd.current_pos;
                if (whence == SEEK_SET) new_pos = offset;
                else if (whence == SEEK_CUR) new_pos += offset;
                else if (whence == SEEK_END) new_pos = static_cast<off_t>(vfd.file_size) + offset;
                else { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

                if (new_pos < 0) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
                vfd.current_pos = new_pos;
                jit.Regs()[0] = static_cast<uint32_t>(new_pos);
                return;
            }
        }

        off_t res = (fd >= 0) ? lseek(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek64", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int64_t offset = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        int whence = static_cast<int>(host.MemoryRead32(jit.Regs()[13]));

        if (off64_t n = mc4::Phase3VfsHookLseek(fd, offset, whence); n >= 0) {
            jit.Regs()[0] = static_cast<uint32_t>(n & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(n >> 32);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                off_t new_pos = vfd.current_pos;
                if (whence == SEEK_SET) new_pos = offset;
                else if (whence == SEEK_CUR) new_pos += offset;
                else if (whence == SEEK_END) new_pos = static_cast<off_t>(vfd.file_size) + offset;
                else { jit.Regs()[0] = static_cast<uint32_t>(-1); jit.Regs()[1] = static_cast<uint32_t>(-1); return; }

                if (new_pos < 0) { jit.Regs()[0] = static_cast<uint32_t>(-1); jit.Regs()[1] = static_cast<uint32_t>(-1); return; }
                vfd.current_pos = new_pos;
                jit.Regs()[0] = static_cast<uint32_t>(new_pos & 0xFFFFFFFF);
                jit.Regs()[1] = static_cast<uint32_t>(new_pos >> 32);
                return;
            }
        }

        off64_t res = (fd >= 0) ? lseek64(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(res >> 32);
    });

    RegisterThunk("access", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int mode = static_cast<int>(jit.Regs()[1]);
        struct stat virtual_st;
        int res;
        // Virtual OBB/assets are read-only. Query with a real output buffer:
        // passing nullptr always made the VFS stat hook return EFAULT.
        if (path && mc4::Phase3VfsHookStat(path, &virtual_st) == 0) {
            res = (mode & (W_OK | X_OK)) ? -1 : 0;
            if (res != 0) errno = EACCES;
        } else {
            res = access(path ? path : "", mode);
            if (res != 0 && FindApkEntry(path)) {
                res = (mode & (W_OK | X_OK)) ? -1 : 0;
                if (res != 0) errno = EACCES;
            }
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("stat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = -1;

        // phase3 VFS virtual asset / OBB stat (host port of hook_stat).
        if (path && mc4::Phase3VfsHookStat(path, &st) == 0) {
            res = 0;
        }

        if (res != 0) res = stat(path ? path : "", &st);
        if (res != 0) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry) {
                memset(&st, 0, sizeof(st));
                st.st_size = entry->file_size;
                st.st_mode = S_IFREG | 0644;
                st.st_nlink = 1;
                res = 0;
            }
        }
        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("feof", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = WithGuestFile<int>(handle, 1,
            [](FILE* file) { return feof(file); });
    });

    RegisterThunk("fflush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = WithGuestFile<int>(handle, 0,
            [](FILE* file) { return fflush(file); });
    });

    RegisterThunk("setvbuf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // mmap/munmap. Do NOT stub these as "hand out a fresh heap block": a caller that checks
    // the returned address (Boehm does, see lesson 2.15) will abort, and an engine that maps
    // its archive gets 345 MB of zeroes -- which reads as "the pak has no entries", not as an
    // error, and parks the boot on a download screen.
    //
    // The guest arena is one anonymous MAP_PRIVATE reservation. An ordinary real-file fd
    // can be laid into it with MAP_FIXED without an eager copy; an APK virtual fd cannot,
    // because its member offset/EOF do not match the containing APK. MAP_PRIVATE prevents
    // a stray guest write from reaching the file on disk.
    RegisterThunk("mmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t len   = jit.Regs()[1];
        const uint32_t flags = jit.Regs()[3];
        const uint32_t sp    = jit.Regs()[13];         // AAPCS: args 5 and 6 are on the stack
        int            fd    = static_cast<int>(host.MemoryRead32(sp));
        off_t          off   = static_cast<off_t>(host.MemoryRead32(sp + 4));

        constexpr uint32_t kMapAnonymous = 0x20;       // Linux MAP_ANONYMOUS on arm
        constexpr uint32_t kMapFailed    = 0xFFFFFFFF;
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));

        if (len == 0) { jit.Regs()[0] = kMapFailed; return; }

        // phase3 VFS virtual archive mmap (host port of hook_mmap): the whole
        // view is materialized in the guest arena instead of page-run mirroring.
        if (!(flags & kMapAnonymous)) {
            uint32_t p3_va = 0;
            if (mc4::Phase3VfsHookMmap(host, fd, len, off, &p3_va) == 0) {
                jit.Regs()[0] = p3_va;
                return;
            }
        }

        if (fd < 0 || (flags & kMapAnonymous)) {
            // Anonymous: fresh mapping space, which the arena zero-fills for us.
            const uint32_t va = host.GuestAllocMapping((len + page - 1) & ~(page - 1), page);
            jit.Regs()[0] = va ? va : kMapFailed;
            return;
        }

        // An APK VFD's offset and EOF belong to the member, not base.apk.
        // Mapping the raw APK page and returning va + payload_bias made mmap
        // return a non-page-aligned guest address, and exposed the neighboring
        // ZIP bytes through that page. Copy only the requested virtual member
        // view into a page-aligned anonymous guest mapping instead. The normal
        // phase3 OBB VFS above still handles large archive mappings first.
        VirtualFd vfd{};
        ScopedHostFd source;
        bool is_vfd = false;
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                is_vfd = true;
                vfd = it->second;
                source.fd = dup(vfd.real_apk_fd);
            }
        }
        if (is_vfd) {
            if (source.fd < 0 || vfd.file_offset < 0 || off < 0) {
                jit.Regs()[0] = kMapFailed;
                return;
            }
            mc4::ApkVfdView view{};
            if (!mc4::PrepareApkVfdView(vfd.file_size,
                                         static_cast<uint64_t>(off), len,
                                         page, &view)) {
                jit.Regs()[0] = kMapFailed;
                return;
            }
            struct stat fst{};
            if (fstat(source.fd, &fst) != 0) {
                jit.Regs()[0] = kMapFailed;
                return;
            }
            {
                std::lock_guard<std::mutex> lock(g_mapping_mutex);
                for (const auto& m : g_guest_virtual_maps) {
                    if (m.dev == fst.st_dev && m.ino == fst.st_ino &&
                        m.member_offset == vfd.file_offset &&
                        m.member_size == vfd.file_size &&
                        m.virtual_offset == off && m.span == view.span) {
                        jit.Regs()[0] = m.va;
                        return;
                    }
                }
            }
            const uint32_t va = host.GuestAllocMapping(view.span, page);
            if (!va || static_cast<uint64_t>(va) + view.span >
                           host.GetGuestMemorySize()) {
                errno = ENOMEM;
                jit.Regs()[0] = kMapFailed;
                return;
            }
            if (!mc4::CopyApkVfdView(source.fd,
                                     static_cast<uint64_t>(vfd.file_offset),
                                     static_cast<uint64_t>(off), view,
                                     host.GetGuestMemoryBase() + va)) {
                LOGE("mmap: APK VFD copy failed fd=%d off=%lld: %s", fd,
                     static_cast<long long>(off), strerror(errno));
                jit.Regs()[0] = kMapFailed;
                return;
            }
            {
                std::lock_guard<std::mutex> lock(g_mapping_mutex);
                g_guest_virtual_maps.push_back({fst.st_dev, fst.st_ino,
                                                vfd.file_offset, vfd.file_size,
                                                off, view.span, va});
            }
            LOGI("mmap: APK VFD %d len=%u off=%lld -> guest 0x%08X", fd,
                 len, static_cast<long long>(off), va);
            jit.Regs()[0] = va;
            return;
        }
        if (fd < 0) { jit.Regs()[0] = kMapFailed; return; }

        // mmap needs a page-aligned file offset; keep the remainder as a bias on the result.
        const off_t  aligned = off & ~static_cast<off_t>(page - 1);
        const size_t bias    = static_cast<size_t>(off - aligned);
        const size_t span    = (len + bias + page - 1) & ~(page - 1);

        struct stat fst{};
        if (fstat(fd, &fst) == 0) {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (m.dev == fst.st_dev && m.ino == fst.st_ino && m.off == aligned && m.span == span) {
                    jit.Regs()[0] = m.va + static_cast<uint32_t>(bias);
                    return;
                }
            }
        }

        const uint32_t va = host.GuestAllocMapping(span, page);
        if (!va) { LOGE("mmap: no guest arena for %zu bytes", span); jit.Regs()[0] = kMapFailed; return; }
        if (static_cast<uint64_t>(va) + span > host.GetGuestMemorySize()) {
            LOGE("mmap: 0x%08X + %zu would run past the guest arena", va, span);
            jit.Regs()[0] = kMapFailed;
            return;
        }
        void* want = host.GetGuestMemoryBase() + va;
        void* got = ::mmap(want, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, aligned);
        if (got == MAP_FAILED) {
            LOGE("mmap(fd=%d, len=%u, off=%lld) failed: %s", fd, len,
                 static_cast<long long>(off), strerror(errno));
            jit.Regs()[0] = kMapFailed;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            g_guest_file_maps.push_back({fst.st_dev, fst.st_ino, aligned, span, va});
        }
        LOGI("mmap: fd=%d len=%u off=%lld -> guest 0x%08X", fd, len,
             static_cast<long long>(off), va + static_cast<uint32_t>(bias));
        jit.Regs()[0] = va + static_cast<uint32_t>(bias);
    });

    RegisterThunk("munmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t len  = jit.Regs()[1];
        if (!addr || !len) { jit.Regs()[0] = 0; return; }
        const long host_page_size = sysconf(_SC_PAGESIZE);
        if (host_page_size <= 0 ||
            (host_page_size & (host_page_size - 1)) != 0 ||
            !host.GuestMappingContains(addr, len)) {
            LOGE("munmap(0x%08X, %u) invalid page size or mapping range", addr, len);
            errno = EINVAL;
            jit.Regs()[0] = UINT32_MAX;
            return;
        }
        const uint64_t end = static_cast<uint64_t>(addr) + len;
        const uint64_t page = static_cast<uint64_t>(host_page_size);
        const uint64_t mask = page - 1;

        // Cached file mappings can be shared by other readers. Preserve each
        // overlapping interval, even when it lies in the middle of the unmap
        // request, while discarding only the remaining anonymous/VFS-copy spans.
        std::vector<std::pair<uint64_t, uint64_t>> retained;
        {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            for (const auto& m : g_guest_file_maps) {
                const uint64_t map_end = static_cast<uint64_t>(m.va) + m.span;
                if (addr < map_end && end > m.va)
                    retained.emplace_back(std::max<uint64_t>(addr, m.va),
                                          std::min(end, map_end));
            }
            for (const auto& m : g_guest_virtual_maps) {
                const uint64_t map_end = static_cast<uint64_t>(m.va) + m.span;
                if (addr < map_end && end > m.va)
                    retained.emplace_back(std::max<uint64_t>(addr, m.va),
                                          std::min(end, map_end));
            }
        }
        std::sort(retained.begin(), retained.end());

        // The guest arena is bump-only: unmap means discard bytes, not recycle
        // an address. Only complete host pages can be discarded as pages.
        // Rounding a 4-KiB guest request OUT to 16 KiB would erase unrelated
        // live data beside it on a 16-KiB-page Android device.
        uint8_t* const base = host.GetGuestMemoryBase();
        auto discard = [&](uint64_t begin, uint64_t stop) -> bool {
            if (begin >= stop) return true;
            const uint64_t full_begin = (begin + mask) & ~mask;
            const uint64_t full_end = stop & ~mask;
            if (full_begin >= full_end) {
                memset(base + begin, 0, static_cast<size_t>(stop - begin));
            } else {
                if (madvise(base + full_begin,
                            static_cast<size_t>(full_end - full_begin),
                            MADV_DONTNEED) != 0) {
                    LOGE("munmap(0x%08X, %u) madvise failed: %s", addr, len,
                         strerror(errno));
                    return false;
                }
                if (full_begin > begin)
                    memset(base + begin, 0,
                           static_cast<size_t>(full_begin - begin));
                if (stop > full_end)
                    memset(base + full_end, 0,
                           static_cast<size_t>(stop - full_end));
            }
            return true;
        };
        uint64_t cursor = addr;
        for (const auto& keep : retained) {
            if (cursor < keep.first && !discard(cursor, keep.first)) {
                jit.Regs()[0] = UINT32_MAX;
                return;
            }
            cursor = std::max(cursor, keep.second);
        }
        if (!discard(cursor, end)) {
            jit.Regs()[0] = UINT32_MAX;
            return;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("fstat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = -1;

        if (mc4::Phase3VfsHookFstat(fd, &st) == 0) {
            res = 0;
        }

        if (res != 0) {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                memset(&st, 0, sizeof(st));
                st.st_size = it->second.file_size;
                st.st_mode = S_IFREG | 0644;
                st.st_nlink = 1;
                res = 0;
            }
        }

        if (res != 0) {
            res = fstat(fd, &st);
        }

        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("remove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = remove(path ? path : "");
    });

    RegisterThunk("rename", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* oldp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* newp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = rename(oldp ? oldp : "", newp ? newp : "");
    });

    RegisterThunk("chmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("umask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("mkstemp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = -1; });
    RegisterThunk("getpid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getpid(); });

    RegisterThunk("time", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(time(nullptr));
    });

    // Same contract as strerror: the caller never frees it. Real localtime
    // overwrites one static buffer per call; this does the same, per thread, so
    // two threads formatting a timestamp cannot scribble on each other.
    RegisterThunk("localtime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t gtm = 0;
        time_t t = static_cast<time_t>(host.MemoryRead32(jit.Regs()[0]));
        struct tm* tm_res = localtime(&t);
        if (!gtm) gtm = host.GuestAlloc(sizeof(struct tm));
        if (tm_res && gtm) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), gtm), tm_res, sizeof(struct tm));
            jit.Regs()[0] = gtm;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("mktime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct tm* tm_ptr = reinterpret_cast<struct tm*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = tm_ptr ? static_cast<uint32_t>(mktime(tm_ptr)) : 0;
    });

    RegisterThunk("raise", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Runtime guards & hooks. Both guards dump the full context ONCE and
    // then halt the core: the guest state is corrupt and returning lets the
    // caller loop on abort() for thousands of iterations (4085 seen in the
    // 21:52 run), burying the one interesting frame under log noise.
    RegisterThunk("__stack_chk_fail", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<bool> dumped{false};
        if (!dumped.exchange(true)) {
            char st[260]; int o = 0;
            uint32_t sp = jit.Regs()[13];
            for (int i = 0; i < 16 && o < (int)sizeof(st) - 12; ++i)
                o += snprintf(st + o, sizeof(st) - o, " %02X:%08X", i * 4, host.MemoryRead32(sp + i * 4));
            st[o] = 0;
            LOGE("[STACKFAIL] canary=%08X expected=%08X | r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X "
                 "r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X fp=%08X ip=%08X sp=%08X lr=%08X",
                 host.MemoryRead32(jit.Regs()[11] - 8), host.MemoryRead32(0x100u),
                 jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], jit.Regs()[4],
                 jit.Regs()[5], jit.Regs()[6], jit.Regs()[7], jit.Regs()[8], jit.Regs()[9],
                 jit.Regs()[10], jit.Regs()[11], jit.Regs()[12], sp, jit.Regs()[14]);
            LOGE("[STACKFAIL] stack:%s", st);
            char hi[160]; o = 0;
            // The failing frame's canary slot lives near sp+0x104 in
            // createAndOpenFile; dump the region so the overwriting writer
            // (a callee's upward buffer overflow) is visible.
            for (int i = 60; i < 70 && o < (int)sizeof(hi) - 12; ++i)
                o += snprintf(hi + o, sizeof(hi) - o, " %02X:%08X", i * 4, host.MemoryRead32(sp + i * 4));
            hi[o] = 0;
            LOGE("[STACKFAIL] canary-region sp+0xF0..:%s", hi);
            // Frame-specific: onClassInitialized frame is 0x668 bytes, its
            // canary (var_4) sits at sp+0x664. Dump sp+0x600..0x668 to see
            // what smashed it (FocusGain path).
            {
                char cbuf[420]; int co = 0;
                for (int i = 0x180; i <= 0x19A && co < (int)sizeof(cbuf) - 14; ++i)
                    co += snprintf(cbuf + co, sizeof(cbuf) - co, " %03X:%08X",
                                   i * 4, host.MemoryRead32(sp + i * 4));
                cbuf[co] = 0;
                LOGE("[STACKFAIL] canary-frame sp+0x600..:%s", cbuf);
            }
        }
        // 2026-09-20: instead of halting (which aborted FocusGain ->
        // InitMainMenuNative mid-way and stopped all menu class
        // registration), log and RETURN: pc = lr, r0 = 0. The canary
        // mismatch on a transient frame is survivable; halting was not.
        jit.Regs()[0] = 0;
        jit.Regs()[15] = jit.Regs()[14] & ~1u;
    });

    RegisterThunk("abort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<bool> dumped{false};
        if (!dumped.exchange(true)) {
            LOGE("[ABORT] lr=%08X sp=%08X r0=%08X r1=%08X r2=%08X r3=%08X",
                 jit.Regs()[14], jit.Regs()[13], jit.Regs()[0], jit.Regs()[1],
                 jit.Regs()[2], jit.Regs()[3]);
        }
        jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
    });

    RegisterThunk("__assert2", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* file = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int line = static_cast<int>(jit.Regs()[1]);
        const char* func = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const char* expr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        LOGE("Assertion failed: %s at %s:%d (%s)", expr ? expr : "", file ? file : "", line, func ? func : "");
    });

    RegisterThunk("__cxa_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_finalize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__aeabi_unwind_cpp_pr0", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("__aeabi_unwind_cpp_pr1", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_RaiseException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_DeleteException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_GetLanguageSpecificData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_GetRegionStart", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Set", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_unwind_frame", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Asset override: see InstallAssetOverrideHook below. R1 is the archive-relative
    // entry name; returning ip=0 makes the veneer return NULL, so the engine's own
    // "not in the archive" path takes over and opens the plain file instead.
    RegisterThunk("asset_override_archive_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[12] = HasAssetOverride(name) ? 0u : g_asset_override_real_fn;
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing Math (softfp)
    // -----------------------------------------------------------------------
    RegisterThunk("asin", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double val = ReadDF(jit, 0);
        WriteDF(jit, 0, asin(val));
    });
    RegisterThunk("asinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        WriteSF(jit, 0, asinf(val));
    });
    RegisterThunk("atan", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double val = ReadDF(jit, 0);
        WriteDF(jit, 0, atan(val));
    });
    RegisterThunk("atan2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float y = ReadSF(jit, 0);
        float x = ReadSF(jit, 1);
        WriteSF(jit, 0, atan2f(y, x));
    });
    RegisterThunk("ceil", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double val = ReadDF(jit, 0);
        WriteDF(jit, 0, ceil(val));
    });
    RegisterThunk("ceilf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        WriteSF(jit, 0, ceilf(val));
    });
    RegisterThunk("expf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        WriteSF(jit, 0, expf(val));
    });
    RegisterThunk("floorf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        WriteSF(jit, 0, floorf(val));
    });
    RegisterThunk("fmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = ReadDF(jit, 0);
        double y = ReadDF(jit, 1);
        WriteDF(jit, 0, fmod(x, y));
    });
    RegisterThunk("fmodf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float x = ReadSF(jit, 0);
        float y = ReadSF(jit, 1);
        WriteSF(jit, 0, fmodf(x, y));
    });
    RegisterThunk("logf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        WriteSF(jit, 0, logf(val));
    });
    RegisterThunk("modff", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float x = ReadSF(jit, 0);
        uint32_t iptr_gaddr = jit.Regs()[1];
        float iptr = 0.0f;
        float res = modff(x, &iptr);
        if (iptr_gaddr) {
            *reinterpret_cast<float*>(GuestToHost(host.GetGuestMemoryBase(), iptr_gaddr)) = iptr;
        }
        WriteSF(jit, 0, res);
    });
    RegisterThunk("sinh", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double val = ReadDF(jit, 0);
        WriteDF(jit, 0, sinh(val));
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing String Functions
    // -----------------------------------------------------------------------
    RegisterThunk("strchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = static_cast<int>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strchr(s, c);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });
    RegisterThunk("strcoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcoll(s1, s2) : 0;
    });
    RegisterThunk("strcspn", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? static_cast<uint32_t>(strcspn(s1, s2)) : 0;
    });
    RegisterThunk("strncat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        if (dest && src) strncat(dest, src, n);
    });
    RegisterThunk("strpbrk", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* accept = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!s || !accept) { jit.Regs()[0] = 0; return; }
        const char* res = strpbrk(s, accept);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });
    RegisterThunk("strstr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* haystack = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* needle = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!haystack || !needle) { jit.Regs()[0] = 0; return; }
        const char* res = strstr(haystack, needle);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });
    RegisterThunk("strtod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t endptr_gaddr = jit.Regs()[1];
        char* endptr = nullptr;
        double res = nptr ? strtod(nptr, &endptr) : 0.0;
        if (endptr_gaddr) {
            uint32_t end_gaddr = endptr ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(endptr) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
            host.MemoryWrite32(endptr_gaddr, end_gaddr);
        }
        WriteDF(jit, 0, res);
    });
    RegisterThunk("strtok", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* s = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* delim = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        char* res = delim ? strtok(s, delim) : nullptr;
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });
    RegisterThunk("strtok_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* s = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* delim = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        uint32_t saveptr_gaddr = jit.Regs()[2];
        if (!saveptr_gaddr || !delim) { jit.Regs()[0] = 0; return; }
        uint32_t prev_saved = host.MemoryRead32(saveptr_gaddr);
        char* saveptr = prev_saved ? reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), prev_saved)) : nullptr;
        char* res = strtok_r(s, delim, &saveptr);
        uint32_t new_saved = saveptr ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(saveptr) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
        host.MemoryWrite32(saveptr_gaddr, new_saved);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });
    RegisterThunk("strtoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t endptr_gaddr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        char* endptr = nullptr;
        long long res = nptr ? strtoll(nptr, &endptr, base) : 0;
        if (endptr_gaddr) {
            uint32_t end_gaddr = endptr ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(endptr) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
            host.MemoryWrite32(endptr_gaddr, end_gaddr);
        }
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res >> 32) & 0xFFFFFFFF);
    });
    RegisterThunk("strtoull", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t endptr_gaddr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        char* endptr = nullptr;
        unsigned long long res = nptr ? strtoull(nptr, &endptr, base) : 0;
        if (endptr_gaddr) {
            uint32_t end_gaddr = endptr ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(endptr) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
            host.MemoryWrite32(endptr_gaddr, end_gaddr);
        }
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res >> 32) & 0xFFFFFFFF);
    });
    RegisterThunk("strxfrm", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (dest && src) ? static_cast<uint32_t>(strxfrm(dest, src, n)) : 0;
    });
    RegisterThunk("strlcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t size = jit.Regs()[2];
        jit.Regs()[0] = (dest && src) ? static_cast<uint32_t>(strlcat(dest, src, size)) : 0;
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing Wide Char Functions (wchar_t is 4 bytes on both)
    // -----------------------------------------------------------------------
    RegisterThunk("btowc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(btowc(static_cast<int>(jit.Regs()[0])));
    });
    RegisterThunk("wctob", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(wctob(static_cast<wint_t>(jit.Regs()[0])));
    });
    RegisterThunk("towlower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(towlower(static_cast<wint_t>(jit.Regs()[0])));
    });
    RegisterThunk("towupper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(towupper(static_cast<wint_t>(jit.Regs()[0])));
    });
    RegisterThunk("wctype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = name ? static_cast<uint32_t>(wctype(name)) : 0;
    });
    RegisterThunk("iswctype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wint_t wc = static_cast<wint_t>(jit.Regs()[0]);
        wctype_t desc = static_cast<wctype_t>(jit.Regs()[1]);
        jit.Regs()[0] = iswctype(wc, desc);
    });
    RegisterThunk("wcslen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* s = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(wcslen(s)) : 0;
    });
    RegisterThunk("wcscmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* s1 = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* s2 = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? wcscmp(s1, s2) : 0;
    });
    RegisterThunk("wcscoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* s1 = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* s2 = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? wcscoll(s1, s2) : 0;
    });
    RegisterThunk("wcscpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* src = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (dest && src) wcscpy(dest, src);
    });
    RegisterThunk("wcsxfrm", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* src = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (dest && src) ? static_cast<uint32_t>(wcsxfrm(dest, src, n)) : 0;
    });
    RegisterThunk("wmemchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* s = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        wchar_t c = static_cast<wchar_t>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (!s) { jit.Regs()[0] = 0; return; }
        const wchar_t* res = wmemchr(s, c, n);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });
    RegisterThunk("wmemcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* s1 = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* s2 = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? wmemcmp(s1, s2, n) : 0;
    });
    RegisterThunk("wmemcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* src = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        if (dest && src && n) wmemcpy(dest, src, n);
    });
    RegisterThunk("wmemmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* src = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        if (dest && src && n) wmemmove(dest, src, n);
    });
    RegisterThunk("wmemset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* dest = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        wchar_t c = static_cast<wchar_t>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (dest && n) wmemset(dest, c, n);
    });
    RegisterThunk("mbstowcs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* pwcs = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = s ? static_cast<uint32_t>(mbstowcs(pwcs, s, n)) : 0;
    });
    RegisterThunk("mbrtowc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* pwc = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        mbstate_t ps{};
        size_t res = s ? mbrtowc(pwc, s, n, &ps) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("wcrtomb", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* s = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        wchar_t wc = static_cast<wchar_t>(jit.Regs()[1]);
        mbstate_t ps{};
        size_t res = s ? wcrtomb(s, wc, &ps) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("wcsftime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* s = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t max = jit.Regs()[1];
        const wchar_t* format = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        uint32_t tm_gaddr = jit.Regs()[3];
        struct tm tm_val{};
        if (tm_gaddr) {
            int* gtm = reinterpret_cast<int*>(GuestToHost(host.GetGuestMemoryBase(), tm_gaddr));
            tm_val.tm_sec = gtm[0]; tm_val.tm_min = gtm[1]; tm_val.tm_hour = gtm[2];
            tm_val.tm_mday = gtm[3]; tm_val.tm_mon = gtm[4]; tm_val.tm_year = gtm[5];
            tm_val.tm_wday = gtm[6]; tm_val.tm_yday = gtm[7]; tm_val.tm_isdst = gtm[8];
        }
        size_t res = (s && format && max > 0) ? wcsftime(s, max, format, &tm_val) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("getwc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = static_cast<uint32_t>(WithGuestFile<wint_t>(handle, WEOF,
            [](FILE* file) { return fgetwc(file); }));
    });
    RegisterThunk("putwc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t c = static_cast<wchar_t>(jit.Regs()[0]);
        uint32_t handle = jit.Regs()[1];
        jit.Regs()[0] = static_cast<uint32_t>(WithGuestFile<wint_t>(handle, WEOF,
            [c](FILE* file) { return fputwc(c, file); }));
    });
    RegisterThunk("ungetwc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wint_t c = static_cast<wint_t>(jit.Regs()[0]);
        uint32_t handle = jit.Regs()[1];
        jit.Regs()[0] = static_cast<uint32_t>(WithGuestFile<wint_t>(handle, WEOF,
            [c](FILE* file) { return ungetwc(c, file); }));
    });
    RegisterThunk("swprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        wchar_t* s = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t max = jit.Regs()[1];
        const wchar_t* fmt = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        if (s && fmt && max > 0) {
            wcsncpy(s, fmt, max);
            s[max - 1] = L'\0';
            jit.Regs()[0] = static_cast<uint32_t>(wcslen(s));
        } else {
            jit.Regs()[0] = 0;
        }
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing File / IO
    // -----------------------------------------------------------------------
    RegisterThunk("fgets", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* s = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int size = static_cast<int>(jit.Regs()[1]);
        uint32_t handle = jit.Regs()[2];
        char* res = s ? WithGuestFile<char*>(handle, nullptr,
            [s, size](FILE* file) { return fgets(s, size, file); }) : nullptr;
        jit.Regs()[0] = res ? jit.Regs()[0] : 0;
    });
    RegisterThunk("getc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        jit.Regs()[0] = static_cast<uint32_t>(WithGuestFile<int>(handle, EOF,
            [](FILE* file) { return getc(file); }));
    });
    RegisterThunk("rewind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        WithGuestFileVoid(handle, [](FILE* file) { rewind(file); });
    });
    RegisterThunk("ungetc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int c = static_cast<int>(jit.Regs()[0]);
        uint32_t handle = jit.Regs()[1];
        jit.Regs()[0] = static_cast<uint32_t>(WithGuestFile<int>(handle, EOF,
            [c](FILE* file) { return ungetc(c, file); }));
    });
    RegisterThunk("vsprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* s = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const auto formatted = FormatGuestVaList(host, fmt, jit.Regs()[2]);
        jit.Regs()[0] = static_cast<uint32_t>(arm32::CopyPrintfResult(
            s, formatted.text.size() + 1, formatted));
    });
    RegisterThunk("pread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        off_t offset = static_cast<off_t>(jit.Regs()[3]);
        if (buf) {
            if (ssize_t n = mc4::Phase3VfsHookPread(fd, buf, count, offset); n >= 0) {
                jit.Regs()[0] = static_cast<uint32_t>(n);
                return;
            }
        }
        ssize_t res = (fd >= 0 && buf) ? pread(fd, buf, count, offset) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("pread64", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        uint32_t sp = jit.Regs()[13];
        uint64_t off_lo = host.MemoryRead32(sp);
        uint64_t off_hi = host.MemoryRead32(sp + 4);
        off64_t offset = static_cast<off64_t>(off_lo | (off_hi << 32));
        if (buf) {
            if (ssize_t n = mc4::Phase3VfsHookPread(fd, buf, count, offset); n >= 0) {
                jit.Regs()[0] = static_cast<uint32_t>(n);
                return;
            }
        }
        ssize_t res = (fd >= 0 && buf) ? pread64(fd, buf, count, offset) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("writev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t iov_gaddr = jit.Regs()[1];
        int iovcnt = static_cast<int>(jit.Regs()[2]);
        if (!iov_gaddr || iovcnt <= 0) { jit.Regs()[0] = 0; return; }
        std::vector<struct iovec> host_iov(iovcnt);
        uint8_t* base = host.GetGuestMemoryBase();
        for (int i = 0; i < iovcnt; ++i) {
            uint32_t base_ptr = host.MemoryRead32(iov_gaddr + i * 8);
            uint32_t len = host.MemoryRead32(iov_gaddr + i * 8 + 4);
            host_iov[i].iov_base = base_ptr ? base + base_ptr : nullptr;
            host_iov[i].iov_len = len;
        }
        ssize_t res = writev(fd, host_iov.data(), iovcnt);
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("ftruncate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off_t len = static_cast<off_t>(jit.Regs()[1]);
        jit.Regs()[0] = static_cast<uint32_t>(ftruncate(fd, len));
    });
    RegisterThunk("ioctl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("dup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(dup(fd));
    });
    RegisterThunk("mprotect", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing Directory Functions
    // -----------------------------------------------------------------------
    static std::mutex s_dir_mutex;
    static std::unordered_map<uint32_t, DIR*> s_dir_map;
    static uint32_t s_next_dir_handle = 0x70000000;

    RegisterThunk("opendir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        DIR* d = name ? opendir(name) : nullptr;
        if (!d) { jit.Regs()[0] = 0; return; }
        std::lock_guard<std::mutex> lock(s_dir_mutex);
        uint32_t handle = s_next_dir_handle += 4;
        s_dir_map[handle] = d;
        jit.Regs()[0] = handle;
    });
    RegisterThunk("closedir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        std::lock_guard<std::mutex> lock(s_dir_mutex);
        auto it = s_dir_map.find(handle);
        if (it != s_dir_map.end()) {
            closedir(it->second);
            s_dir_map.erase(it);
            jit.Regs()[0] = 0;
        } else {
            jit.Regs()[0] = -1;
        }
    });
    RegisterThunk("readdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        DIR* d = nullptr;
        {
            std::lock_guard<std::mutex> lock(s_dir_mutex);
            auto it = s_dir_map.find(handle);
            if (it != s_dir_map.end()) d = it->second;
        }
        if (!d) { jit.Regs()[0] = 0; return; }
        struct dirent* de = readdir(d);
        if (!de) { jit.Regs()[0] = 0; return; }
        static uint32_t s_guest_dirent = 0;
        if (!s_guest_dirent) {
            s_guest_dirent = host.GuestAlloc(sizeof(struct dirent), 8);
        }
        memcpy(GuestToHost(host.GetGuestMemoryBase(), s_guest_dirent), de, sizeof(struct dirent));
        jit.Regs()[0] = s_guest_dirent;
    });
    RegisterThunk("mkdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        mode_t mode = static_cast<mode_t>(jit.Regs()[1]);
        jit.Regs()[0] = path ? static_cast<uint32_t>(mkdir(path, mode)) : -1;
    });
    RegisterThunk("chdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = path ? static_cast<uint32_t>(chdir(path)) : -1;
    });
    RegisterThunk("getcwd", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t size = jit.Regs()[1];
        char* res = (buf && size > 0) ? getcwd(buf, size) : nullptr;
        jit.Regs()[0] = res ? jit.Regs()[0] : 0;
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing Network Functions
    // -----------------------------------------------------------------------
    struct addrinfo32 {
        int32_t ai_flags;
        int32_t ai_family;
        int32_t ai_socktype;
        int32_t ai_protocol;
        uint32_t ai_addrlen;
        uint32_t ai_canonname;
        uint32_t ai_addr;
        uint32_t ai_next;
    };

    RegisterThunk("getaddrinfo", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* node = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* service = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        uint32_t hints_gaddr = jit.Regs()[2];
        uint32_t res_gaddr = jit.Regs()[3];
        struct addrinfo hints{};
        struct addrinfo* hints_ptr = nullptr;
        if (hints_gaddr) {
            uint32_t* gh = reinterpret_cast<uint32_t*>(GuestToHost(host.GetGuestMemoryBase(), hints_gaddr));
            hints.ai_flags = static_cast<int>(gh[0]);
            hints.ai_family = static_cast<int>(gh[1]);
            hints.ai_socktype = static_cast<int>(gh[2]);
            hints.ai_protocol = static_cast<int>(gh[3]);
            hints_ptr = &hints;
        }
        struct addrinfo* host_res = nullptr;
        int ret = getaddrinfo(node, service, hints_ptr, &host_res);
        if (ret == 0 && host_res && res_gaddr) {
            uint32_t gai_buf = host.GuestAlloc(sizeof(addrinfo32) + host_res->ai_addrlen + 64, 4);
            addrinfo32* gai = reinterpret_cast<addrinfo32*>(GuestToHost(host.GetGuestMemoryBase(), gai_buf));
            gai->ai_flags = host_res->ai_flags;
            gai->ai_family = host_res->ai_family;
            gai->ai_socktype = host_res->ai_socktype;
            gai->ai_protocol = host_res->ai_protocol;
            gai->ai_addrlen = host_res->ai_addrlen;
            gai->ai_canonname = 0;
            gai->ai_next = 0;
            uint32_t saddr = gai_buf + sizeof(addrinfo32);
            memcpy(GuestToHost(host.GetGuestMemoryBase(), saddr), host_res->ai_addr, host_res->ai_addrlen);
            gai->ai_addr = saddr;
            host.MemoryWrite32(res_gaddr, gai_buf);
            freeaddrinfo(host_res);
        } else if (res_gaddr) {
            host.MemoryWrite32(res_gaddr, 0);
        }
        jit.Regs()[0] = static_cast<uint32_t>(ret);
    });
    RegisterThunk("freeaddrinfo", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t addr = jit.Regs()[0];
        if (addr) host.GuestFree(addr);
    });
    RegisterThunk("gethostname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* name = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t len = jit.Regs()[1];
        jit.Regs()[0] = (name && len > 0) ? static_cast<uint32_t>(gethostname(name, len)) : -1;
    });
    RegisterThunk("getsockname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        struct sockaddr* sa = reinterpret_cast<struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        socklen_t* sl = reinterpret_cast<socklen_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        jit.Regs()[0] = getsockname(fd, sa, sl);
    });
    RegisterThunk("getpeername", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        struct sockaddr* sa = reinterpret_cast<struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        socklen_t* sl = reinterpret_cast<socklen_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        jit.Regs()[0] = getpeername(fd, sa, sl);
    });
    RegisterThunk("getsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int level = static_cast<int>(jit.Regs()[1]);
        int optname = static_cast<int>(jit.Regs()[2]);
        void* optval = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]);
        uint32_t sp = jit.Regs()[13];
        uint32_t optlen_gaddr = host.MemoryRead32(sp);
        socklen_t* optlen = optlen_gaddr ? reinterpret_cast<socklen_t*>(GuestToHost(host.GetGuestMemoryBase(), optlen_gaddr)) : nullptr;
        jit.Regs()[0] = getsockopt(fd, level, optname, optval, optlen);
    });
    RegisterThunk("inet_ntoa", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct in_addr in;
        in.s_addr = jit.Regs()[0];
        char* str = inet_ntoa(in);
        static uint32_t s_ntoa_buf = 0;
        if (!s_ntoa_buf) s_ntoa_buf = host.GuestAlloc(32, 4);
        if (str) strcpy(reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), s_ntoa_buf)), str);
        jit.Regs()[0] = s_ntoa_buf;
    });
    RegisterThunk("poll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct pollfd* fds = reinterpret_cast<struct pollfd*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        nfds_t nfds = static_cast<nfds_t>(jit.Regs()[1]);
        int timeout = static_cast<int>(jit.Regs()[2]);
        jit.Regs()[0] = poll(fds, nfds, timeout);
    });
    RegisterThunk("recvfrom", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t len = jit.Regs()[2];
        int flags = static_cast<int>(jit.Regs()[3]);
        uint32_t sp = jit.Regs()[13];
        uint32_t src_addr = host.MemoryRead32(sp);
        uint32_t addrlen_ptr = host.MemoryRead32(sp + 4);
        struct sockaddr* sa = src_addr ? reinterpret_cast<struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), src_addr)) : nullptr;
        socklen_t* sl = addrlen_ptr ? reinterpret_cast<socklen_t*>(GuestToHost(host.GetGuestMemoryBase(), addrlen_ptr)) : nullptr;
        ssize_t res = recvfrom(fd, buf, len, flags, sa, sl);
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("sendto", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t len = jit.Regs()[2];
        int flags = static_cast<int>(jit.Regs()[3]);
        uint32_t sp = jit.Regs()[13];
        uint32_t dest_addr = host.MemoryRead32(sp);
        socklen_t addrlen = static_cast<socklen_t>(host.MemoryRead32(sp + 4));
        const struct sockaddr* sa = dest_addr ? reinterpret_cast<const struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), dest_addr)) : nullptr;
        ssize_t res = sendto(fd, buf, len, flags, sa, addrlen);
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("shutdown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int how = static_cast<int>(jit.Regs()[1]);
        jit.Regs()[0] = shutdown(fd, how);
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing pthread Functions
    // -----------------------------------------------------------------------
    RegisterThunk("pthread_cond_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestCondDestroy(jit.Regs()[0]);
    });
    RegisterThunk("pthread_cond_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestCondInit(jit.Regs()[0], jit.Regs()[1]);
    });
    RegisterThunk("pthread_cond_timedwait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestCondWait(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], true);
    });
    RegisterThunk("pthread_condattr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 4)) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        host.MemoryWrite32(jit.Regs()[0], 0);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_equal", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = (jit.Regs()[0] == jit.Regs()[1]) ? 1 : 0;
    });
    RegisterThunk("pthread_join", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t id = jit.Regs()[0];
        const uint32_t result_out = jit.Regs()[1];
        if (result_out && !GuestRangeValid(host.GetGuestMemorySize(), result_out, 4)) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        if (id == CurrentGuestPthreadId()) {
            jit.Regs()[0] = EDEADLK;
            return;
        }
        std::unique_lock lock(g_guest_threads_mutex);
        auto it = g_guest_threads.find(id);
        if (it == g_guest_threads.end()) { jit.Regs()[0] = ESRCH; return; }
        auto completion = it->second;
        if (completion->detached || completion->joining) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        completion->joining = true;
        completion->changed.wait(lock, [&] { return completion->finished; });
        const uint32_t result = completion->result;
        g_guest_threads.erase(id);
        lock.unlock();
        if (result_out) host.MemoryWrite32(result_out, result);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_key_delete", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t key = jit.Regs()[0];
        std::lock_guard lock(g_guest_tls_keys_mutex);
        if (key < 7 || key >= g_guest_tls_keys.size() ||
            !g_guest_tls_keys[key].allocated) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        host.GuestClearTlsSlotForAllThreads(key);
        g_guest_tls_keys[key] = {};
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_trylock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = host.GuestMutexTryLock(jit.Regs()[0]);
    });
    RegisterThunk("pthread_mutexattr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 4) ? 0 : EINVAL;
    });
    RegisterThunk("pthread_setname_np", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_detach", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t id = jit.Regs()[0];
        std::lock_guard lock(g_guest_threads_mutex);
        auto it = g_guest_threads.find(id);
        if (it == g_guest_threads.end()) { jit.Regs()[0] = ESRCH; return; }
        auto completion = it->second;
        if (completion->detached || completion->joining) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        completion->detached = true;
        if (completion->finished) g_guest_threads.erase(it);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sched_yield", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        sched_yield();
        jit.Regs()[0] = 0;
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing Process / System / Time Functions
    // -----------------------------------------------------------------------
    RegisterThunk("atol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(atol(s)) : 0;
    });
    RegisterThunk("clock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(clock());
    });
    RegisterThunk("clock_gettime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        clockid_t clk_id = static_cast<clockid_t>(jit.Regs()[0]);
        uint32_t tp_gaddr = jit.Regs()[1];
        struct timespec ts{};
        int res = clock_gettime(clk_id, &ts);
        if (res == 0 && tp_gaddr) {
            host.MemoryWrite32(tp_gaddr, static_cast<uint32_t>(ts.tv_sec));
            host.MemoryWrite32(tp_gaddr + 4, static_cast<uint32_t>(ts.tv_nsec));
        }
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("difftime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        time_t t1 = static_cast<time_t>(jit.Regs()[0]);
        time_t t0 = static_cast<time_t>(jit.Regs()[1]);
        double res = difftime(t1, t0);
        WriteDF(jit, 0, res);
    });
    RegisterThunk("exit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int code = static_cast<int>(jit.Regs()[0]);
        uint32_t lr = jit.Regs()[14];
        uint32_t sp = jit.Regs()[13];
        std::string stk;
        for (int i = 0; i < 24; ++i) {
            char b[16];
            snprintf(b, sizeof(b), " %08X", host.MemoryRead32(sp + i * 4));
            stk += b;
        }
        // nativeStart's NULL check: GOT slot 0x41798440 -> static var ->
        // Application object pointer. Dump the whole chain at exit time.
        uint32_t got = host.MemoryRead32(0x41798440u);
        uint32_t obj = host.MemoryRead32(got);
        LOGE("[GUEST-EXIT] code=%d LR=%08X SP=%08X gotSlot=%08X -> var=%08X -> obj=%08X stack:%s",
             code, lr, sp, got, obj ? 0u : obj, obj, stk.c_str());
        // Do not kill the whole host process: the guest's exit() during the
        // installer phase is a data-check bail-out, not a game quit. Park the
        // calling thread instead of tearing down every background worker.
        for (;;) std::this_thread::sleep_for(std::chrono::hours(1));
    });
    RegisterThunk("getenv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        char* val = name ? getenv(name) : nullptr;
        if (!val) { jit.Regs()[0] = 0; return; }
        size_t len = strlen(val) + 1;
        uint32_t gval = host.GuestAlloc(len, 4);
        strcpy(reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), gval)), val);
        jit.Regs()[0] = gval;
    });
    RegisterThunk("getuid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getuid(); });
    RegisterThunk("geteuid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = geteuid(); });
    RegisterThunk("getgid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getgid(); });
    RegisterThunk("getegid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getegid(); });
    RegisterThunk("gettid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = gettid(); });
    RegisterThunk("getpwuid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uid_t uid = static_cast<uid_t>(jit.Regs()[0]);
        struct passwd* pw = getpwuid(uid);
        if (!pw) { jit.Regs()[0] = 0; return; }
        static uint32_t s_guest_passwd = 0;
        if (!s_guest_passwd) s_guest_passwd = host.GuestAlloc(128, 4);
        uint8_t* base = host.GetGuestMemoryBase();
        uint32_t* gpw = reinterpret_cast<uint32_t*>(base + s_guest_passwd);
        gpw[0] = 0; gpw[1] = 0;
        gpw[2] = pw->pw_uid; gpw[3] = pw->pw_gid;
        gpw[4] = 0; gpw[5] = 0; gpw[6] = 0;
        jit.Regs()[0] = s_guest_passwd;
    });
    RegisterThunk("prctl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("setlocale", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static uint32_t s_c_locale = 0;
        if (!s_c_locale) {
            s_c_locale = host.GuestAlloc(8, 4);
            strcpy(reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), s_c_locale)), "C");
        }
        jit.Regs()[0] = s_c_locale;
    });
    RegisterThunk("sigaction", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("bsd_signal", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("sysconf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int name = static_cast<int>(jit.Regs()[0]);
        long res = sysconf(name);
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("syscall", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("system", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = -1; });
    RegisterThunk("tolower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(tolower(static_cast<int>(jit.Regs()[0])));
    });
    RegisterThunk("perror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (s) LOGE("perror: %s", s);
    });
    RegisterThunk("setjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("longjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("longjmp called in guest!");
    });
    RegisterThunk("__android_log_vprint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        LOGI("[GuestLog %s] %s", tag ? tag : "null", fmt ? fmt : "null");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("dlerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dl_iterate_phdr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Time functions
    RegisterThunk("gmtime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t timep_gaddr = jit.Regs()[0];
        if (!timep_gaddr) { jit.Regs()[0] = 0; return; }
        time_t t = static_cast<time_t>(host.MemoryRead32(timep_gaddr));
        struct tm* tm_res = gmtime(&t);
        if (!tm_res) { jit.Regs()[0] = 0; return; }
        static uint32_t s_gmtime_buf = 0;
        if (!s_gmtime_buf) s_gmtime_buf = host.GuestAlloc(64, 4);
        uint8_t* gtm = reinterpret_cast<uint8_t*>(GuestToHost(host.GetGuestMemoryBase(), s_gmtime_buf));
        int* igtm = reinterpret_cast<int*>(gtm);
        igtm[0] = tm_res->tm_sec; igtm[1] = tm_res->tm_min; igtm[2] = tm_res->tm_hour;
        igtm[3] = tm_res->tm_mday; igtm[4] = tm_res->tm_mon; igtm[5] = tm_res->tm_year;
        igtm[6] = tm_res->tm_wday; igtm[7] = tm_res->tm_yday; igtm[8] = tm_res->tm_isdst;
        jit.Regs()[0] = s_gmtime_buf;
    });
    RegisterThunk("gmtime_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t timep_gaddr = jit.Regs()[0];
        uint32_t res_gaddr = jit.Regs()[1];
        if (!timep_gaddr || !res_gaddr) { jit.Regs()[0] = 0; return; }
        time_t t = static_cast<time_t>(host.MemoryRead32(timep_gaddr));
        struct tm tm_res{};
        if (!gmtime_r(&t, &tm_res)) { jit.Regs()[0] = 0; return; }
        uint8_t* gtm = reinterpret_cast<uint8_t*>(GuestToHost(host.GetGuestMemoryBase(), res_gaddr));
        int* igtm = reinterpret_cast<int*>(gtm);
        igtm[0] = tm_res.tm_sec; igtm[1] = tm_res.tm_min; igtm[2] = tm_res.tm_hour;
        igtm[3] = tm_res.tm_mday; igtm[4] = tm_res.tm_mon; igtm[5] = tm_res.tm_year;
        igtm[6] = tm_res.tm_wday; igtm[7] = tm_res.tm_yday; igtm[8] = tm_res.tm_isdst;
        jit.Regs()[0] = res_gaddr;
    });
    RegisterThunk("localtime_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t timep_gaddr = jit.Regs()[0];
        uint32_t res_gaddr = jit.Regs()[1];
        if (!timep_gaddr || !res_gaddr) { jit.Regs()[0] = 0; return; }
        time_t t = static_cast<time_t>(host.MemoryRead32(timep_gaddr));
        struct tm tm_res{};
        if (!localtime_r(&t, &tm_res)) { jit.Regs()[0] = 0; return; }
        uint8_t* gtm = reinterpret_cast<uint8_t*>(GuestToHost(host.GetGuestMemoryBase(), res_gaddr));
        int* igtm = reinterpret_cast<int*>(gtm);
        igtm[0] = tm_res.tm_sec; igtm[1] = tm_res.tm_min; igtm[2] = tm_res.tm_hour;
        igtm[3] = tm_res.tm_mday; igtm[4] = tm_res.tm_mon; igtm[5] = tm_res.tm_year;
        igtm[6] = tm_res.tm_wday; igtm[7] = tm_res.tm_yday; igtm[8] = tm_res.tm_isdst;
        jit.Regs()[0] = res_gaddr;
    });
    RegisterThunk("strftime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* s = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t max = jit.Regs()[1];
        const char* format = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        uint32_t tm_gaddr = jit.Regs()[3];
        struct tm tm_val{};
        if (tm_gaddr) {
            int* gtm = reinterpret_cast<int*>(GuestToHost(host.GetGuestMemoryBase(), tm_gaddr));
            tm_val.tm_sec = gtm[0]; tm_val.tm_min = gtm[1]; tm_val.tm_hour = gtm[2];
            tm_val.tm_mday = gtm[3]; tm_val.tm_mon = gtm[4]; tm_val.tm_year = gtm[5];
            tm_val.tm_wday = gtm[6]; tm_val.tm_yday = gtm[7]; tm_val.tm_isdst = gtm[8];
        }
        size_t res = (s && format && max > 0) ? strftime(s, max, format, &tm_val) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("strptime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* format = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        uint32_t tm_gaddr = jit.Regs()[2];
        struct tm tm_val{};
        char* res = (s && format) ? strptime(s, format, &tm_val) : nullptr;
        if (res && tm_gaddr) {
            int* gtm = reinterpret_cast<int*>(GuestToHost(host.GetGuestMemoryBase(), tm_gaddr));
            gtm[0] = tm_val.tm_sec; gtm[1] = tm_val.tm_min; gtm[2] = tm_val.tm_hour;
            gtm[3] = tm_val.tm_mday; gtm[4] = tm_val.tm_mon; gtm[5] = tm_val.tm_year;
            gtm[6] = tm_val.tm_wday; gtm[7] = tm_val.tm_yday; gtm[8] = tm_val.tm_isdst;
        }
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - AAsset Thunks
    // -----------------------------------------------------------------------
    static std::mutex s_aasset_mutex;
    static std::unordered_map<uint32_t, AAsset*> s_aasset_map;
    static std::unordered_map<uint32_t, AAssetDir*> s_aasset_dir_map;
    static uint32_t s_next_aasset_handle = 0x60000000;

    RegisterThunk("AAssetManager_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fn = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        int mode = static_cast<int>(jit.Regs()[2]);
        LOGI("AAssetManager_open('%s', mode=%d)", fn ? fn : "null", mode);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("AAssetManager_openDir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* dn = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        LOGI("AAssetManager_openDir('%s')", dn ? dn : "null");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("AAssetDir_getNextFileName", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("AAssetDir_close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("AAsset_close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("AAsset_getLength", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("AAsset_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("AAsset_seek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(-1);
    });

    // -----------------------------------------------------------------------
    // Modern Combat 4 - Missing Data Symbols
    // __stack_chk_guard (0x100) and __sF (0x200) are already registered at the
    // top of this function; fill in the ctype tables the guest reads directly.
    //
    // The guest imports _ctype_/_tolower_tab_/_toupper_tab_ as bionic pointer
    // VARIABLES (const char * const / const short * const): the GOT slot holds
    // the address of the pointer cell, and the guest dereferences the cell to
    // reach the table (genericDriverInit does ldr r3,[got]; ldr r1,[r3];
    // ldrsb r3,[r1,c+1]). Registering the table address directly made the first
    // scan dereference read the table's own first word (0x20202000 = the "00 20
    // 20 20" header bytes) and the GL version scan never terminated. Wrap every
    // table in a 4-byte pointer cell so the guest's extra deref lands on it.
    // -----------------------------------------------------------------------
    {
        uint32_t ctype_addr = m_host.GuestAlloc(257, 4);
        uint8_t* ctype_mem = reinterpret_cast<uint8_t*>(GuestToHost(m_host.GetGuestMemoryBase(), ctype_addr));
        memset(ctype_mem, 0, 257);
        for (int i = 0; i < 256; ++i) {
            uint8_t flags = 0;
            if (isupper(i)) flags |= 0x01;
            if (islower(i)) flags |= 0x02;
            if (isdigit(i)) flags |= 0x04;
            if (isspace(i)) flags |= 0x08;
            if (ispunct(i)) flags |= 0x10;
            if (iscntrl(i)) flags |= 0x20;
            if (isxdigit(i)) flags |= 0x40;
            ctype_mem[i + 1] = flags;
        }
        uint32_t ctype_cell = m_host.GuestAlloc(4, 4);
        m_host.MemoryWrite32(ctype_cell, ctype_addr);
        RegisterSymbol("_ctype_", ctype_cell);

        uint32_t tolower_addr = m_host.GuestAlloc(257 * sizeof(short), 4);
        short* tolower_mem = reinterpret_cast<short*>(GuestToHost(m_host.GetGuestMemoryBase(), tolower_addr));
        tolower_mem[0] = -1;
        for (int i = 0; i < 256; ++i) tolower_mem[i + 1] = static_cast<short>(tolower(i));
        uint32_t tolower_cell = m_host.GuestAlloc(4, 4);
        m_host.MemoryWrite32(tolower_cell, tolower_addr);
        RegisterSymbol("_tolower_tab_", tolower_cell);

        uint32_t toupper_addr = m_host.GuestAlloc(257 * sizeof(short), 4);
        short* toupper_mem = reinterpret_cast<short*>(GuestToHost(m_host.GetGuestMemoryBase(), toupper_addr));
        toupper_mem[0] = -1;
        for (int i = 0; i < 256; ++i) toupper_mem[i + 1] = static_cast<short>(toupper(i));
        uint32_t toupper_cell = m_host.GuestAlloc(4, 4);
        m_host.MemoryWrite32(toupper_cell, toupper_addr);
        RegisterSymbol("_toupper_tab_", toupper_cell);
    }
}

// ---------------------------------------------------------------------------
// Loading modified assets from <externalFilesDir>/...
//
// Engines of this era resolve a file through a chain: archive -> optional second
// archive -> plain fopen(rootDir + path). Making the first archive report "not
// found" for any file the user dropped into the override root turns that existing
// fallback into a full mod mechanism, with no archive-format code and no risk to
// the normal path. Point InstallAssetOverrideHook at the guest's archive-open PLT
// slot; everything below is engine-agnostic.
// ---------------------------------------------------------------------------

static std::string g_override_root;   // e.g. /sdcard/Android/data/<pkg>/files/
static bool g_override_enabled = false;

void SetAssetOverrideRoot(const std::string& root) {
    g_override_root = root;
    if (!g_override_root.empty() && g_override_root.back() != '/') g_override_root += '/';
    struct stat st;
    g_override_enabled = !g_override_root.empty() &&
                         stat(g_override_root.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    LOGI("Asset override root: '%s' (%s)", g_override_root.c_str(), g_override_enabled ? "active" : "inactive");
}

bool HasAssetOverride(const char* entry_name) {
    if (!g_override_enabled || !entry_name) return false;
    // Entry names carry the archive layout, e.g. "assets/data/textures/x.bin" or
    // "<expansion-prefix>/assets/data/textures/x.bin"; the override root mirrors
    // everything below "assets/". Adjust this split if the guest archives differ.
    const char* rel = strstr(entry_name, "assets/");
    if (!rel) return false;
    rel += 7;
    if (!*rel) return false;
    std::string path = g_override_root + rel;
    if (access(path.c_str(), R_OK) != 0) return false;
    LOGI("Asset override: '%s' -> '%s'", entry_name, path.c_str());
    return true;
}

void InstallAssetOverrideHook(DynarmicHost& host, uint32_t plt_slot, const char* real_symbol) {
    if (!g_override_enabled || !plt_slot || !real_symbol) return;

    static bool s_installed = false;
    if (s_installed) return;

    g_asset_override_real_fn = host.GetElfLoader().GetSymbolAddress(real_symbol);
    if (!g_asset_override_real_fn) {
        LOGE("InstallAssetOverrideHook: '%s' not found in the guest", real_symbol);
        return;
    }

    uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("asset_override_archive_open");
    uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) {
        LOGE("InstallAssetOverrideHook: unexpected trampoline at 0x%08X", hook);
        return;
    }

    // ARM veneer: run the hook, then either tail-call the real archive-open (ip != 0)
    // or return NULL. BX reaches the whole address space and handles the Thumb bit,
    // so unlike a B-based trampoline there is no +-32 MB limit.
    uint32_t veneer = host.GuestAlloc(32, 4);
    host.MemoryWrite32(veneer + 0,  svc);         // svc  #id
    host.MemoryWrite32(veneer + 4,  0xE35C0000);  // cmp  ip, #0
    host.MemoryWrite32(veneer + 8,  0x112FFF1C);  // bxne ip
    host.MemoryWrite32(veneer + 12, 0xE3A00000);  // mov  r0, #0
    host.MemoryWrite32(veneer + 16, 0xE12FFF1E);  // bx   lr
    host.InvalidateGuestCode(veneer, 32);

    host.MemoryWrite32(plt_slot + 0, 0xE51FF004);  // ldr pc, [pc, #-4]
    host.MemoryWrite32(plt_slot + 4, veneer);
    host.InvalidateGuestCode(plt_slot, 12);
    // The veneer is executable guest code living in the heap, so it must be
    // exempt from runaway-PC containment.
    host.AddExecutableRange(veneer, 32);

    s_installed = true;
    LOGI("Installed asset-override hook on '%s' (plt 0x%08X, veneer 0x%08X)",
         real_symbol, plt_slot, veneer);
}
