// MC4 phase3 VFS, host side of the arm64 bridge.
//
// Direct port of work/phase3_vfs/phase3_vfs.c (arm32 guest library) into the
// 64-bit bridge host. On arm32 the guest library hooked the game's libc
// imports by GOT patching; here the bridge *is* the libc layer
// (thunks_libc.cpp), so the hooks become first-class checks inside the
// existing fopen/open/fdopen/close/read/pread/pread64/lseek/lseek64/stat/
// fstat/mmap thunks via the Phase3VfsHook* functions below. The virtual
// archive layout, the 69-asset expectation, main/patch views, dup-backed
// virtual fds and the cheat-gate / IAP-route guest patches are identical to
// the original, keeping external Phase 3/4 rules intact (STATE.md).
//
// phase3_vfs.c line numbers referenced in comments are from that file.

#include "mc4_phase3.h"
#include "arm32_push.h"

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "sha256_file.h"
#include "thunk_manager.h"

#define LOG_TAG "MC4Phase3Vfs"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" FILE* funopen(const void*, int (*)(void*, char*, int),
                         int (*)(void*, const char*, int),
                         fpos_t (*)(void*, fpos_t, int), int (*)(void*));

namespace mc4 {

// --- constants (phase3_vfs.c:27-36) ---
constexpr size_t kMaxAssets = 128;
// The embedded main OBB has 69 indexed members. Runtime snapshots reached
// 64 live OBB streams (61 flat) before later mission/resource opens completed;
// 128 is the next power-of-two with room for patch and member handles too.
constexpr size_t kMaxHandles = 128;
constexpr int VFD_BASE = 1000;
constexpr const char* APK_NAME = "assets/";
constexpr const char* APK_SKIP = "assets/eventParameters.json";
constexpr const char* APK_GUEST_LIBS = "assets/guest_libs/";
constexpr const char* kPackageObb = "/Android/obb/com.gameloft.android.ANMP.GloftM4HM/";

// Guest offsets inside libModernCombat4.so (phase3_vfs.c:186, 262, 1370).
constexpr uint32_t kCheatGateOffset = 0x75bab8u;
constexpr uint32_t kCheatGateContinue = 0x75bc10u;
constexpr uint32_t kCheatGateOptionZero = 0x75bbecu;

// --- structures (phase3_vfs.c:38-67) ---
struct AssetEntry {
    char name[PATH_MAX];
    off64_t apk_offset;
    off64_t size;
    off64_t local_offset;
    off64_t data_offset;
    uint32_t crc32;
    uint16_t name_len;
    uint16_t extra_len;
    // Small offline-only metadata files are owned by the bridge process. Real
    // pack entries instead point directly into the APK's nested data_4 ZIP.
    const uint8_t* host_data = nullptr;
    bool patch_source = false;
};

struct VirtualArchive {
    int apk_fd = -1;
    off64_t size = 0;
    off64_t central_offset = 0;
    off64_t central_size = 0;
    long page_size = 4096;
    std::vector<AssetEntry> entries;
};

struct AssetRef {
    VirtualArchive* archive = nullptr;
    AssetEntry* entry = nullptr;
};

struct VirtualHandle {
    bool used = false;
    uint64_t generation = 0;
    int vfd = 0;
    int real_fd = -1;
    off64_t position = 0;
    VirtualArchive* archive = nullptr;
    AssetEntry* asset = nullptr;
    // Whole-OBB mode (2026-09-17): the handle is a flat window onto an OBB
    // file stored verbatim inside the APK; reads pread straight through.
    bool flat = false;
    off64_t flat_offset = 0;
    off64_t flat_size = 0;
    std::chrono::steady_clock::time_point opened_at{};
    unsigned log_ops = 0;
};

// OBB containers shipped verbatim inside the APK (2026-09-17 directive: the
// cache is read as OBB files inside the APK, not as unpacked assets).
struct ObbAsset {
    bool present = false;
    off64_t apk_offset = 0;   // first payload byte of the OBB inside the APK
    off64_t size = 0;
};
static ObbAsset g_main_obb_asset;
static ObbAsset g_patch_obb_asset;

// --- state (phase3_vfs.c:84-102) ---
static VirtualArchive g_archive;
static VirtualArchive g_patch_archive;
// Entries in the nested ZIPs inside main/patch data_4. Their payload offsets
// are absolute offsets into the installed APK, so no OBB extraction or device
// side staging is needed.
static std::vector<AssetEntry> g_pack_assets;
static VirtualHandle g_handles[kMaxHandles];
static std::mutex g_lock;
static std::string g_apk_path;
static std::atomic<int> g_installed{0};
static std::atomic<uint32_t> g_cheat_entitlements{0};
static std::atomic<int> g_cheat_gate_ready{0};

// Empty offline multiplayer arrays are a distinct, explicitly deferred path.
static uint8_t g_empty_array[4];

// Called only while g_lock is held, and only on a sampled allocation failure.
// This distinguishes a transient peak from handles that remain live for the
// whole route without changing the table limit or allocation policy.
static void LogLiveHandlesLocked(uint32_t failure) {
    const auto now = std::chrono::steady_clock::now();
    size_t active = 0;
    size_t flat = 0;
    size_t age_ge_60s = 0;
    size_t age_ge_180s = 0;
    long long oldest_seconds = 0;
    for (const VirtualHandle& h : g_handles) {
        if (!h.used) continue;
        ++active;
        if (h.flat) ++flat;
        if (h.opened_at.time_since_epoch().count() == 0) continue;
        const auto age_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            now - h.opened_at).count();
        if (age_seconds >= 60) ++age_ge_60s;
        if (age_seconds >= 180) ++age_ge_180s;
        oldest_seconds = std::max(oldest_seconds, (long long)age_seconds);
    }

    char snapshot[1024];
    int prefix = snprintf(snapshot, sizeof(snapshot),
                          "VFS handles: failure=%u active=%zu/%zu flat=%zu age60=%zu age180=%zu oldest=%llds slots=[",
                          failure, active, kMaxHandles, flat, age_ge_60s,
                          age_ge_180s, oldest_seconds);
    if (prefix < 0) return;
    size_t used = std::min(static_cast<size_t>(prefix), sizeof(snapshot) - 1);
    bool first = true;
    for (size_t i = 0; i < kMaxHandles; ++i) {
        if (i >= 12 && i < kMaxHandles - 12) continue;
        const VirtualHandle& h = g_handles[i];
        if (!h.used) continue;
        const auto age_ms = h.opened_at.time_since_epoch().count() == 0
            ? -1LL
            : std::chrono::duration_cast<std::chrono::milliseconds>(now - h.opened_at).count();
        const char kind = !h.flat ? 'A'
            : h.flat_offset == g_patch_obb_asset.apk_offset ? 'P' : 'M';
        int written = snprintf(snapshot + used, sizeof(snapshot) - used,
                               "%s%02zu%c:%lld:%lld", first ? "" : ",", i, kind,
                               (long long)(age_ms < 0 ? -1 : age_ms / 1000),
                               (long long)(h.position / (1024 * 1024)));
        if (written < 0) break;
        first = false;
        if (static_cast<size_t>(written) >= sizeof(snapshot) - used) {
            used = sizeof(snapshot) - 1;
            break;
        }
        used += static_cast<size_t>(written);
    }
    if (used < sizeof(snapshot) - 1) {
        snapshot[used++] = ']';
        snapshot[used] = '\0';
    }
    LOGE("%s", snapshot);
}

// --- byte helpers (phase3_vfs.c:120-141) ---
static uint16_t read_u16(const unsigned char* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t read_u32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static void write_u16(unsigned char* p, uint16_t value) {
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
}
static void write_u32(unsigned char* p, uint32_t value) {
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}
static uint32_t Crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xffffffffu;
}

// --- entitlements (phase3_vfs.c:172-183) ---
bool Phase3AllowCheatOption(int option) {
    if (option < 18 || option > 32) return true;
    if (option == 22 || option == 32) return false;
    return true;  // Original switches/saveOption own both ON and OFF states.
}

void Phase3SetCheatEntitlement(int option) {
    if (option < 18 || option > 31 || option == 22) return;
    g_cheat_entitlements |= 1u << (unsigned)(option - 18);
    LOGI("cheat entitlement option=%d mask=0x%08x", option,
         (unsigned)g_cheat_entitlements.load());
}

bool Phase3GateReady() { return g_cheat_gate_ready.load() != 0; }

// --- path classification (phase3_vfs.c:353-359) ---
// The game opens the OBB locations WITHOUT the .obb suffix
// (/storage/.../obb/<pkg>/main.12222|patch.12222 -- see the OBB-PATCH probe).
static bool IsMainObbLocation(const char* path) {
    return path && strstr(path, kPackageObb) &&
           (strstr(path, "/main.12222") != nullptr || strstr(path, "/main.1100") != nullptr);
}
static bool IsPatchObbLocation(const char* path) {
    return path && strstr(path, kPackageObb) && strstr(path, "/patch.12222") != nullptr;
}
static bool IsObbLocation(const char* path) {
    return IsMainObbLocation(path) || IsPatchObbLocation(path);
}
// Legacy spellings (an explicit .obb name on device storage).
static bool IsObbPath(const char* path) {
    return IsObbLocation(path) || (path && strstr(path, kPackageObb) && strstr(path, ".obb"));
}
static bool IsPatchObb(const char* path) {
    return IsPatchObbLocation(path) || (IsObbPath(path) && strstr(path, "/patch.") != nullptr);
}

// --- handle table (phase3_vfs.c:361-367) ---
// The caller must hold g_lock through lookup and use. The slot objects are
// stable, but their contents may be recycled as soon as the lock is released.
static VirtualHandle* HandleForFdLocked(int fd) {
    if (fd < VFD_BASE || fd >= VFD_BASE + (int)kMaxHandles) return nullptr;
    VirtualHandle* h = &g_handles[fd - VFD_BASE];
    return (h->used && h->vfd == fd) ? h : nullptr;
}

static ssize_t ArchiveReadAt(const VirtualArchive* archive, void* buffer, size_t count,
                             off64_t position);

// --- data_1..data_6 lookup (phase3_vfs.c:372-387) ---
static AssetRef AssetForPath(const char* path) {
    if (!path) return {};
    const char* name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (!*name) return {};
    // iFPS::Init mounts the patch OBB before main. Preserve that overlay
    // precedence when the game opens its extracted data_N files by basename.
    for (auto& e : g_patch_archive.entries)
        if (strcmp(e.name, name) == 0) return {&g_patch_archive, &e};
    // The main OBB supplies the base files and any names absent from patch.
    for (auto& e : g_archive.entries)
        if (strcmp(e.name, name) == 0) return {&g_archive, &e};
    // data_4 contains nested packs; their entries were indexed patch-first.
    for (auto& e : g_pack_assets)
        if (strcmp(e.name, name) == 0)
            return {e.patch_source ? &g_patch_archive : &g_archive, &e};
    return {};
}

int Phase3OpenMedia(const char* name, off64_t* offset, off64_t* length) {
    const char* extension = name ? strrchr(name, '.') : nullptr;
    if (!offset || !length || !extension ||
        (strcmp(extension, ".mp4") && strcmp(extension, ".srt"))) {
        errno = EINVAL;
        return -1;
    }
    if (!Phase3Installed()) { errno = ENOENT; return -1; }
    std::lock_guard<std::mutex> lock(g_lock);
    const auto asset = AssetForPath(name);
    if (!asset.entry || !asset.archive || asset.entry->host_data ||
        asset.entry->apk_offset < 0 || asset.entry->size <= 0) {
        errno = ENOENT;
        return -1;
    }
    struct stat64 st{};
    if (fstat64(asset.archive->apk_fd, &st)) return -1;
    if (asset.entry->apk_offset > st.st_size ||
        asset.entry->size > st.st_size - asset.entry->apk_offset) {
        errno = EIO;
        return -1;
    }
    // AFD InputStream skips from the current cursor; dup would share it with other readers.
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", asset.archive->apk_fd);
    const int fd = open(fd_path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        *offset = asset.entry->apk_offset;
        *length = asset.entry->size;
    }
    return fd;
}

static off64_t HandleSize(const VirtualHandle* h) {
    if (h->flat) return h->flat_size;
    return h->asset ? h->asset->size : h->archive->size;
}

// (phase3_vfs.c:393-411)
static ssize_t HandleReadAt(VirtualHandle* h, void* buffer, size_t count, off64_t position) {
    if (h->asset && h->asset->host_data) {
        // Log host_data reads (Res.array manifest verification): throttled.
        static std::atomic<uint32_t> hd_n{0};
        uint32_t hk = hd_n.fetch_add(1, std::memory_order_relaxed) + 1;
        if (hk <= 20 || (hk % 500) == 0)
            LOGI("virtual host_data read: vfd=%d pos=%lld count=%d size=%d #%u",
                 h->vfd, (long long)position, (int)count, (int)h->asset->size, hk);
        if (position < 0 || position >= h->asset->size) return 0;
        if ((off64_t)count > h->asset->size - position)
            count = (size_t)(h->asset->size - position);
        memcpy(buffer, h->asset->host_data + position, count);
        return (ssize_t)count;
    }
    if (h->flat) {
        if (position < 0 || position >= h->flat_size) return 0;
        if ((off64_t)count > h->flat_size - position)
            count = (size_t)(h->flat_size - position);
        ssize_t result = pread64(h->real_fd, buffer, count, h->flat_offset + position);
        if (result != (ssize_t)count) { errno = EIO; return -1; }
        return result;
    }
    if (h->asset) {
        if (position < 0 || position >= h->asset->size) return 0;
        if ((off64_t)count > h->asset->size - position)
            count = (size_t)(h->asset->size - position);
        ssize_t result = pread64(h->real_fd, buffer, count, h->asset->apk_offset + position);
        if (result != (ssize_t)count) { errno = EIO; return -1; }
        return result;
    }
    return ArchiveReadAt(h->archive, buffer, count, position);
}

// (phase3_vfs.c:413-438)
static VirtualHandle* AllocateHandleFor(VirtualArchive* archive, AssetEntry* asset) {
    std::lock_guard<std::mutex> lock(g_lock);
    for (size_t i = 0; i < kMaxHandles; ++i) {
        VirtualHandle* h = &g_handles[i];
        if (h->used) continue;
        int real_fd = dup(archive->apk_fd);
        if (real_fd < 0) return nullptr;
        if (++h->generation == 0) ++h->generation;
        h->used = true;
        h->vfd = VFD_BASE + (int)i;
        h->real_fd = real_fd;
        h->position = 0;
        h->archive = archive;
        h->asset = asset;
        h->flat = false;
        h->flat_offset = 0;
        h->flat_size = 0;
        h->opened_at = std::chrono::steady_clock::now();
        h->log_ops = 0;
        return h;
    }
    errno = EMFILE;
    static std::atomic<uint32_t> exhausted{0};
    const uint32_t k = exhausted.fetch_add(1, std::memory_order_relaxed) + 1;
    if (k == 1 || (k % 256) == 0) LogLiveHandlesLocked(k);
    if (k <= 8 || (k % 256) == 0)
        LOGE("VFS handle table exhausted: asset=%s capacity=%zu failure=%u",
             asset ? asset->name : "<null>", kMaxHandles, k);
    return nullptr;
}

// Whole-OBB handle: a flat byte window onto the OBB payload inside the APK.
static VirtualHandle* AllocateFlatHandle(VirtualArchive* archive, off64_t source_offset,
                                         off64_t size) {
    std::lock_guard<std::mutex> lock(g_lock);
    for (size_t i = 0; i < kMaxHandles; ++i) {
        VirtualHandle* h = &g_handles[i];
        if (h->used) continue;
        int real_fd = dup(archive->apk_fd);
        if (real_fd < 0) return nullptr;
        if (++h->generation == 0) ++h->generation;
        h->used = true;
        h->vfd = VFD_BASE + (int)i;
        h->real_fd = real_fd;
        h->position = 0;
        h->archive = archive;
        h->asset = nullptr;
        h->flat = true;
        h->flat_offset = source_offset;
        h->flat_size = size;
        h->opened_at = std::chrono::steady_clock::now();
        h->log_ops = 0;
        return h;
    }
    errno = EMFILE;
    static std::atomic<uint32_t> exhausted{0};
    const uint32_t k = exhausted.fetch_add(1, std::memory_order_relaxed) + 1;
    if (k == 1 || (k % 256) == 0) LogLiveHandlesLocked(k);
    if (k <= 8 || (k % 256) == 0)
        LOGE("VFS handle table exhausted: flat offset=%lld size=%lld capacity=%zu failure=%u",
             (long long)source_offset, (long long)size, kMaxHandles, k);
    return nullptr;
}

// (phase3_vfs.c:444-464)
static void ReleaseHandleLocked(VirtualHandle* h, uint64_t generation) {
    if (h && h->used && h->generation == generation) {
        static std::atomic<uint32_t> released{0};
        const uint32_t k = released.fetch_add(1, std::memory_order_relaxed) + 1;
        if (k <= 80 || (k % 256) == 0)
            LOGI("VFS handle released: vfd=%d flat=%d asset=%s release=%u",
                 h->vfd, h->flat ? 1 : 0,
                 h->asset ? h->asset->name : "<whole-obb>", k);
        close(h->real_fd);
        h->used = false;
        h->vfd = 0;
        h->real_fd = -1;
        h->position = 0;
        h->archive = nullptr;
        h->asset = nullptr;
        h->flat = false;
        h->flat_offset = 0;
        h->flat_size = 0;
        h->opened_at = {};
        h->log_ops = 0;
    }
}

static void ReleaseHandle(VirtualHandle* h, uint64_t generation) {
    if (!h) return;
    std::lock_guard<std::mutex> lock(g_lock);
    ReleaseHandleLocked(h, generation);
}

// (phase3_vfs.c:466-475) The original mutated nothing here; the entry lookup
// is const except that map_virtual_range wanted a mutable pointer. Under the
// bridge only Phase3VfsHookMmap reads through it, so const_cast is localized.
static AssetEntry* EntryForData(const VirtualArchive* archive, off64_t position) {
    for (auto& e : archive->entries)
        if (position >= e.data_offset && position < e.data_offset + e.size)
            return const_cast<AssetEntry*>(&e);
    return nullptr;
}

// Synthetic ZIP metadata byte (phase3_vfs.c:477-564), identical field layout.
static int MetadataByte(const VirtualArchive* archive, off64_t position, unsigned char* value) {
    for (auto& entry : archive->entries) {
        if (position >= entry.local_offset && position < entry.data_offset) {
            off64_t relative = position - entry.local_offset;
            unsigned char header[30] = {0};
            write_u32(header + 0, 0x04034b50u);
            write_u16(header + 4, 20);
            write_u32(header + 14, entry.crc32);
            write_u32(header + 18, (uint32_t)entry.size);
            write_u32(header + 22, (uint32_t)entry.size);
            write_u16(header + 26, entry.name_len);
            write_u16(header + 28, entry.extra_len);
            if (relative < 30)
                *value = header[relative];
            else if (relative < 30 + entry.name_len)
                *value = (unsigned char)entry.name[relative - 30];
            else
                *value = 0;
            return 1;
        }
    }

    if (position >= archive->central_offset &&
        position < archive->central_offset + archive->central_size) {
        off64_t central = archive->central_offset;
        for (auto& entry : archive->entries) {
            off64_t central_end = central + 46 + entry.name_len;
            if (position < central || position >= central_end) {
                central = central_end;
                continue;
            }
            off64_t relative = position - central;
            unsigned char header[46] = {0};
            write_u32(header + 0, 0x02014b50u);
            write_u16(header + 4, 20);
            write_u16(header + 6, 20);
            write_u32(header + 16, entry.crc32);
            write_u32(header + 20, (uint32_t)entry.size);
            write_u32(header + 24, (uint32_t)entry.size);
            write_u16(header + 28, entry.name_len);
            write_u32(header + 42, (uint32_t)entry.local_offset);
            if (relative < 46)
                *value = header[relative];
            else
                *value = (unsigned char)entry.name[relative - 46];
            return 1;
        }
    }

    if (position >= archive->central_offset + archive->central_size &&
        position < archive->size) {
        off64_t relative = position - (archive->central_offset + archive->central_size);
        unsigned char footer[22] = {0};
        write_u32(footer + 0, 0x06054b50u);
        write_u16(footer + 8, (uint16_t)archive->entries.size());
        write_u16(footer + 10, (uint16_t)archive->entries.size());
        write_u32(footer + 12, (uint32_t)archive->central_size);
        write_u32(footer + 16, (uint32_t)archive->central_offset);
        if (relative < (off64_t)sizeof(footer)) {
            *value = footer[relative];
            return 1;
        }
    }
    return 0;
}

// (phase3_vfs.c:566-602)
static ssize_t ArchiveReadAt(const VirtualArchive* archive, void* buffer, size_t count,
                             off64_t position) {
    if (position < 0 || position >= archive->size) return 0;
    if ((off64_t)count > archive->size - position)
        count = (size_t)(archive->size - position);
    size_t done = 0;
    unsigned char* out = (unsigned char*)buffer;
    while (done < count) {
        AssetEntry* entry = EntryForData(archive, position);
        if (entry) {
            size_t chunk = (size_t)(entry->data_offset + entry->size - position);
            if (chunk > count - done) chunk = count - done;
            ssize_t read_count =
                pread64(archive->apk_fd, out + done, chunk,
                        entry->apk_offset + position - entry->data_offset);
            if (read_count != (ssize_t)chunk) { errno = EIO; return -1; }
            done += chunk;
            position += chunk;
            continue;
        }
        unsigned char byte = 0;
        if (!MetadataByte(archive, position, &byte)) { errno = EIO; return -1; }
        out[done++] = byte;
        ++position;
    }
    return (ssize_t)done;
}

// (phase3_vfs.c:624-646)
static bool BuildArchiveLayout(VirtualArchive* archive) {
    off64_t layout = 0;
    for (auto& e : archive->entries) {
        e.local_offset = layout;
        e.extra_len = 0;
        e.data_offset = layout + 30 + e.name_len;
        layout = e.data_offset + e.size;
    }
    archive->central_offset = layout;
    archive->central_size = 0;
    for (auto& e : archive->entries) archive->central_size += 46 + e.name_len;
    archive->size = archive->central_offset + archive->central_size + 22;
    if (archive->size > (off64_t)0x7fffffff || archive->central_offset > (off64_t)0x7fffffff) {
        LOGE("phase3 VFS blocked: virtual archive exceeds 32-bit file offset limit: %lld",
             (long long)archive->size);
        return false;
    }
    return true;
}

// Parse an OBB container stored verbatim inside the APK: locate its EOCD and
// central directory, then fold every STORED member into the archive entry
// table with apk_offset pointing at the member payload inside the APK.
static bool ParseObbMembers(int fd, const ObbAsset& obb, VirtualArchive* archive,
                            const char* label) {
    if (!obb.present) {
        LOGE("phase3 VFS blocked: %s OBB asset missing from the APK", label);
        return false;
    }
    size_t tail_size = (size_t)(obb.size < 65557 ? obb.size : 65557);
    std::vector<unsigned char> tail(tail_size);
    if (pread64(fd, tail.data(), tail_size, obb.apk_offset + obb.size - (off64_t)tail_size) !=
        (ssize_t)tail_size) {
        LOGE("phase3 VFS blocked: cannot read %s OBB EOCD", label);
        return false;
    }
    ssize_t eocd = -1;
    for (ssize_t i = (ssize_t)tail_size - 22; i >= 0; --i) {
        if (read_u32(tail.data() + i) == 0x06054b50u) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) {
        LOGE("phase3 VFS blocked: %s OBB has no EOCD", label);
        return false;
    }
    uint16_t total_entries = read_u16(tail.data() + eocd + 10);
    uint32_t central_size = read_u32(tail.data() + eocd + 12);
    uint32_t central_offset = read_u32(tail.data() + eocd + 16);
    off64_t central_abs = obb.apk_offset + central_offset;
    if ((uint64_t)central_offset + central_size > (uint64_t)obb.size) {
        LOGE("phase3 VFS blocked: %s OBB central directory out of range", label);
        return false;
    }
    off64_t cursor = central_abs;
    for (uint16_t i = 0; i < total_entries; ++i) {
        unsigned char header[46];
        if (pread64(fd, header, sizeof(header), cursor) != (ssize_t)sizeof(header) ||
            read_u32(header) != 0x02014b50u) {
            LOGE("phase3 VFS blocked: %s OBB central record %u invalid", label, i);
            return false;
        }
        uint16_t name_len = read_u16(header + 28);
        uint16_t extra_len = read_u16(header + 30);
        uint16_t comment_len = read_u16(header + 32);
        uint16_t method = read_u16(header + 10);
        uint32_t compressed_size = read_u32(header + 20);
        uint32_t uncompressed_size = read_u32(header + 24);
        uint32_t local_offset = read_u32(header + 42);
        std::vector<char> name_buf(name_len + 1u);
        if (pread64(fd, name_buf.data(), name_len, cursor + 46) != name_len) {
            LOGE("phase3 VFS blocked: cannot read %s OBB member name", label);
            return false;
        }
        name_buf[name_len] = '\0';
        cursor += 46 + name_len + extra_len + comment_len;
        if (name_len && name_buf[name_len - 1] == '/') continue;  // directory
        if (method != 0 || compressed_size != uncompressed_size) {
            LOGE("phase3 VFS blocked: %s OBB member is compressed: %s", label, name_buf.data());
            return false;
        }
        unsigned char local[30];
        off64_t local_abs = obb.apk_offset + local_offset;
        if (pread64(fd, local, sizeof(local), local_abs) != (ssize_t)sizeof(local) ||
            read_u32(local) != 0x04034b50u) {
            LOGE("phase3 VFS blocked: %s OBB invalid local header: %s", label, name_buf.data());
            return false;
        }
        uint16_t local_name_len = read_u16(local + 26);
        uint16_t local_extra_len = read_u16(local + 28);
        if (archive->entries.size() >= kMaxAssets) {
            LOGE("phase3 VFS blocked: %s OBB member table is too large", label);
            return false;
        }
        archive->entries.resize(archive->entries.size() + 1);
        AssetEntry& e = archive->entries.back();
        memset(&e, 0, sizeof(e));
        const char* short_name = name_buf.data();
        strncpy(e.name, short_name, PATH_MAX - 1);
        e.name_len = (uint16_t)strlen(short_name);
        e.size = uncompressed_size;
        e.crc32 = read_u32(header + 16);
        e.apk_offset = obb.apk_offset + local_offset + 30 + local_name_len + local_extra_len;
        e.local_offset = 0;
        e.data_offset = 0;
    }
    LOGI("phase3 VFS: %s OBB parsed: %zu members, payload at +0x%llx size=%lld",
         label, archive->entries.size(), (long long)obb.apk_offset, (long long)obb.size);
    return true;
}

// data_4 is itself a stored ZIP nested inside each OBB. These legacy packs
// append opaque metadata after the ZIP EOCD, so identify the EOCD by requiring
// the central directory to end exactly at it instead of assuming it is at
// EOF. Index .sobfs payloads directly in the installed APK; patch wins and
// main supplies fallback members. All offsets are range-checked first.
static bool ParseNestedData4(int fd, const AssetEntry& pack, const char* label,
                             bool patch_source) {
    constexpr size_t kMaxNestedEntries = 4096;
    if (pack.size < 22 || pack.apk_offset < 0) {
        LOGE("phase3 VFS blocked: %s data_4 is too small", label);
        return false;
    }
    const size_t tail_size = (size_t)(pack.size < 65557 ? pack.size : 65557);
    std::vector<unsigned char> tail(tail_size);
    if (pread64(fd, tail.data(), tail_size,
                pack.apk_offset + pack.size - (off64_t)tail_size) !=
        (ssize_t)tail_size) {
        LOGE("phase3 VFS blocked: cannot read %s data_4 EOCD", label);
        return false;
    }

    ssize_t eocd = -1;
    uint64_t eocd_offset = 0;
    for (ssize_t i = (ssize_t)tail_size - 22; i >= 0; --i) {
        if (read_u32(tail.data() + i) != 0x06054b50u) continue;
        uint16_t comment_len = read_u16(tail.data() + i + 20);
        if ((size_t)i + 22u + comment_len > tail_size) continue;
        const uint16_t disk = read_u16(tail.data() + i + 4);
        const uint16_t central_disk = read_u16(tail.data() + i + 6);
        const uint16_t disk_entries = read_u16(tail.data() + i + 8);
        const uint16_t total_entries = read_u16(tail.data() + i + 10);
        const uint32_t central_size = read_u32(tail.data() + i + 12);
        const uint32_t central_offset = read_u32(tail.data() + i + 16);
        const uint64_t candidate_offset = (uint64_t)pack.size - tail_size + (size_t)i;
        if (disk != 0 || central_disk != 0 || disk_entries != total_entries ||
            total_entries == 0xffffu ||
            (uint64_t)central_offset + central_size != candidate_offset)
            continue;
        eocd = i;
        eocd_offset = candidate_offset;
        break;
    }
    if (eocd < 0) {
        LOGE("phase3 VFS blocked: %s data_4 has no valid EOCD", label);
        return false;
    }

    const uint16_t disk = read_u16(tail.data() + eocd + 4);
    const uint16_t central_disk = read_u16(tail.data() + eocd + 6);
    const uint16_t disk_entries = read_u16(tail.data() + eocd + 8);
    const uint16_t total_entries = read_u16(tail.data() + eocd + 10);
    const uint32_t central_size = read_u32(tail.data() + eocd + 12);
    const uint32_t central_offset = read_u32(tail.data() + eocd + 16);
    if (disk != 0 || central_disk != 0 || disk_entries != total_entries ||
        total_entries == 0xffffu ||
        (uint64_t)central_offset + central_size != eocd_offset) {
        LOGE("phase3 VFS blocked: %s data_4 has unsupported ZIP directory", label);
        return false;
    }

    const off64_t central_end = (off64_t)central_offset + central_size;
    off64_t cursor = pack.apk_offset + central_offset;
    const off64_t absolute_central_end = pack.apk_offset + central_end;
    size_t added = 0;
    size_t duplicates = 0;
    for (uint16_t i = 0; i < total_entries; ++i) {
        unsigned char header[46];
        if (cursor < pack.apk_offset || cursor + (off64_t)sizeof(header) > absolute_central_end ||
            pread64(fd, header, sizeof(header), cursor) != (ssize_t)sizeof(header) ||
            read_u32(header) != 0x02014b50u) {
            LOGE("phase3 VFS blocked: %s data_4 central entry %u invalid", label, i);
            return false;
        }
        const uint16_t flags = read_u16(header + 8);
        const uint16_t method = read_u16(header + 10);
        const uint16_t name_len = read_u16(header + 28);
        const uint16_t extra_len = read_u16(header + 30);
        const uint16_t comment_len = read_u16(header + 32);
        const uint32_t compressed_size = read_u32(header + 20);
        const uint32_t uncompressed_size = read_u32(header + 24);
        const uint32_t local_offset = read_u32(header + 42);
        const uint64_t record_size = 46ull + name_len + extra_len + comment_len;
        if (name_len == 0 || cursor + (off64_t)record_size > absolute_central_end) {
            LOGE("phase3 VFS blocked: %s data_4 central record out of range", label);
            return false;
        }

        std::vector<char> full_name((size_t)name_len + 1u);
        if (pread64(fd, full_name.data(), name_len, cursor + 46) != name_len) {
            LOGE("phase3 VFS blocked: cannot read %s data_4 member name", label);
            return false;
        }
        full_name[name_len] = '\0';
        cursor += (off64_t)record_size;
        if (full_name[name_len - 1] == '/') continue;

        const char* base_name = strrchr(full_name.data(), '/');
        base_name = base_name ? base_name + 1 : full_name.data();
        const size_t base_len = strlen(base_name);
        if (base_len < 6 || strcmp(base_name + base_len - 6, ".sobfs") != 0)
            continue;
        if (memchr(full_name.data(), '\0', name_len) != nullptr ||
            (flags & 1u) != 0 || method != 0 || compressed_size != uncompressed_size) {
            LOGE("phase3 VFS blocked: unsupported %s data_4 member %s", label,
                 full_name.data());
            return false;
        }

        const uint64_t local_header_offset = local_offset;
        if (local_header_offset + 30ull > (uint64_t)pack.size) {
            LOGE("phase3 VFS blocked: %s data_4 local header out of range", label);
            return false;
        }
        unsigned char local[30];
        const off64_t local_abs = pack.apk_offset + (off64_t)local_offset;
        if (pread64(fd, local, sizeof(local), local_abs) != (ssize_t)sizeof(local) ||
            read_u32(local) != 0x04034b50u) {
            LOGE("phase3 VFS blocked: %s data_4 local header invalid: %s", label,
                 full_name.data());
            return false;
        }
        const uint16_t local_name_len = read_u16(local + 26);
        const uint16_t local_extra_len = read_u16(local + 28);
        const uint64_t payload_rel = local_header_offset + 30ull + local_name_len + local_extra_len;
        if (local_name_len != name_len || payload_rel + uncompressed_size > (uint64_t)pack.size) {
            LOGE("phase3 VFS blocked: %s data_4 payload out of range: %s", label,
                 full_name.data());
            return false;
        }
        std::vector<char> local_name((size_t)local_name_len + 1u);
        if (pread64(fd, local_name.data(), local_name_len, local_abs + 30) != local_name_len ||
            memcmp(local_name.data(), full_name.data(), name_len) != 0) {
            LOGE("phase3 VFS blocked: %s data_4 local/central name mismatch", label);
            return false;
        }

        bool already_indexed = false;
        for (const auto& e : g_pack_assets) {
            if (strcmp(e.name, base_name) == 0) {
                already_indexed = true;
                break;
            }
        }
        if (already_indexed) {
            ++duplicates;
            continue;
        }
        if (g_pack_assets.size() >= kMaxNestedEntries || base_len >= PATH_MAX) {
            LOGE("phase3 VFS blocked: nested data_4 asset table limit exceeded");
            return false;
        }

        g_pack_assets.emplace_back();
        AssetEntry& entry = g_pack_assets.back();
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.name, base_name, base_len + 1);
        entry.name_len = (uint16_t)base_len;
        entry.apk_offset = pack.apk_offset + (off64_t)payload_rel;
        entry.size = uncompressed_size;
        entry.crc32 = read_u32(header + 16);
        entry.patch_source = patch_source;
        ++added;
    }
    if (cursor != absolute_central_end) {
        LOGE("phase3 VFS blocked: %s data_4 directory length mismatch", label);
        return false;
    }
    const uint16_t eocd_comment_size = read_u16(tail.data() + eocd + 20);
    const uint64_t trailer_size = (uint64_t)pack.size - eocd_offset - 22u - eocd_comment_size;
    LOGI("phase3 VFS: nested %s data_4 indexed %zu .sobfs assets (%zu overlay duplicates, %llu trailer bytes)",
         label, added, duplicates, (unsigned long long)trailer_size);
    return true;
}

// (phase3_vfs.c:685-823) Parse APK central directory into the asset table.
static bool ParseApkAssets(const char* obb_dir) {
    // 2026-09-20: the eternal loader loop re-invokes this every pass; the
    // re-open + pread of the 2 GB APK started failing mid-boot ("cannot read
    // APK EOCD"), which starves guest thread #1 (the OBB indexer) and wedges
    // iFPS::Init forever. The archive is fully cached after the first parse
    // -- serve it and never re-open.
    static bool s_apk_parsed = false;
    if (s_apk_parsed && g_archive.apk_fd >= 0) return true;
    int fd = open(g_apk_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGE("phase3 VFS blocked: cannot open base APK '%s': %s", g_apk_path.c_str(),
             strerror(errno));
        return false;
    }
    int main_fd = fd;
    int patch_fd = fd;
    auto fail = [&]() -> bool {
        if (main_fd >= 0 && main_fd != fd) close(main_fd);
        if (patch_fd >= 0 && patch_fd != fd && patch_fd != main_fd) close(patch_fd);
        if (fd >= 0) close(fd);
        g_archive = VirtualArchive{};
        g_patch_archive = VirtualArchive{};
        g_pack_assets.clear();
        g_main_obb_asset = ObbAsset{};
        g_patch_obb_asset = ObbAsset{};
        return false;
    };
    g_main_obb_asset = ObbAsset{};
    g_patch_obb_asset = ObbAsset{};
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 22) {
        LOGE("phase3 VFS blocked: cannot stat base APK: %s", strerror(errno));
        return fail();
    }
    size_t tail_size = st.st_size < 65557 ? (size_t)st.st_size : 65557u;
    std::vector<unsigned char> tail(tail_size);
    if (pread64(fd, tail.data(), tail_size, (off64_t)st.st_size - tail_size) !=
        (ssize_t)tail_size) {
        LOGE("phase3 VFS blocked: cannot read APK EOCD (errno=%d size=%lld off=%lld)",
             errno, (long long)st.st_size,
             (long long)(st.st_size - (off64_t)tail_size));
        return fail();
    }
    ssize_t eocd = -1;
    for (ssize_t i = (ssize_t)tail_size - 22; i >= 0; --i) {
        if (read_u32(tail.data() + i) == 0x06054b50u &&
            read_u16(tail.data() + i + 20) == tail_size - (size_t)i - 22u) {
            eocd = i;
            break;
        }
    }
    uint16_t total_entries = eocd >= 0 ? read_u16(tail.data() + eocd + 10) : 0xffffu;
    uint32_t central_size = eocd >= 0 ? read_u32(tail.data() + eocd + 12) : 0;
    uint32_t central_offset = eocd >= 0 ? read_u32(tail.data() + eocd + 16) : 0;
    const uint64_t central_end = (uint64_t)central_offset + central_size;
    const uint64_t eocd_absolute = eocd >= 0
        ? (uint64_t)st.st_size - tail_size + (size_t)eocd : 0;
    if (eocd < 0 || total_entries == 0xffffu ||
        central_size == UINT32_MAX || central_offset == UINT32_MAX ||
        read_u16(tail.data() + eocd + 4) != 0 ||
        read_u16(tail.data() + eocd + 6) != 0 ||
        read_u16(tail.data() + eocd + 8) != total_entries ||
        central_end > eocd_absolute) {
        LOGE("phase3 VFS blocked: APK is missing a supported non-ZIP64 EOCD");
        return fail();
    }

    g_archive = VirtualArchive{};
    g_patch_archive = VirtualArchive{};
    g_archive.apk_fd = fd;
    g_archive.page_size = sysconf(_SC_PAGESIZE);
    if (g_archive.page_size <= 0) g_archive.page_size = 4096;
    g_patch_archive.apk_fd = fd;
    g_patch_archive.page_size = g_archive.page_size;

    constexpr const char* kEmbeddedMain = "assets/obb/main.12222.obb";
    constexpr const char* kEmbeddedPatch = "assets/obb/patch.12222.obb";
    constexpr off64_t kMainSize = 2052015324;
    constexpr off64_t kPatchSize = 15093838;
    uint64_t cursor = central_offset;
    for (uint16_t i = 0; i < total_entries; ++i) {
        unsigned char header[46];
        if (cursor + sizeof(header) > central_end ||
            pread64(fd, header, sizeof(header), (off64_t)cursor) != (ssize_t)sizeof(header) ||
            read_u32(header) != 0x02014b50u) {
            LOGE("phase3 VFS blocked: invalid APK central-directory record %u", i);
            return fail();
        }
        uint16_t name_len = read_u16(header + 28);
        uint16_t extra_len = read_u16(header + 30);
        uint16_t comment_len = read_u16(header + 32);
        const uint64_t record_size = 46ull + name_len + extra_len + comment_len;
        if (name_len == 0 || cursor + record_size > central_end) {
            LOGE("phase3 VFS blocked: APK central record %u exceeds directory", i);
            return fail();
        }
        uint16_t method = read_u16(header + 10);
        uint32_t compressed_size = read_u32(header + 20);
        uint32_t uncompressed_size = read_u32(header + 24);
        uint32_t local_offset = read_u32(header + 42);
        std::vector<char> name_buf(name_len + 1u);
        if (pread64(fd, name_buf.data(), name_len, (off64_t)cursor + 46) != name_len ||
            memchr(name_buf.data(), '\0', name_len) != nullptr) {
            LOGE("phase3 VFS blocked: cannot read APK asset name");
            return fail();
        }
        name_buf[name_len] = '\0';
        cursor += record_size;

        ObbAsset* target = nullptr;
        off64_t expected_size = 0;
        if (strcmp(name_buf.data(), kEmbeddedMain) == 0) {
            target = &g_main_obb_asset;
            expected_size = kMainSize;
        } else if (strcmp(name_buf.data(), kEmbeddedPatch) == 0) {
            target = &g_patch_obb_asset;
            expected_size = kPatchSize;
        }
        if (!target) continue;
        const uint16_t flags = read_u16(header + 8);
        if (target->present || (flags & (1u | 8u)) != 0 || method != 0 ||
            compressed_size != uncompressed_size ||
            uncompressed_size != expected_size || read_u16(header + 34) != 0 ||
            (uint64_t)local_offset + 30u > central_offset) {
            LOGE("phase3 VFS blocked: duplicate or invalid embedded OBB %s", name_buf.data());
            return fail();
        }
        unsigned char local[30];
        if (pread64(fd, local, sizeof(local), local_offset) != (ssize_t)sizeof(local) ||
            read_u32(local) != 0x04034b50u) {
            LOGE("phase3 VFS blocked: invalid APK local header: %s", name_buf.data());
            return fail();
        }
        uint16_t local_name_len = read_u16(local + 26);
        uint16_t local_extra_len = read_u16(local + 28);
        const uint64_t payload = (uint64_t)local_offset + 30u + local_name_len +
                                 local_extra_len;
        if (read_u16(local + 6) != flags || read_u16(local + 8) != method ||
            read_u32(local + 14) != read_u32(header + 16) ||
            read_u32(local + 18) != compressed_size ||
            read_u32(local + 22) != uncompressed_size ||
            local_name_len != name_len || payload + uncompressed_size > central_offset) {
            LOGE("phase3 VFS blocked: embedded OBB local/central mismatch: %s",
                 name_buf.data());
            return fail();
        }
        std::vector<char> local_name(local_name_len);
        if (pread64(fd, local_name.data(), local_name_len,
                    (off64_t)local_offset + 30) != local_name_len ||
            memcmp(local_name.data(), name_buf.data(), name_len) != 0) {
            LOGE("phase3 VFS blocked: embedded OBB local name mismatch: %s",
                 name_buf.data());
            return fail();
        }
        target->present = true;
        target->apk_offset = (off64_t)payload;
        target->size = uncompressed_size;
    }
    if (cursor != central_end) {
        LOGE("phase3 VFS blocked: APK central-directory length mismatch");
        return fail();
    }

    if (!g_main_obb_asset.present || !g_patch_obb_asset.present) {
        LOGI("phase3 VFS: embedded OBB set incomplete (main=%d patch=%d); checking external pair",
             (int)g_main_obb_asset.present, (int)g_patch_obb_asset.present);
        if (!obb_dir || !*obb_dir) {
            LOGE("phase3 VFS blocked: no embedded OBB set and getObbDir is unavailable");
            return fail();
        }
        constexpr const char* kMainName =
            "main.1100.com.gameloft.android.ANMP.GloftM4HM.obb";
        constexpr const char* kPatchName =
            "patch.12222.com.gameloft.android.ANMP.GloftM4HM.obb";
        constexpr const char* kMainSha =
            "c47c0fff7bfb56f158fa8bd2ef2c6b47caac30c6e48f0cbc91c4ee40931fcd1c";
        constexpr const char* kPatchSha =
            "14f53062d1d6a5ad7b02aff603b9b6de09bcac8945fd135301b7f8bc2f0dd670";
        const std::string main_path = std::string(obb_dir) + "/" + kMainName;
        const std::string patch_path = std::string(obb_dir) + "/" + kPatchName;
        auto open_verified = [&](const std::string& path, off64_t expected_size,
                                 const char* expected_hash) -> int {
            const int source = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (source < 0) {
                LOGE("phase3 VFS blocked: external OBB unavailable: %s: %s",
                     path.c_str(), strerror(errno));
                return -1;
            }
            struct stat file_st;
            if (fstat(source, &file_st) != 0 || !S_ISREG(file_st.st_mode) ||
                file_st.st_size != expected_size) {
                LOGE("phase3 VFS blocked: external OBB size/type mismatch: %s", path.c_str());
                close(source);
                return -1;
            }
            std::string actual;
            if (!Sha256FileEquals(source, expected_size, expected_hash, &actual)) {
                LOGE("phase3 VFS blocked: external OBB SHA-256 mismatch/read failure: %s actual=%s",
                     path.c_str(), actual.empty() ? "<read-failed>" : actual.c_str());
                close(source);
                return -1;
            }
            LOGI("phase3 VFS: verified external OBB %s size=%lld sha256=%s",
                 path.c_str(), (long long)expected_size, actual.c_str());
            return source;
        };
        main_fd = open_verified(main_path, kMainSize, kMainSha);
        if (main_fd < 0) return fail();
        patch_fd = open_verified(patch_path, kPatchSize, kPatchSha);
        if (patch_fd < 0) return fail();
        close(fd);
        fd = -1;
        g_main_obb_asset = {true, 0, kMainSize};
        g_patch_obb_asset = {true, 0, kPatchSize};
        LOGI("phase3 VFS: source=external verified main+patch; embedded entries ignored");
    } else {
        LOGI("phase3 VFS: source=embedded complete main+patch; external OBBs ignored");
    }
    g_archive.apk_fd = main_fd;
    g_patch_archive.apk_fd = patch_fd;

    // Fold the main OBB members into the archive table: the game's files/
    // opens (data_1..6, briefings, ...) are served straight from the OBB
    // container stored inside the APK.
    if (!ParseObbMembers(main_fd, g_main_obb_asset, &g_archive, "main")) return fail();
    g_pack_assets.clear();
    if (!ParseObbMembers(patch_fd, g_patch_obb_asset, &g_patch_archive, "patch-index"))
        return fail();
    auto find_member = [](const VirtualArchive& archive, const char* name) -> const AssetEntry* {
        for (const auto& entry : archive.entries)
            if (strcmp(entry.name, name) == 0) return &entry;
        return nullptr;
    };
    const AssetEntry* patch_data4 = find_member(g_patch_archive, "data_4");
    const AssetEntry* main_data4 = find_member(g_archive, "data_4");
    const char* required_patch_packs[] = {"data_2", "data_4", "data_5", "data_6"};
    bool patch_overlay_complete = true;
    for (const char* name : required_patch_packs)
        patch_overlay_complete = patch_overlay_complete && find_member(g_patch_archive, name);
    if (!patch_overlay_complete || !patch_data4 || !main_data4 ||
        !ParseNestedData4(patch_fd, *patch_data4, "patch", true) ||
        !ParseNestedData4(main_fd, *main_data4, "main", false)) {
        LOGE("phase3 VFS blocked: patch data-pack overlay or nested data_4 index is incomplete");
        return fail();
    }
    for (const char* name : required_patch_packs) {
        const AssetEntry* patch = find_member(g_patch_archive, name);
        const AssetEntry* main = find_member(g_archive, name);
        if (!main || patch->size == 0) {
            LOGE("phase3 VFS blocked: invalid patch/base data-pack pair: %s", name);
            return fail();
        }
        LOGI("phase3 VFS: patch override %s patch_size=%lld main_size=%lld", name,
             (long long)patch->size, (long long)main->size);
    }
    // The offline package has no server-delivered multiplayer manifests. A
    // four-byte zero count is the valid empty-list encoding consumed by the
    // game's DataStream array reader; do not emulate arbitrary zero pages.
    // Replace any stale packaged placeholders instead of inserting duplicate
    // basenames into the virtual ZIP. This also makes the bridge robust to
    // APKs produced by earlier builds that appended 4-KiB zero-page stubs.
    for (const char* mp_name : {"mpgamemodes_array", "multiplayerevents_array",
                                "mpattachments_array"}) {
        AssetEntry entry{};
        strncpy(entry.name, mp_name, PATH_MAX - 1);
        entry.name_len = (uint16_t)strlen(mp_name);
        entry.host_data = g_empty_array;
        entry.size = sizeof(g_empty_array);
        entry.apk_offset = -1;
        entry.crc32 = Crc32(entry.host_data, (size_t)entry.size);
        auto existing = std::find_if(g_archive.entries.begin(), g_archive.entries.end(),
                                     [mp_name](const AssetEntry& candidate) {
                                         return strcmp(candidate.name, mp_name) == 0;
                                     });
        if (existing != g_archive.entries.end()) {
            *existing = entry;
        } else {
            if (g_archive.entries.size() >= kMaxAssets) {
                LOGE("phase3 VFS blocked: no room for offline MP metadata");
                return fail();
            }
            g_archive.entries.push_back(entry);
        }
    }

    // Keep the complete, authoritative Res.array and Game.graphml inside the
    // original patch/main data_5 packs. FileStream hashes their logical
    // data/... paths and its native ZIP resolver selects the matching .obfs
    // member. Do not shadow that route with a truncated host manifest or a
    // fabricated one-state graph: runtime probes observed the real 13-state
    // graph and subsequent native sub-automata loads from the OBBs.

    LOGI("phase3 VFS: offline archive assembled with %zu members",
         g_archive.entries.size());
    std::sort(g_archive.entries.begin(), g_archive.entries.end(),
              [](const AssetEntry& a, const AssetEntry& b) {
                  return strcmp(a.name, b.name) < 0;
              });
    for (size_t i = 1; i < g_archive.entries.size(); ++i) {
        if (strcmp(g_archive.entries[i - 1].name, g_archive.entries[i].name) == 0) {
            LOGE("phase3 VFS blocked: duplicate OBB member name: %s",
                 g_archive.entries[i].name);
            return fail();
        }
    }
    if (!BuildArchiveLayout(&g_archive)) {
        return fail();
    }
    // The selected pair stays open as the archive read source.
    s_apk_parsed = true;
    return true;
}

// --- virtual stdio stream (phase3_vfs.c:825-895) ---
// Host-side funopen with host callbacks: no JIT re-entry needed here.
struct VirtualStreamContext {
    VirtualHandle* handle;
    uint64_t generation;
};

// The caller must hold g_lock. The context pins the slot identity, not the
// slot itself: if a guest fd is closed and its slot reused, stale FILE callbacks
// must fail rather than operate on or release the new file.
static FILE* OpenVirtualStreamLocked(VirtualHandle* handle) {
    if (!handle || !handle->used) return nullptr;
    auto* context = new (std::nothrow) VirtualStreamContext{handle, handle->generation};
    if (!context) {
        ReleaseHandleLocked(handle, handle->generation);
        return nullptr;
    }
    FILE* stream = funopen(
        context,
        [](void* c, char* buf, int n) -> int {
            auto* context = static_cast<VirtualStreamContext*>(c);
            if (n <= 0) return 0;
            std::lock_guard<std::mutex> lock(g_lock);
            VirtualHandle* h = context->handle;
            if (!h->used || h->generation != context->generation) {
                errno = EBADF;
                return -1;
            }
            off64_t start = h->position;
            ssize_t result = HandleReadAt(h, buf, (size_t)n, start);
            if (result > 0) h->position += result;
            if (h->log_ops < 16) {
                LOGI("virtual read: vfd=%d pos=%lld count=%d result=%d", h->vfd,
                     (long long)start, n, (int)result);
                if (result < 0)
                    LOGE("virtual read FAIL: vfd=%d errno=%d asset=%d entries=%zu archive_size=%lld apk_fd=%d",
                         h->vfd, errno, h->asset != nullptr, h->archive->entries.size(),
                         (long long)h->archive->size, h->archive->apk_fd);
                ++h->log_ops;
            }
            return result < 0 ? -1 : (int)result;
        },
        nullptr,
        [](void* c, fpos_t off, int whence) -> fpos_t {
            auto* context = static_cast<VirtualStreamContext*>(c);
            std::lock_guard<std::mutex> lock(g_lock);
            VirtualHandle* h = context->handle;
            if (!h->used || h->generation != context->generation) {
                errno = EBADF;
                return (fpos_t)-1;
            }
            off64_t base = 0;
            if (whence == SEEK_SET)
                base = 0;
            else if (whence == SEEK_CUR)
                base = h->position;
            else if (whence == SEEK_END)
                base = HandleSize(h);
            else {
                errno = EINVAL;
                return (fpos_t)-1;
            }
            off64_t next = base + (off64_t)off;
            if (next < 0 || next > HandleSize(h)) {
                errno = EINVAL;
                return (fpos_t)-1;
            }
            h->position = next;
            if (h->log_ops < 16) {
                LOGI("virtual seek: vfd=%d whence=%d offset=%lld -> %lld", h->vfd, whence,
                     (long long)off, (long long)next);
                ++h->log_ops;
            }
            return (fpos_t)next;
        },
        [](void* c) -> int {
            auto* context = static_cast<VirtualStreamContext*>(c);
            ReleaseHandle(context->handle, context->generation);
            delete context;
            return 0;
        });
    if (!stream) {
        ReleaseHandleLocked(handle, context->generation);
        delete context;
        return nullptr;
    }
    return stream;
}

// --- hook entry points used by thunks_libc ---

FILE* Phase3VfsHookFopen(const char* path, const char* mode, bool* handled) {
    *handled = false;
    if (g_archive.entries.empty() || !mode || mode[0] != 'r' || strchr(mode, '+'))
        return nullptr;
    AssetRef asset = AssetForPath(path);
    if (asset.entry) {
        *handled = true;
        VirtualHandle* handle = AllocateHandleFor(asset.archive, asset.entry);
        FILE* stream = nullptr;
        if (handle) {
            std::lock_guard<std::mutex> lock(g_lock);
            stream = OpenVirtualStreamLocked(handle);
        }
        if (stream)
            LOGI("fopen: OBB member opened '%s' -> member=%s fd=%d vfd=%d size=%lld", path,
                 asset.entry->name, handle->real_fd, handle->vfd,
                 (long long)asset.entry->size);
        return stream;
    }
    // The OBB locations are served from the containers stored inside the APK
    // (2026-09-17 directive): the guest zip-mounts the real OBB bytes.
    const ObbAsset* obb = IsMainObbLocation(path) ? &g_main_obb_asset
                        : IsPatchObbLocation(path) ? &g_patch_obb_asset
                        : nullptr;
    if (!obb || !obb->present) return nullptr;
    *handled = true;
    VirtualArchive* archive = IsPatchObbLocation(path) ? &g_patch_archive : &g_archive;
    VirtualHandle* handle = AllocateFlatHandle(archive, obb->apk_offset, obb->size);
    FILE* stream = nullptr;
    if (handle) {
        std::lock_guard<std::mutex> lock(g_lock);
        stream = OpenVirtualStreamLocked(handle);
    }
    if (stream)
        LOGI("fopen: APK OBB stream opened '%s' -> %s fd=%d vfd=%d size=%lld",
             path, IsPatchObbLocation(path) ? "patch.12222.obb" : "main.12222.obb",
             handle->real_fd, handle->vfd, (long long)obb->size);
    return stream;
}

// Returns the virtual fd, or -1 with *handled=false when the path is not ours.
int Phase3VfsHookOpen(const char* path, int flags, bool* handled) {
    *handled = false;
    if (g_archive.entries.empty() || (flags & O_ACCMODE) != O_RDONLY) return -1;
    AssetRef asset = AssetForPath(path);
    if (asset.entry) {
        *handled = true;
        VirtualHandle* handle = AllocateHandleFor(asset.archive, asset.entry);
        if (!handle) return -1;
        LOGI("open: OBB member opened '%s' -> member=%s fd=%d vfd=%d size=%lld", path,
             asset.entry->name, handle->real_fd, handle->vfd,
             (long long)asset.entry->size);
        return handle->vfd;
    }
    const ObbAsset* obb = IsMainObbLocation(path) ? &g_main_obb_asset
                        : IsPatchObbLocation(path) ? &g_patch_obb_asset
                        : nullptr;
    if (obb && obb->present) {
        *handled = true;
        VirtualArchive* archive = IsPatchObbLocation(path) ? &g_patch_archive : &g_archive;
        VirtualHandle* handle = AllocateFlatHandle(archive, obb->apk_offset, obb->size);
        if (!handle) return -1;
        LOGI("open: APK OBB stream opened '%s' -> %s fd=%d vfd=%d size=%lld",
             path, IsPatchObbLocation(path) ? "patch.12222.obb" : "main.12222.obb",
             handle->real_fd, handle->vfd, (long long)obb->size);
        return handle->vfd;
    }
    return -1;
}

// (phase3_vfs.c:1125-1131)
int Phase3VfsHookFdopen(int fd, FILE** out) {
    std::lock_guard<std::mutex> lock(g_lock);
    VirtualHandle* handle = HandleForFdLocked(fd);
    if (!handle) return -1;
    FILE* stream = OpenVirtualStreamLocked(handle);
    if (!stream) return -1;
    *out = stream;
    return 0;
}

// (phase3_vfs.c:1133-1140)
int Phase3VfsHookClose(int fd) {
    std::lock_guard<std::mutex> lock(g_lock);
    VirtualHandle* handle = HandleForFdLocked(fd);
    if (!handle) return -1;
    ReleaseHandleLocked(handle, handle->generation);
    return 0;
}

// (phase3_vfs.c:1142-1160)
ssize_t Phase3VfsHookRead(int fd, void* buffer, size_t count) {
    std::lock_guard<std::mutex> lock(g_lock);
    VirtualHandle* handle = HandleForFdLocked(fd);
    if (!handle) return -1;
    ssize_t result = HandleReadAt(handle, buffer, count, handle->position);
    if (result > 0) handle->position += result;
    return result;
}

ssize_t Phase3VfsHookPread(int fd, void* buffer, size_t count, off64_t offset) {
    std::lock_guard<std::mutex> lock(g_lock);
    VirtualHandle* handle = HandleForFdLocked(fd);
    if (!handle) return -1;
    return HandleReadAt(handle, buffer, count, offset);
}

// (phase3_vfs.c:1162-1177)
off64_t Phase3VfsHookLseek(int fd, off64_t offset, int whence) {
    std::lock_guard<std::mutex> lock(g_lock);
    VirtualHandle* handle = HandleForFdLocked(fd);
    if (!handle) return -1;
    off64_t base = whence == SEEK_SET   ? 0
                   : whence == SEEK_CUR ? handle->position
                   : whence == SEEK_END ? HandleSize(handle)
                                       : -1;
    off64_t next = base < 0 ? -1 : base + offset;
    if (next < 0 || next > HandleSize(handle)) next = -1;
    if (next >= 0) handle->position = next;
    if (next < 0) errno = EINVAL;
    return next;
}

// (phase3_vfs.c:897-903)
void Phase3VfsFillStat(off64_t size, struct stat* st) {
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_size = (off_t)size;
    st->st_blksize = 4096;
}

// (phase3_vfs.c:1179-1194)
int Phase3VfsHookFstat(int fd, struct stat* st) {
    std::lock_guard<std::mutex> lock(g_lock);
    VirtualHandle* handle = HandleForFdLocked(fd);
    if (!handle) return -1;
    if (!st) {
        errno = EFAULT;
        return -1;
    }
    Phase3VfsFillStat(HandleSize(handle), st);
    if (handle->log_ops < 16) {
        LOGI("virtual fstat: vfd=%d size=%lld", handle->vfd, (long long)st->st_size);
        ++handle->log_ops;
    }
    return 0;
}

// (phase3_vfs.c:1196-1220)
int Phase3VfsHookStat(const char* path, struct stat* st) {
    if (g_archive.entries.empty()) return -1;
    AssetRef asset = AssetForPath(path);
    if (asset.entry) {
        if (!st) {
            errno = EFAULT;
            return -1;
        }
        Phase3VfsFillStat(asset.entry->size, st);
        return 0;
    }
    const ObbAsset* obb = IsMainObbLocation(path) ? &g_main_obb_asset
                        : IsPatchObbLocation(path) ? &g_patch_obb_asset
                        : nullptr;
    if (obb && obb->present) {
        if (!st) {
            errno = EFAULT;
            return -1;
        }
        Phase3VfsFillStat(obb->size, st);
        return 0;
    }
    return -1;
}

// --- mmap hook (phase3_vfs.c:972-1053) ---
// A virtual fd is a file view (either a whole OBB or one OBB member), not the
// synthetic archive used for indexing. Materialize that exact file range in
// guest memory; the thunk cache keeps repeated mappings from growing the arena.
int Phase3VfsHookMmap(DynarmicHost& host, int fd, size_t length, off64_t offset,
                      uint32_t* out_va) {
    VirtualHandle snapshot;
    {
        std::lock_guard<std::mutex> lock(g_lock);
        VirtualHandle* live = HandleForFdLocked(fd);
        if (!live) return -1;
        snapshot = *live;
        snapshot.real_fd = dup(live->real_fd);
        if (snapshot.real_fd < 0) return -1;
    }
    struct FdGuard {
        int fd;
        ~FdGuard() { if (fd >= 0) ::close(fd); }
    } fd_guard{snapshot.real_fd};
    VirtualHandle* handle = &snapshot;
    VirtualArchive* archive = handle->archive;
    const long page_size = archive->page_size;
    const off64_t file_size = HandleSize(handle);
    if (page_size <= 0 || (page_size & (page_size - 1)) != 0 || file_size < 0) {
        errno = EINVAL;
        return -1;
    }
    if (offset < 0 || length == 0 ||
        (uint64_t)length > UINT64_MAX - (uint64_t)(offset & ((off64_t)page_size - 1))) {
        errno = EINVAL;
        return -1;
    }
    const off64_t aligned = offset & ~((off64_t)page_size - 1);
    const size_t bias = (size_t)(offset - aligned);
    const uint64_t covered = (uint64_t)bias + (uint64_t)length;
    if (covered > UINT64_MAX - (uint64_t)(page_size - 1)) {
        errno = EINVAL;
        return -1;
    }
    const uint64_t span64 =
        (covered + (uint64_t)page_size - 1u) & ~((uint64_t)page_size - 1u);
    if (span64 == 0 || span64 > 0x40000000ull || aligned >= file_size ||
        (uint64_t)aligned + span64 > (uint64_t)file_size + (uint64_t)page_size) {
        errno = EINVAL;
        return -1;
    }
    const size_t span = (size_t)span64;

    uint32_t va = host.GuestAllocMapping(span, (size_t)page_size);
    if (!va) {
        LOGE("phase3 mmap: no guest arena for %zu bytes", span);
        return -1;
    }
    unsigned char* dst = host.GetGuestMemoryBase() + va;
    size_t done = 0;
    while (done < span) {
        size_t chunk = span - done;
        if (chunk > (size_t)1 << 20) chunk = (size_t)1 << 20;
        off64_t pos = aligned + (off64_t)done;
        if (pos >= file_size) {
            // mmap exposes zero-filled bytes through the final partial page.
            memset(dst + done, 0, chunk);
            done += chunk;
            continue;
        }
        const size_t available = (size_t)(file_size - pos);
        const size_t read_size = std::min(chunk, available);
        ssize_t n = HandleReadAt(handle, dst + done, read_size, pos);
        if (n != (ssize_t)read_size) {
            LOGE("phase3 mmap: read failed at %lld", (long long)pos);
            errno = EIO;
            return -1;
        }
        if (read_size < chunk) memset(dst + done + read_size, 0, chunk - read_size);
        done += chunk;
    }
    LOGI("mmap: fd=%d len=%zu off=%lld -> guest 0x%08X (virtual=%d)", handle->real_fd,
         length, (long long)offset, va + (uint32_t)bias, handle->vfd);
    *out_va = va + (uint32_t)bias;
    return 0;
}

// --- find_apk_path (phase3_vfs.c:307-351) ---
static bool CopyMapPath(const char* line, const char* needle, std::string* out) {
    const char* hit = strstr(line, needle);
    if (!hit) return false;
    const char* start = hit;
    while (start > line && start[-1] != ' ') --start;
    const char* end = hit + strlen(needle);
    while (*end && *end != ' ' && *end != '\r' && *end != '\n') ++end;
    size_t length = (size_t)(end - start);
    if (length == 0 || length >= PATH_MAX) return false;
    out->assign(start, length);
    return true;
}

static bool FindApkPath() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    char line[4096];
    std::string fallback;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "/base.apk") && CopyMapPath(line, "/base.apk", &g_apk_path)) {
            fclose(maps);
            return true;
        }
        if (fallback.empty() && strstr(line, ".apk"))
            CopyMapPath(line, ".apk", &fallback);
    }
    fclose(maps);
    if (!fallback.empty()) {
        g_apk_path = fallback;
        return true;
    }
    return false;
}

// --- guest code patches ---
// The original wrote ARM stubs via mmap(RWX)+clear_cache (phase3_vfs.c:185-305).
// Here the same words go into guest memory (heap for the stub, the module text
// for the two-word patch), the JIT range is invalidated, and blx targets are
// thunk trampolines so guest calls land in host code.

static bool WriteGuestWords(DynarmicHost& host, uint32_t guest_addr,
                            const uint32_t* words, size_t count) {
    memcpy(host.GetGuestMemoryBase() + guest_addr, words, count * 4);
    host.AddExecutableRange(guest_addr, count * 4);
    host.InvalidateGuestCode(guest_addr, count * 4);
    return true;
}

// (phase3_vfs.c:185-238)
static bool InstallCheatGate(DynarmicHost& host) {
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    const uint32_t target = base + kCheatGateOffset;
    uint8_t* mem = host.GetGuestMemoryBase();
    uint32_t original[2] = {0};
    memcpy(original, mem + target, sizeof(original));
    if (original[0] != 0xe3540000u || original[1] != 0x0a00004au) {
        LOGE("cheat gate blocked: unexpected saveOption bytes %08x %08x", original[0],
             original[1]);
        return false;
    }

    const uint32_t stub_va = host.GuestAlloc(72, 4);
    if (!stub_va) return false;
    const uint32_t helper =
        host.GetThunkManager().GetOrCreateThunkAddress("phase3_allow_cheat_option");

    uint32_t stub[18];
    stub[0] = 0xe1a00004u;  // mov r0, r4
    stub[1] = 0xe59fc02cu;  // ldr ip, [pc, #44]  -> stub[14]
    stub[2] = 0xe12fff3cu;  // blx ip
    stub[3] = 0xe3500000u;  // cmp r0, #0
    stub[4] = 0x0a000003u;  // beq reject          -> stub[9]
    stub[5] = 0xe3540000u;  // cmp r4, #0
    stub[6] = 0x0a000003u;  // beq option-zero     -> stub[11]
    stub[7] = 0xe59fc018u;  // ldr ip, [pc, #24]  -> stub[15]
    stub[8] = 0xe12fff1cu;  // bx ip (literal is a code address, not a pointer)
    stub[9] = 0xe59fc014u;  // ldr ip, [pc, #20]  -> stub[16]
    stub[10] = 0xe12fff1cu; // bx ip
    stub[11] = 0xe59fc010u; // ldr ip, [pc, #16]  -> stub[17]
    stub[12] = 0xe12fff1cu; // bx ip
    stub[13] = 0;
    stub[14] = helper;                      // phase3_allow_cheat_option
    stub[15] = target + 8;                  // continue
    stub[16] = base + kCheatGateContinue;   // reject -> continue path
    stub[17] = base + kCheatGateOptionZero; // option-zero

    uint32_t patch[2] = {0xe51ff004u, stub_va};  // ldr pc, [pc, #-4]; <stub>
    if (!WriteGuestWords(host, stub_va, stub, 18)) return false;
    if (!WriteGuestWords(host, target, patch, 2)) return false;
    g_cheat_gate_ready = 1;
    LOGI("cheat gate installed: saveOption=0x%08X stub=0x%08X", target, stub_va);
    return true;
}

static bool InstallTouchResponse(DynarmicHost& host) {
    const uint32_t target = host.GetElfLoader().GetBaseAddress() + 0x5658a4u;
    if (host.MemoryRead32(target) != 0xe3a0304bu ||
        host.MemoryRead32(target + 4) != 0xe581303cu) return false;
    // Only TouchScreenBase's interpolation window; simulation dt is unchanged.
    // Zero bypasses the target-position copy in the original update.
    const uint32_t instruction = 0xe3a03001u;  // mov r3, #1 millisecond
    return WriteGuestWords(host, target, &instruction, 1);
}

// The original shop parses this local metadata and owns its confirmation UI.
struct LocalPack { const char* id; int amount; };
static constexpr LocalPack kLocalPacks[] = {
    {"mc4.offline.credits.1000", 1000}, {"mc4.offline.credits.5000", 5000},
    {"mc4.offline.credits.10000", 10000}, {"mc4.offline.credits.20000", 20000},
    {"mc4.offline.credits.50000", 50000}, {"mc4.offline.credits.100000", 100000},
};

static const std::string& LocalCatalogJson() {
    static const std::string json = [] {
        std::string result = "{\"items\":[";
        for (const auto& pack : kLocalPacks) {
            if (result.back() != '[') result += ',';
            const std::string amount = std::to_string(pack.amount);
            result += "{\"title\":\"" + amount + " campaign credits (offline)\","
                "\"id\":\"" + pack.id + "\",\"description\":\"Add " + amount +
                " campaign credits locally after confirmation.\",\"amount\":" + amount +
                ",\"type\":\"currency\",\"virtual_cash_type\":\"credit\","
                "\"billing_methods\":[{\"type\":\"offline\",\"name\":\"Offline catalog\","
                "\"currency\":\"OFFLINE\",\"currency_symbol\":\"OFFLINE\","
                "\"price\":0,\"display_price\":\"Offline\"}]}";
        }
        return result + "]}";
    }();
    return json;
}

static bool GuestRange(DynarmicHost& host, uint32_t p, size_t size) {
    return p != 0 && uint64_t(p) + size <= host.GetGuestMemorySize();
}

static std::string GuestString(DynarmicHost& host, uint32_t p) {
    if (!GuestRange(host, p, 256)) return {};
    const char* chars = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + p);
    const size_t size = strnlen(chars, 256);
    return size < 256 ? std::string(chars, size) : std::string{};
}

static bool g_qa_advanced_request = false;
static bool g_qa_advanced_response = false;
static bool g_qa_active = false;
static bool g_qa_rows_active = false;
static unsigned g_qa_refresh = 0;
static bool g_qa_refresh_general = false;
static bool g_qa_reenter = false;
static uint32_t g_qa_owner_manager = 0;
static uint32_t g_qa_owner_root = 0;
static bool g_qa_hint_pending = false;
static int g_qa_hint_option = 0;
static bool g_qa_russian = false;
static JavaVM* g_qa_java_vm = nullptr;
static std::atomic<uint32_t> g_qa_settings_ready{0};
static std::atomic<uint32_t> g_qa_dirty{0};
static bool g_qa_restored = false;
static uint32_t g_qa_saved = 0;
static constexpr uint32_t kQaOptionMask = 0x3fef;
static unsigned g_qa_clip_refresh = 0;
#if MC4_ENABLE_NATIVE_LOGGING
static unsigned g_qa_selection_refresh = 0;
#endif

static std::string GuestAsString(DynarmicHost& host, uint32_t p) {
    if (!GuestRange(host, p, 20)) return {};
    const uint8_t first = host.MemoryRead8(p);
    uint32_t size = 0, chars = 0;
    if (first >= 1 && first <= 15) {
        size = first - 1;
        chars = p + 1;
    } else if (first == 255 && host.MemoryRead32(p + 4)) {
        size = host.MemoryRead32(p + 4) - 1;
        chars = host.MemoryRead32(p + 12);
    } else return {};
    if (size > 128 || !GuestRange(host, chars, size + 1)) return {};
    const char* text = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + chars);
    return strnlen(text, size + 1) == size ? std::string(text, size) : std::string{};
}

static int QaInfoOption(DynarmicHost& host, uint32_t row) {
    if (!GuestRange(host, row, 0x10)) return 0;
    const uint32_t table = host.MemoryRead32(row + 0xc);
    if (!GuestRange(host, table, 8)) return 0;
    const uint32_t mask = host.MemoryRead32(table + 4);
    if (mask > 1023 || (mask & (mask + 1)) ||
        !GuestRange(host, table, 8 + (mask + 1) * 24)) return 0;
    // List clips are recycled; their own id changes when another option is shown.
    for (uint32_t i = 0; i <= mask; ++i) {
        const uint32_t entry = table + 8 + i * 24;
        if (host.MemoryRead32(entry) == uint32_t(-2) ||
            GuestAsString(host, host.MemoryRead32(entry + 8)) != "id" ||
            host.MemoryRead8(entry + 12) != 2) continue;
        double id = 0;
        std::memcpy(&id, host.GetGuestMemoryBase() + entry + 16, sizeof(id));
        if (!std::isfinite(id) || id < 18 || id > 31 || id != static_cast<int>(id)) return 0;
        const int option = static_cast<int>(id);
        return kQaOptionMask & (1u << (option - 18)) ? option : 0;
    }
    return 0;
}

static uint32_t QaChild(DynarmicHost& host, uint32_t owner, const char* name) {
    if (!GuestRange(host, owner, 0xec)) return 0;
    const uint32_t vtable = host.MemoryRead32(owner);
    if (!GuestRange(host, vtable, 12)) return 0;
    const uint32_t is = host.MemoryRead32(vtable + 8), base = host.GetElfLoader().GetBaseAddress();
    if (is != base + 0x1055600 && is != base + 0xfe0e58) return 0;
    const uint32_t count = host.MemoryRead32(owner + 0xe8), children = host.MemoryRead32(owner + 0xe4);
    if (count > 32 || (count && !GuestRange(host, children, count * 4))) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t child = host.MemoryRead32(children + i * 4);
        if (GuestRange(host, child, 0xa8) &&
            GuestAsString(host, host.MemoryRead32(child + 0x4c)) == name) return child;
    }
    return 0;
}

static bool PumpQaClip(DynarmicHost& host) {
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    const uint32_t manager = host.MemoryRead32(base + 0x17b5e8c);
    if (manager != g_qa_owner_manager || !GuestRange(host, manager, 0x20) ||
        host.MemoryRead32(manager + 0x1c) != g_qa_owner_root) return false;
    const uint32_t info = host.RunFunction(base + 0x5ca2cc, {manager, uint32_t(-1)});
    const uint32_t fx = GuestRange(host, info, 0x18) ? host.MemoryRead32(info + 0x14) : 0;
    if (!GuestRange(host, fx, 0x2c) || !host.MemoryRead32(fx + 0x28)) return false;
    const uint32_t player = host.MemoryRead32(fx + 0x24);
    if (!GuestRange(host, player, 0x7c) || !host.MemoryRead32(player + 0x78)) return false;
    const uint32_t menu = host.RunFunction(base + 0x100e514, {fx, base + 0x1606b48, 0});
    if (!GuestRange(host, menu, 0x168) ||
        GuestAsString(host, host.MemoryRead32(menu + 0x4c)) != "menu_advanced") return false;
    const uint32_t menu_vtable = host.MemoryRead32(menu);
    if (!GuestRange(host, menu_vtable, 12) ||
        host.MemoryRead32(menu_vtable + 8) != base + 0xfe0e58) return false;
    const uint32_t list = QaChild(host, menu, "options_list");
    const auto owned_sprite = [&](uint32_t p) {
        if (!GuestRange(host, p, 0x150) || host.MemoryRead32(p + 0x48) != menu) return false;
        const uint32_t vtable = host.MemoryRead32(p);
        return GuestRange(host, vtable, 12) && host.MemoryRead32(vtable + 8) == base + 0xfe0e58;
    };
    if (!owned_sprite(list)) return false;
    if (g_qa_rows_active) {
        const uint32_t title = QaChild(host, menu, "mc_title");
        const uint32_t label = QaChild(host, title, "title_lbl");
        const uint32_t text_field = QaChild(host, label, "tf");
        const uint32_t vtable = GuestRange(host, text_field, 0xec) ? host.MemoryRead32(text_field) : 0;
        if (!GuestRange(host, vtable, 12) || host.MemoryRead32(vtable + 8) != base + 0xff9fc8 ||
            host.MemoryRead32(text_field + 0x48) != label) return false;
        const uint32_t text = host.GuestAlloc(128, 4);
        if (!text) return false;
        const char* hint = g_qa_russian ? "QA: 13, листайте" : "QA: 13, scroll";
        std::memcpy(host.GetGuestMemoryBase() + text + 32, hint, std::strlen(hint) + 1);
        // SETTINGS is shared with the left category; change only the QA header widget.
        host.RunFunction(base + 0x5b2d58, {text, text + 32});
        host.RunFunction(base + 0xff4728, {text_field, text, 0});
        host.RunFunction(base + 0x5b17e4, {text});
        host.GuestFree(text);
    }
    const uint32_t buttons = QaChild(host, menu, "mc_btns");
    const uint32_t general = QaChild(host, buttons, "opt1_btn"), qa = QaChild(host, buttons, "opt6_btn");
    const auto button_sprite = [&](uint32_t p) {
        if (!GuestRange(host, p, 0x168)) return false;
        const uint32_t vtable = host.MemoryRead32(p);
        return GuestRange(host, vtable, 12) && host.MemoryRead32(vtable + 8) == base + 0xfe0e58;
    };
#if MC4_ENABLE_NATIVE_LOGGING
    static unsigned selections = 0;
    if (button_sprite(general) && button_sprite(qa) && selections++ < 8) {
        LOGI("[QA-SELECT] qa=%d opt1=%d/%u play=%u def=%08X opt6=%d/%u play=%u def=%08X",
             g_qa_rows_active, int16_t(host.MemoryRead16(general + 0x140)),
             host.RunFunction(base + 0xf747cc, {general}), host.MemoryRead8(general + 0x142),
             host.MemoryRead32(general + 0x10c), int16_t(host.MemoryRead16(qa + 0x140)),
             host.RunFunction(base + 0xf747cc, {qa}), host.MemoryRead8(qa + 0x142),
             host.MemoryRead32(qa + 0x10c));
    }
#endif
    // Original shared button clip: settled default8 and selected18, both STOP.
    if (g_qa_rows_active && button_sprite(general) && button_sprite(qa) &&
        host.MemoryRead32(general + 0x48) == buttons && host.MemoryRead32(qa + 0x48) == buttons &&
        host.MemoryRead32(general + 0x10c) != 0 &&
        host.MemoryRead32(general + 0x10c) == host.MemoryRead32(qa + 0x10c) &&
        host.MemoryRead16(general + 0x140) >= 10 && host.MemoryRead16(general + 0x140) <= 18 &&
        host.MemoryRead16(qa + 0x140) <= 8 &&
        host.RunFunction(base + 0xf747cc, {general}) > 18 && host.RunFunction(base + 0xf747cc, {qa}) > 18) {
        host.RunFunction(base + 0xfdb394, {general, 8});
        host.RunFunction(base + 0xfd9954, {general, 1});
        host.RunFunction(base + 0xfdb394, {qa, 18});
        host.RunFunction(base + 0xfd9954, {qa, 1});
        LOGI("[QA-SELECT] selected original QA button");
    }
    const auto current_mask = [&] {
        const uint32_t aux = host.MemoryRead32(list + 0x5c);
        return GuestRange(host, aux, 0x94) ? host.MemoryRead32(aux + 0x90) : 0u;
    };
    uint32_t shape = QaChild(host, menu, "mc4_qa_viewport");
    if (shape && !owned_sprite(shape)) return false;
    if (current_mask() && current_mask() != shape) return false;
    if (!g_qa_rows_active && !shape) return true;
    if (g_qa_rows_active && shape && current_mask() == shape && !host.MemoryRead8(shape + 0x146)) return true;
    const uint32_t scratch = host.GuestAlloc(64, 4);
    if (!scratch) return false;
    std::memset(host.GetGuestMemoryBase() + scratch, 0, 64);
    bool success = false;
    do {
        if (!g_qa_rows_active) {
            if (current_mask() == shape) host.RunFunction(base + 0xf6cb80, {list, 94, scratch + 16});
            if (current_mask()) break;
            host.RunFunction(base + 0xfd810c, {menu, shape});
            success = true;
            LOGI("[QA-CLIP] removed viewport");
            break;
        }
        float viewport[4]{};
        bool bounds_ok = true;
        for (unsigned i = 0; i < 6; ++i) {
            const uint32_t row = QaChild(host, list, ("item_" + std::to_string(i)).c_str());
            if (!row) { bounds_ok = false; break; }
            host.RunFunction(base + 0xf6b860, {row, scratch});
            float rect[4];
            std::memcpy(rect, host.GetGuestMemoryBase() + scratch, 16);
            for (float value : rect) if (!std::isfinite(value) || std::abs(value) > 10000) bounds_ok = false;
            if (!bounds_ok || rect[0] >= rect[1] || rect[2] >= rect[3]) { bounds_ok = false; break; }
            if (!i) std::memcpy(viewport, rect, 16);
            else {
                viewport[0] = std::min(viewport[0], rect[0]); viewport[1] = std::max(viewport[1], rect[1]);
                viewport[2] = std::min(viewport[2], rect[2]); viewport[3] = std::max(viewport[3], rect[3]);
            }
        }
        const uint32_t matrix = host.MemoryRead32(list + 0x54);
        if (!bounds_ok || !GuestRange(host, matrix, 24)) break;
        std::memcpy(host.GetGuestMemoryBase() + scratch, viewport, 16);
        host.RunFunction(base + 0xf4aa7c, {matrix, scratch});
        std::memcpy(viewport, host.GetGuestMemoryBase() + scratch, 16);
        for (float value : viewport) if (!std::isfinite(value) || std::abs(value) > 10000) bounds_ok = false;
        if (!bounds_ok || viewport[0] >= viewport[1] || viewport[2] >= viewport[3]) break;
        if (!shape) {
            const uint32_t depth = host.RunFunction(base + 0xfdbeb8, {menu});
            if (depth < 0x4000 || depth > 0xffff) break;
            const char name[] = "mc4_qa_viewport";
            std::memcpy(host.GetGuestMemoryBase() + scratch + 32, name, sizeof(name));
            shape = host.RunFunction(base + 0xfdaeb4, {menu, scratch + 32, depth});
        }
        if (!owned_sprite(shape)) { shape = 0; break; }
        const uint32_t canvas = host.RunFunction(base + 0xfdc86c, {shape});
        if (!GuestRange(host, canvas, 0xc8)) break;
        host.MemoryWrite32(scratch + 28, 0xffffffff);
        host.RunFunction(base + 0x107dfd4, {canvas, scratch + 28});
        const auto point = [&](float x, float y, bool move = false) {
            // Native bounds are pixels; the original Canvas consumes twips.
            const float coordinates[] = {x * 20, y * 20};
            uint32_t words[2]; std::memcpy(words, coordinates, sizeof(words));
            host.RunFunction(base + (move ? 0x107e8b8 : 0x107e8f8), {canvas, words[0], words[1]});
        };
        point(viewport[0], viewport[2], true); point(viewport[1], viewport[2]);
        point(viewport[1], viewport[3]); point(viewport[0], viewport[3]); point(viewport[0], viewport[2]);
        host.RunFunction(base + 0x107daf0, {canvas});
        // A drawing mask must not become the topmost mouse target.
        host.MemoryWrite8(scratch + 16, 1);
        host.RunFunction(base + 0xfdeb8c, {shape, 41, scratch + 16});
        if (host.MemoryRead8(shape + 0x146)) break;
        // Borrowed ASValue: the original setter takes its own Character reference.
        host.MemoryWrite8(scratch + 16, 5);
        host.MemoryWrite32(scratch + 20, shape);
        host.RunFunction(base + 0xf6cb80, {list, 94, scratch + 16});
        success = current_mask() == shape;
        LOGI("[QA-CLIP] applied=%d rect=%.2f,%.2f,%.2f,%.2f", success,
             viewport[0], viewport[1], viewport[2], viewport[3]);
    } while (false);
    if (!success && shape && current_mask() != shape) host.RunFunction(base + 0xfd810c, {menu, shape});
    host.GuestFree(scratch);
    return success;
}

struct QaHint { int id; uint16_t offset; const char* english; const char* russian; uint32_t stored[2]{}; };
static QaHint kQaHints[] = {
    {18, 0x04, "Protects the player from damage during campaign gameplay.", "Защищает игрока от урона в кампании."},
    {19, 0x08, "Shows the frame-rate counter during gameplay.", "Показывает счётчик частоты кадров во время игры."},
    {20, 0x814, "Shows the game's diagnostic information overlay.", "Показывает отладочную информацию игры."},
    {21, 0x07, "Makes all campaign missions and the highest difficulty available while enabled.", "Открывает все миссии кампании и максимальную сложность, пока настройка включена."},
    {23, 0x06, "Shows the gameplay HUD. Turn it off to hide the interface.", "Показывает игровой интерфейс. Выключите, чтобы скрыть его."},
    {24, 0xbf, "Adds the game's debug maps to level selection.", "Показывает отладочные карты в меню выбора уровней."},
    {25, 0xc2, "Shows diagnostic AI navigation nodes.", "Показывает отладочные узлы навигации ИИ."},
    {26, 0x348, "Doubles game simulation time for the built-in speed test.", "Ускоряет игровое время вдвое для проверки игры."},
    {27, 0x349, "Keeps consumable perk counts from decreasing when used.", "Не уменьшает количество расходуемых навыков при использовании."},
    {28, 0x34a, "Keeps military support actions available after use.", "Сохраняет доступность военной поддержки после использования."},
    {29, 0x34b, "Keeps available grenades from being consumed when thrown.", "Не расходует имеющиеся гранаты при броске."},
    {30, 0x34c, "Keeps rounds in the weapon magazine while firing.", "Не расходует патроны в магазине оружия при стрельбе."},
    {31, 0x34d, "Keeps reserve ammunition from being spent when reloading.", "Не расходует запас патронов при перезарядке."},
};

static bool QaPreferenceState(uint32_t& state, bool save) {
    JNIEnv* env = nullptr;
    if (!g_qa_java_vm || g_qa_java_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ||
        !env || env->ExceptionCheck()) return false;
    if (env->PushLocalFrame(8) != JNI_OK) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    bool ok = false;
    do {
        const jclass utils = env->FindClass("com/gameloft/android/ANMP/GloftM4HM/GLUtils/SUtils");
        if (!utils) break;
        const jmethodID context_method = env->GetStaticMethodID(utils, "getContext", "()Landroid/content/Context;");
        if (!context_method) break;
        const jobject context = env->CallStaticObjectMethod(utils, context_method);
        if (env->ExceptionCheck() || !context) break;
        const jmethodID get = env->GetStaticMethodID(utils, "getPreferenceInt", "(Ljava/lang/String;ILjava/lang/String;)I");
        if (!get) break;
        const jstring key = env->NewStringUTF("options");
        if (!key) break;
        const jstring prefs = env->NewStringUTF("MC4QaSettings");
        if (!prefs) break;
        if (save) {
            const jclass integer = env->FindClass("java/lang/Integer");
            if (!integer) break;
            const jmethodID box = env->GetStaticMethodID(integer, "valueOf", "(I)Ljava/lang/Integer;");
            if (!box) break;
            const jobject value = env->CallStaticObjectMethod(integer, box, static_cast<jint>(state));
            if (env->ExceptionCheck() || !value) break;
            const jmethodID set = env->GetStaticMethodID(utils, "setPreference", "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;)V");
            if (!set) break;
            env->CallStaticVoidMethod(utils, set, key, value, prefs);
            if (env->ExceptionCheck()) break;
        }
        const uint32_t read = static_cast<uint32_t>(env->CallStaticIntMethod(utils, get, key, 0, prefs));
        ok = !env->ExceptionCheck() && (!save || read == state);
        if (ok) state = read;
    } while (false);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("QA preference access failed");
    }
    env->PopLocalFrame(nullptr);
    return ok;
}

static void PumpQaPreferences(DynarmicHost& host) {
    if (g_qa_restored && !g_qa_dirty.load(std::memory_order_relaxed)) return;
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    const uint32_t settings = g_qa_settings_ready.load(std::memory_order_acquire);
    const uint32_t application = host.MemoryRead32(base + 0x17b7d88);
    if (!GuestRange(host, settings, 0x358) || host.MemoryRead32(base + 0x17b85f0) != settings ||
        !GuestRange(host, application, 0x818)) return;
    if (!g_qa_restored) {
        uint32_t state = 0;
        if (!QaPreferenceState(state, false)) return;
        const uint32_t known = state >> 16, enabled = state & 0xffff;
        if ((state & ~(kQaOptionMask | (kQaOptionMask << 16))) || (enabled & ~known)) {
            LOGE("Invalid QA preference state; retaining native defaults");
            state = 0;
        }
        const uint32_t dirty = g_qa_dirty.load(std::memory_order_relaxed);
        for (const auto& option : kQaHints) {
            const uint32_t bit = 1u << (option.id - 18);
            if (!(state >> 16 & bit) || (dirty & bit)) continue;
            const uint32_t value = (state & bit) ? 1 : 0;
            if (option.id == 18) host.RunFunction(base + 0x89e96c, {settings, value});
            else if (option.id == 20) host.RunFunction(base + 0x89d4b4, {settings, value});
            else host.MemoryWrite8(settings + option.offset, value);
        }
        g_qa_saved = state;
        g_qa_restored = true;
        LOGI("[QA-SAVE] restored=%08X", state);
    }
    const uint32_t dirty = g_qa_dirty.exchange(0, std::memory_order_relaxed);
    if (!dirty) return;
    uint32_t state = g_qa_saved | (dirty << 16);
    for (const auto& option : kQaHints) {
        const uint32_t bit = 1u << (option.id - 18);
        if (!(dirty & bit)) continue;
        const bool value = host.MemoryRead8((option.id == 20 ? application : settings) + option.offset) != 0;
        state = value ? state | bit : state & ~bit;
    }
    if (QaPreferenceState(state, true)) {
        g_qa_saved = state;
        LOGI("[QA-SAVE] saved=%08X", state);
    } else g_qa_dirty.fetch_or(dirty, std::memory_order_relaxed);
}

uint32_t Phase3SettingsStringOverride(DynarmicHost& host, uint32_t manager,
                                     uint32_t id, uint32_t caller) {
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    if (caller == base + 0x5897d0 && g_qa_hint_pending) {
        g_qa_hint_pending = false;
        for (auto& hint : kQaHints) if (id == 0 && hint.id == g_qa_hint_option) {
            LOGI("[QA-HINT] option=%d locale=%s", hint.id, g_qa_russian ? "ru" : "en");
            const char* text = g_qa_russian ? hint.russian : hint.english;
            uint32_t& stored = hint.stored[g_qa_russian ? 1 : 0];
            if (!stored) {
                stored = host.GuestAlloc(strlen(text) + 1, 4);
                if (stored) memcpy(host.GetGuestMemoryBase() + stored, text, strlen(text) + 1);
            }
            return stored;
        }
    }
#if MC4_ENABLE_NATIVE_LOGGING
    static unsigned qa_lookups = 0;
    if (g_qa_active && caller == base + 0x5897d0 && qa_lookups++ < 256)
        LOGI("[QA-LOOKUP] id=%08X", id);
#endif
    if (!GuestRange(host, manager, 12)) return 0;
    const uint32_t count = host.MemoryRead32(manager + 4);
    const uint32_t tables = host.MemoryRead32(manager + 8);
    if (count > 32 || (id >> 16) >= count || !GuestRange(host, tables, 4 * count)) return 0;
    const uint32_t table = host.MemoryRead32(tables + 4 * (id >> 16));
    if (!GuestRange(host, table, 0x30)) return 0;
    const uint32_t strings = host.MemoryRead32(table + 0x24);
    const uint32_t offsets = host.MemoryRead32(table + 0x2c);
    if (strings > 65535 || (id & 0xffff) >= strings || !GuestRange(host, offsets, 4 * strings)) return 0;
    const uint64_t address = uint64_t(host.MemoryRead32(table + 0x28)) +
        host.MemoryRead32(offsets + 4 * (id & 0xffff));
    if (address > UINT32_MAX) return 0;
    const uint32_t chars = static_cast<uint32_t>(address);
    const std::string text = GuestString(host, chars);
#if MC4_ENABLE_NATIVE_LOGGING
    if (caller == base + 0x5897d0) {
        static uint32_t seen[512]{};
        static size_t used = 0;
        if (used < 512 && std::find(seen, seen + used, id) == seen + used) {
            seen[used++] = id;
            LOGI("[QA-STRING] id=%08X text=%s", id, text.c_str());
        }
    }
#endif
    const char* replacement = nullptr;
    if (caller == base + 0x5897d0 && id == 0x40263) {
        g_qa_russian = text.find("конфиденц") != std::string::npos || text.find("Конфиденц") != std::string::npos;
        replacement = g_qa_russian ? "QA: настройки" : "QA settings";
    }
    if (id == 0x2052b && caller == base + 0x678a48)
        replacement = "Local credits could not be saved. No purchase was completed.";
    if (!replacement) return 0;
    // Strings are borrowed by StringMgr, so retain each small label for the process.
    static uint32_t english = 0, russian = 0, error = 0;
    uint32_t& stored = id == 0x2052b ? error : g_qa_russian ? russian : english;
    if (!stored) {
        const size_t size = strlen(replacement) + 1;
        stored = host.GuestAlloc(size, 4);
        if (stored) memcpy(host.GetGuestMemoryBase() + stored, replacement, size);
    }
    return stored;
}

static void ContinuePush(Dynarmic::A32::Jit& jit, DynarmicHost& host,
                         uint16_t mask, uint32_t entry) {
    jit.Regs()[13] = arm32::PushRegisters(jit.Regs()[13], mask,
        [&jit](unsigned r) { return jit.Regs()[r]; },
        [&host](uint32_t p, uint32_t value) { host.MemoryWrite32(p, value); });
    jit.Regs()[15] = entry + 4;
}

static uint32_t g_purchase_iap = 0;
static int g_purchase_amount = 0;
static std::mutex g_purchase_lock;

void Phase3PumpLocalUi(DynarmicHost& host) {
    PumpQaPreferences(host);
#if MC4_ENABLE_NATIVE_LOGGING
    static bool chapters_logged = false;
    if (!chapters_logged) {
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        const uint32_t gameplay = host.MemoryRead32(base + 0x17b5e10), fm = host.MemoryRead32(base + 0x17b5bb0);
        const uint32_t desc = GuestRange(host, gameplay, 0x110) ? host.MemoryRead32(gameplay + 0x14) : 0;
        const uint32_t map = GuestRange(host, fm, 4) ? host.MemoryRead32(fm) : 0;
        if (GuestRange(host, desc, 0x14) && GuestRange(host, map, 8)) {
            const uint32_t count = host.MemoryRead32(desc + 0x10), chapters = host.MemoryRead32(desc + 0xc);
            const uint32_t files = host.MemoryRead32(map), rows = host.MemoryRead32(map + 4);
            if (count && count <= 32 && files && files <= 65536 &&
                GuestRange(host, chapters, count * 52) && GuestRange(host, rows, files * 12)) {
                chapters_logged = true;
                for (uint32_t i = 0; i < count; ++i) {
                    const uint32_t chapter = chapters + i * 52;
                    const int32_t intro = host.MemoryRead32(chapter + 8), outro = host.MemoryRead32(chapter + 0x14);
                    const auto filename = [&](int32_t id) {
                        return id >= 0 && uint32_t(id) < files ? GuestString(host, host.MemoryRead32(rows + id * 12 + 4)) : "";
                    };
                    LOGI("[CHAPTER-VIDEO] mission=%u intro=%d:%s outro=%d:%s sections=%u checkpoint=%u loading=%u",
                         i + 1, intro, filename(intro).c_str(), outro, filename(outro).c_str(),
                         host.MemoryRead32(chapter + 0x30), host.MemoryRead8(gameplay + 0x75),
                         host.MemoryRead8(gameplay + 0x18));
                }
            }
        }
    }
#endif
    if (g_qa_refresh && --g_qa_refresh == 0) {
        g_qa_advanced_response = false;
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        const uint32_t manager = host.MemoryRead32(base + 0x17b5e8c);
        const bool same_owner = manager == g_qa_owner_manager && GuestRange(host, manager, 0x20) &&
                                host.MemoryRead32(manager + 0x1c) == g_qa_owner_root;
        if (!same_owner) {
            g_qa_advanced_request = false;
            g_qa_active = false;
            g_qa_rows_active = false;
            g_qa_hint_pending = false;
        }
        const uint32_t info = same_owner ? host.RunFunction(base + 0x5ca2cc, {manager, uint32_t(-1)}) : 0;
        const uint32_t fx = GuestRange(host, info, 0x18) ? host.MemoryRead32(info + 0x14) : 0;
        const uint32_t player = GuestRange(host, fx, 0x28) ? host.MemoryRead32(fx + 0x24) : 0;
        if (GuestRange(host, player, 0x7c) && host.MemoryRead32(player + 0x78)) {
            // A READY response alone leaves cached settings unchanged. Use
            // the original pop/push path to re-enter the requested settings.
            g_qa_advanced_request = !g_qa_refresh_general;
            host.RunFunction(base + 0x5cda54, {manager, base + 0x1606b48, uint32_t(-1)});
        } else {
            g_qa_advanced_request = false;
            g_qa_active = false;
            g_qa_rows_active = false;
            g_qa_hint_pending = false;
        }
    }
    if (g_qa_clip_refresh) {
        --g_qa_clip_refresh;
        if (PumpQaClip(host)) g_qa_clip_refresh = 0;
    }
#if MC4_ENABLE_NATIVE_LOGGING
    if (g_qa_selection_refresh && --g_qa_selection_refresh == 0) PumpQaClip(host);
#endif
    uint32_t iap;
    int amount;
    {
        std::lock_guard<std::mutex> lock(g_purchase_lock);
        iap = g_purchase_iap;
        amount = g_purchase_amount;
        g_purchase_iap = 0;
    }
    if (!iap) return;
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    const uint32_t settings = host.RunFunction(base + 0x89d0f4u);
    const uint32_t profile = settings ? host.RunFunction(base + 0x89e414u, {settings}) : 0;
    bool success = GuestRange(host, settings, 0xc1) && GuestRange(host, profile, 0x29) &&
                   host.MemoryRead8(profile + 0x28) != 0;
    if (success) {
        const int32_t before = static_cast<int32_t>(host.RunFunction(base + 0x63defcu, {profile}));
        const bool multiplier = host.MemoryRead8(settings + 0xc0) != 0;
        success = before >= 0 && amount > 0 && int64_t(before) + amount <= INT_MAX &&
                  (!multiplier || amount % 50 == 0);
        if (success) {
            host.RunFunction(base + 0x63df34u, {profile, uint32_t(multiplier ? amount / 50 : amount), 1});
            const int32_t after = static_cast<int32_t>(host.RunFunction(base + 0x63defcu, {profile}));
            success = after == before + amount;
            if (success) host.RunFunction(base + 0x89fac8u, {settings, 1});
        }
    }
    // Original Update dispatches the success/error event on the following frame.
    host.MemoryWrite32(iap + 8, 0);
    host.MemoryWrite32(iap, success ? 7 : 8);
}

static bool GuardWords(DynarmicHost& host, uint32_t offset,
                       std::initializer_list<uint32_t> words) {
    uint32_t at = host.GetElfLoader().GetBaseAddress() + offset;
    for (const uint32_t expected : words) {
        if (host.MemoryRead32(at) != expected) {
            LOGE("offline UI patch blocked at %08X expected=%08X actual=%08X", at, expected, host.MemoryRead32(at));
            return false;
        }
        at += 4;
    }
    return true;
}

static bool InstallAudioApi(DynarmicHost& host) {
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    if (!GuardWords(host, 0xf1c6fc, {0xe59f3008, 0xe79f3003, 0xe5830000, 0xe12fff1e})) return false;
    const uint32_t api = host.MemoryRead32(base + 0x179c678);
    if (api != base + 0x17b0764 || host.MemoryRead32(api) != 3) return false;
    char value[PROP_VALUE_MAX]{};
    if (__system_property_get("ro.build.version.sdk", value) <= 0) return false;
    char* end = nullptr;
    const long level = strtol(value, &end, 10);
    if (!end || *end || level < 24 || level > INT_MAX) return false;
    // Equivalent to VoxSetAndroidAPILevel. Its original default is Android3,
    // which selects obsolete AudioTrack; initialize before driver creation.
    host.MemoryWrite32(api, static_cast<uint32_t>(level));
    LOGI("Vox Android API initialized: %ld (original default 3)", level);
    return true;
}

static bool InstallIapRoute(DynarmicHost& host) {
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    const uint32_t text_entry = host.MemoryRead32(base + 0xff4728);
    const uint32_t text_probe = host.GetThunkManager().FindThunkAddress("edit_set");
    // The loader guards the original PUSH before installing its TEXTPATH probe.
    if (text_entry != 0xe92d4ff0 &&
        (!GuestRange(host, text_probe, 4) || (text_entry & 0xff000000) != 0xef000000 ||
         host.MemoryRead32(text_probe) != text_entry)) {
        LOGE("QA text setter blocked: unexpected entry %08X", text_entry);
        return false;
    }
    struct Patch { uint32_t offset, before, after; };
    const Patch patches[] = {
        {0x672c70, 0x1a000112, 0xea000112}, // Original successful shop route, without Wi-Fi.
        {0xc1bee4, 0xda0000ca, 0xba0000ca}, // Zero local price valid; negative still invalid.
        {0x67552c, 0xeb16693e, 0xe320f000}, // No uninitialized live Store::Update.
        {0x67871c, 0xebfcea3b, 0xeafff4d2}, // Completion -> original epilogue.
        {0x67872c, 0xebfcea37, 0xea000012}, // Error case skips live SDK tracking.
        {0x7663c8, 0xe59f3668, 0xea00000b}, // Confirmed buy skips live BI initialization.
        {0x78df5c, 0xebf8942b, 0xea00000a}, // Pack listing skips live tracking.
        {0x76ecd0, 0xeb2287b6, 0xe320f000}, // Omit server-alpha row22.
        {0x76fb30, 0xeb22841e, 0xe320f000}, // Omit credentials row32.
        {0x76ee20, 0xe3a01005, 0xe3a01004}, {0x76ef78, 0xe3a01006, 0xe3a01005},
        {0x76f0d0, 0xe3a01007, 0xe3a01006}, {0x76f228, 0xe3a01008, 0xe3a01007},
        {0x76f380, 0xe3a01009, 0xe3a01008}, {0x76f4d8, 0xe3a0100a, 0xe3a01009},
        {0x76f720, 0xe3a0100b, 0xe3a0100a}, {0x76f878, 0xe3a0100c, 0xe3a0100b},
        {0x76f9d0, 0xe3a0100d, 0xe3a0100c},
    };
    if (!GuardWords(host, 0x670d38, {0xe92d4ff0, 0xe24ddf41, 0xe59f560c}) ||
        !GuardWords(host, 0x66ddd8, {0xe92d47f0, 0xe3073740, 0xe59f549c}) ||
        !GuardWords(host, 0x6754e0, {0xe92d4ff0, 0xed2d8b02, 0xe59f3658}) ||
        !GuardWords(host, 0x6737c4, {0xe92d4ff0, 0xe1a06000, 0xe5903000}) ||
        !GuardWords(host, 0xc12d90, {0xe92d4ff0, 0xe24dd04c, 0xe28d4020}) ||
        !GuardWords(host, 0x89c588, {0xe92d4070, 0xe24dd010, 0xe28d4008}) ||
        !GuardWords(host, 0x76d338, {0xe92d4ff0, 0xe24dd0d4, 0xe59fafcc}) ||
        !GuardWords(host, 0x76e5a0, {0xe92d4ff0, 0xe24ddf45, 0xe59f9fd0}) ||
        !GuardWords(host, 0x76fcdc, {0xe08f1001, 0xebf90c1c, 0xe1a00005}) ||
        !GuardWords(host, 0x7663c8, {0xe59f3668, 0xe799b003, 0xe59b9000}) ||
        !GuardWords(host, 0x78df5c, {0xebf8942b, 0xe3500000, 0x0a000008}) ||
        !GuardWords(host, 0x5cda54, {0xe92d47f0, 0xe24dd098, 0xe59f64cc}) ||
        !GuardWords(host, 0x5ce17c, {0xe92d47f0, 0xe24dd098, 0xe59f64d4}) ||
        !GuardWords(host, 0x5ca2cc, {0xe590300c, 0xe3710001, 0xe24dd008}) ||
        !GuardWords(host, 0xf6a8a0, {0xe92d4070, 0xe1a04001, 0xe1a06000}) ||
        !GuardWords(host, 0xfa59b4, {0xe598200c, 0xe3520000, 0x0a00003e}) ||
        !GuardWords(host, 0xfa59dc, {0xe5925004, 0xe00a0005, 0xe0803080, 0xe1a03183, 0xe2833008}) ||
        !GuardWords(host, 0xfa5a88, {0xe0855085, 0xe598100c, 0xe1a00006, 0xe0811185, 0xe2811014}) ||
        !GuardWords(host, 0x1055600, {0xe3510001, 0x13510004, 0x03a00001}) ||
        !GuardWords(host, 0xfe0e58, {0xe3510004, 0x13510039, 0xe2410001}) ||
        !GuardWords(host, 0x100e514, {0xe251c000, 0x0a00006c, 0xe92d40f8}) ||
        !GuardWords(host, 0xf6b860, {0xe92d47f0, 0xe1a05000, 0xe590305c}) ||
        !GuardWords(host, 0x5b2d58, {0xe92d4070, 0xe2515000, 0xe3a02001}) ||
        !GuardWords(host, 0x5b17e4, {0xe92d4010, 0xe1a04000, 0xe1d030d0}) ||
        !GuardWords(host, 0xff472c, {0xe1a05000, 0xe59f44b8}) ||
        !GuardWords(host, 0xff9fc8, {0xe3510001, 0x13510025, 0x03a00001}) ||
        !GuardWords(host, 0xf4aa7c, {0xed905a02, 0xedd06a01, 0xedd07a05}) ||
        !GuardWords(host, 0xfdbeb8, {0xe28000e4, 0xeafe8d74}) ||
        !GuardWords(host, 0xfdaeb4, {0xe92d4ff0, 0xe1a04000, 0xed2d8b02}) ||
        !GuardWords(host, 0xfdc86c, {0xe92d40f0, 0xe1a04000, 0xe590114c}) ||
        !GuardWords(host, 0x107dfd4, {0xe92d47f0, 0xe24dd058, 0xe28d8004}) ||
        !GuardWords(host, 0x107e8b8, {0xedd06a20, 0xe1a03000, 0xee071a90}) ||
        !GuardWords(host, 0x107e8f8, {0xe92d43f0, 0xe1a04000, 0xe5903090}) ||
        !GuardWords(host, 0x107daf0, {0xe92d4010, 0xe1a04000, 0xe5903090}) ||
        !GuardWords(host, 0xfd810c, {0xe92d4038, 0xe1a04001, 0xe1a05000}) ||
        !GuardWords(host, 0xf6cb80, {0xe92d43f0, 0xe1a05000, 0xed2d8b04}) ||
        !GuardWords(host, 0xfdeb8c, {0xe92d4ff0, 0xe1a05002, 0xe59f99a4}) ||
        !GuardWords(host, 0xfdebc0, {0xea000059}) ||
        !GuardWords(host, 0xfded2c, {0xe1a00005, 0xe3a0b001, 0xeb008ecb, 0xe5ca0146}) ||
        !GuardWords(host, 0xfd8b74, {0xe5d03146, 0xe3530000, 0x0a00001a}) ||
        !GuardWords(host, 0xf747c0, {0xe2800d05, 0xe1d000f0, 0xe12fff1e}) ||
        !GuardWords(host, 0xf747cc, {0xe590010c, 0xe59f301c, 0xe5902000}) ||
        !GuardWords(host, 0xfdb394, {0xe92d41f0, 0xe1a04000, 0xe590010c, 0xe1a06001}) ||
        !GuardWords(host, 0xfd9954, {0xe92d4038, 0xe1a04000, 0xe1a05001}) ||
        !GuardWords(host, 0x63ce00, {0xe5d00028, 0xe12fff1e}) ||
        !GuardWords(host, 0x63defc, {0xe92d4010, 0xe1a04000, 0xe5903000}) ||
        !GuardWords(host, 0x63df34, {0xe92d4030, 0xe24dd00c, 0xe5903000}) ||
        !GuardWords(host, 0x89d0f4, {0xe59f3008, 0xe79f3003, 0xe5930000}) ||
        // The loader already guards/emulates LoadSettings' PUSH entry probe.
        !GuardWords(host, 0x8a0b5c, {0xe24dde45, 0xe59f62fc}) ||
        !GuardWords(host, 0x8a0ce8, {0xe59d244c, 0xe5983000, 0xe1520003}) ||
        !GuardWords(host, 0x89e96c, {0xe92d4038, 0xe2515000, 0xe1a04000}) ||
        !GuardWords(host, 0x89e9b4, {0xe5c45004}) ||
        !GuardWords(host, 0x89d4b4, {0xe59f300c, 0xe79f3003, 0xe5933000, 0xe5c31814}) ||
        !GuardWords(host, 0x75bd94, {0xe5c40008}) ||
        !GuardWords(host, 0x75bf6c, {0xe5c40007}) ||
        !GuardWords(host, 0x75bfac, {0xe5c40006}) ||
        !GuardWords(host, 0x75bfcc, {0xe5c400bf}) ||
        !GuardWords(host, 0x75bfec, {0xe5c400c2}) ||
        !GuardWords(host, 0x75c00c, {0xe5c40348}) ||
        !GuardWords(host, 0x75c02c, {0xe5c40349}) ||
        !GuardWords(host, 0x75c04c, {0xe5c4034a}) ||
        !GuardWords(host, 0x75c06c, {0xe5c4034b}) ||
        !GuardWords(host, 0x75c08c, {0xe5c4034c}) ||
        !GuardWords(host, 0x75c0ac, {0xe5c4034d}) ||
        !GuardWords(host, 0x89e414, {0xe59002fc, 0xe12fff1e}) ||
        !GuardWords(host, 0x89fac8, {0xe92d4ff0, 0xe24dd054, 0xe28d4030}) ||
        !GuardWords(host, 0xc0da2c, {0xe92d4038, 0xe59f4034, 0xe79f4004})) return false;
    for (const auto& patch : patches)
        if (!GuardWords(host, patch.offset, {patch.before})) return false;
#if MC4_ENABLE_NATIVE_LOGGING
    if (!GuardWords(host, 0xfa6344, {0xe1a00009, 0xeb017194, 0xe1a00007})) return false;
#endif

    const uint32_t stub_va = host.GuestAlloc(40, 4);
    if (!stub_va) return false;
    const uint32_t init[] = {0xe92d4010, 0xe1a04000, 0xe59fc014, 0xe12fff3c,
        0xe5840014, 0xe3a03003, 0xe5843000, 0xe3a00000, 0xe8bd8010, base + 0xc0da2c};
    WriteGuestWords(host, stub_va, init, 10);
    const uint32_t jump[] = {0xe51ff004, stub_va};
    WriteGuestWords(host, base + 0x670d38, jump, 2);
    const struct { uint32_t offset; const char* name; } hooks[] = {
        {0x66ddd8, "mc4_local_refresh"}, {0x6754e0, "mc4_local_update"},
        {0x6737c4, "mc4_local_purchase"}, {0xc12d90, "mc4_local_json"},
        {0x89c588, "mc4_settings_qa"},
        {0x8a0ce8, "mc4_qa_settings_loaded"},
        {0x76d338, "mc4_qa_advanced"}, {0x76fcdc, "mc4_qa_advanced_response"},
        {0xf6a8a0, "mc4_qa_event"},
#if MC4_ENABLE_NATIVE_LOGGING
        {0xfa6344, "mc4_qa_member_trace"},
#endif
    };
    for (const auto& hook : hooks) {
        const uint32_t thunk = host.GetThunkManager().GetOrCreateThunkAddress(hook.name);
        const uint32_t svc = host.MemoryRead32(thunk);
        WriteGuestWords(host, base + hook.offset, &svc, 1);
    }
    for (const auto& patch : patches)
        WriteGuestWords(host, base + patch.offset, &patch.after, 1);
    return true;
}

void Phase3SetJavaVM(JavaVM* vm) { g_qa_java_vm = vm; }

static bool g_thunks_registered = false;
void Phase3RegisterThunks(DynarmicHost& host) {
    if (g_thunks_registered) return;
    g_thunks_registered = true;
    auto& thunks = host.GetThunkManager();
    thunks.RegisterThunk("phase3_allow_cheat_option", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const int id = static_cast<int>(jit.Regs()[0]);
        const bool allowed = Phase3AllowCheatOption(id);
        if (allowed && id >= 18 && id <= 31 && id != 22 && jit.Regs()[9] == 0)
            g_qa_dirty.fetch_or(1u << (id - 18), std::memory_order_relaxed);
        jit.Regs()[0] = allowed ? 1u : 0u;
    });
    thunks.RegisterThunk("mc4_qa_settings_loaded", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        g_qa_settings_ready.store(jit.Regs()[4], std::memory_order_release);
        jit.Regs()[2] = host.MemoryRead32(jit.Regs()[13] + 0x44c);
        jit.Regs()[15] = host.GetElfLoader().GetBaseAddress() + 0x8a0cec;
    });
    thunks.RegisterThunk("mc4_local_refresh", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t iap = jit.Regs()[0];
        if (GuestRange(host, iap, 0x78)) {
            host.MemoryWrite32(iap, 3);
            for (unsigned offset : {0x61u, 0x62u, 0x63u}) host.MemoryWrite8(iap + offset, 0);
            host.MemoryWrite32(iap + 0x70, 0);
            host.MemoryWrite32(iap + 0x74, 0);
        }
        jit.Regs()[0] = 0;
        jit.Regs()[15] = jit.Regs()[14];
    });
    thunks.RegisterThunk("mc4_local_update", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t state = host.MemoryRead32(jit.Regs()[0]);
        if (state == 7 || state == 8)
            ContinuePush(jit, host, 0x4ff0, host.GetElfLoader().GetBaseAddress() + 0x6754e0);
        else jit.Regs()[15] = jit.Regs()[14];
    });
    thunks.RegisterThunk("mc4_local_json", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        if (jit.Regs()[14] != base + 0x67292c) {
            ContinuePush(jit, host, 0x4ff0, base + 0xc12d90);
            return;
        }
        jit.Regs()[0] = uint32_t(-1);
        const uint32_t out = jit.Regs()[1];
        if (GuestRange(host, out, 4)) {
            const uint32_t old = host.MemoryRead32(out);
            if (old >= 12 && GuestRange(host, old - 12, 13) && host.MemoryRead32(old - 12) == 0) {
                const auto& json = LocalCatalogJson();
                const uint32_t allocation = host.GuestAlloc(12 + json.size() + 1, 4);
                if (allocation) {
                    host.MemoryWrite32(allocation, json.size());
                    host.MemoryWrite32(allocation + 4, json.size());
                    host.MemoryWrite32(allocation + 8, 0);
                    memcpy(host.GetGuestMemoryBase() + allocation + 12, json.c_str(), json.size() + 1);
                    host.MemoryWrite32(out, allocation + 12);
                    jit.Regs()[0] = 0;
                }
            }
        }
        jit.Regs()[15] = jit.Regs()[14];
    });
    thunks.RegisterThunk("mc4_local_purchase", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        const uint32_t iap = jit.Regs()[0], id_string = jit.Regs()[1];
        int amount = 0;
        if (jit.Regs()[14] == base + 0x766408) {
            const std::string id = GuestString(host, id_string);
            for (const auto& pack : kLocalPacks) if (id == pack.id) amount = pack.amount;
        }
        bool accepted = false;
        if (amount && GuestRange(host, iap, 0x78) && host.MemoryRead32(iap) == 3) {
            std::lock_guard<std::mutex> lock(g_purchase_lock);
            if (!g_purchase_iap) {
                g_purchase_iap = iap;
                g_purchase_amount = amount;
                accepted = true;
            }
        }
        jit.Regs()[0] = accepted ? 0u : uint32_t(-1);
        jit.Regs()[15] = jit.Regs()[14];
    });
    thunks.RegisterThunk("mc4_settings_qa", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        const uint32_t manager = host.MemoryRead32(base + 0x17b5e8c);
        if (GuestRange(host, manager, 0x20)) {
            g_qa_advanced_request = true;
            g_qa_active = true;
            g_qa_refresh = g_qa_reenter ? 2 : 0;
            g_qa_refresh_general = false;
            g_qa_owner_manager = manager;
            g_qa_owner_root = host.MemoryRead32(manager + 0x1c);
            host.RunFunction(base + (g_qa_reenter ? 0x5ce17c : 0x5cda54),
                             {manager, base + 0x1606b48, uint32_t(-1)});
        }
        g_qa_reenter = false;
        jit.Regs()[15] = jit.Regs()[14];
    });
    thunks.RegisterThunk("mc4_qa_advanced", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        if (g_qa_advanced_request) {
            g_qa_advanced_request = false;
            g_qa_advanced_response = true;
            g_qa_refresh = 0;
            jit.Regs()[15] = base + 0x76e5a0;
        } else {
            g_qa_refresh = 0;
            g_qa_advanced_response = false;
            g_qa_active = false;
            g_qa_rows_active = false;
            g_qa_hint_pending = false;
            ContinuePush(jit, host, 0x4ff0, base + 0x76d338);
        }
    });
    thunks.RegisterThunk("mc4_qa_advanced_response", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = host.GetElfLoader().GetBaseAddress();
        if (g_qa_advanced_response) {
            g_qa_advanced_response = false;
            g_qa_rows_active = true;
            g_qa_clip_refresh = 8;
#if MC4_ENABLE_NATIVE_LOGGING
            g_qa_selection_refresh = 60;
#endif
            jit.Regs()[1] = base + 0x16015a4;
        } else jit.Regs()[1] += base + 0x76fcdc + 8;
        jit.Regs()[15] = base + 0x76fce0;
    });
    thunks.RegisterThunk("mc4_qa_event", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t character = jit.Regs()[0], event = jit.Regs()[1];
        const uint32_t info_row = GuestRange(host, character, 0x50) ? host.MemoryRead32(character + 0x48) : 0;
        if (GuestRange(host, event, 0x4c)) {
            const uint8_t tag = host.MemoryRead8(event + 0x38);
            const std::string type = tag == 8 || tag == 10 || tag == 6 || tag == 255 ?
                GuestAsString(host, event + 0x38) : std::string{};
            if (type == "mouseUp" || (g_qa_active && (type == "click" || type == "mouseDown"))) {
                if (type == "mouseDown") g_qa_hint_pending = false;
                std::string path;
                const std::string leaf = GuestRange(host, character, 0x50) ?
                    GuestAsString(host, host.MemoryRead32(character + 0x4c)) : std::string{};
                for (unsigned n = 0; n < 8 && GuestRange(host, character, 0x50); ++n) {
                    const std::string name = GuestAsString(host, host.MemoryRead32(character + 0x4c));
#if MC4_ENABLE_NATIVE_LOGGING
                    static unsigned inventories = 0;
                    if (g_qa_rows_active && type == "mouseUp" && leaf == "infos_btn" &&
                        (name == "options_list" || name == "menu_advanced") && inventories++ < 4 &&
                        GuestRange(host, character, 0xec)) {
                        const uint32_t base = host.GetElfLoader().GetBaseAddress();
                        const uint32_t vtable = host.MemoryRead32(character);
                        const uint32_t is_type = GuestRange(host, vtable, 12) ? host.MemoryRead32(vtable + 8) : 0;
                        const uint32_t aux = host.MemoryRead32(character + 0x5c);
                        const uint32_t mask = GuestRange(host, aux, 0x94) ? host.MemoryRead32(aux + 0x90) : 0;
                        LOGI("[QA-CLIP] owner=%s char=%08X type=%08X mask=%08X", name.c_str(), character, is_type, mask);
                        if (is_type == base + 0x1055600 || is_type == base + 0xfe0e58) {
                            const uint32_t children = host.MemoryRead32(character + 0xe4);
                            const uint32_t count = host.MemoryRead32(character + 0xe8);
                            if (count <= 32 && GuestRange(host, children, count * 4)) {
                                for (uint32_t i = 0; i < count; ++i) {
                                    const uint32_t child = host.MemoryRead32(children + i * 4);
                                    if (GuestRange(host, child, 0x50))
                                        LOGI("[QA-CLIP] child=%08X name=%s", child,
                                            GuestAsString(host, host.MemoryRead32(child + 0x4c)).c_str());
                                }
                            }
                        }
                    }
#endif
                    path = name + (path.empty() ? "" : "." + path);
                    if (path.size() > 256) break;
                    const uint32_t proxy = host.MemoryRead32(character + 0x44);
                    if (!GuestRange(host, proxy, 3) || !host.MemoryRead8(proxy + 2)) break;
                    character = host.MemoryRead32(character + 0x48);
                }
                if (g_qa_rows_active && type == "mouseUp" && leaf == "infos_btn" &&
                    path.find(".menu_advanced.options_list.") != std::string::npos) {
                    g_qa_hint_option = QaInfoOption(host, info_row);
                    g_qa_hint_pending = g_qa_hint_option != 0;
                }
                if (type == "mouseUp" && leaf == "opt6_btn" &&
                    path.find(".mc_btns.") != std::string::npos)
                    g_qa_reenter = path.find(".menu_advanced.mc_btns.") != std::string::npos;
                if (g_qa_active && type == "mouseUp" && path.find(".menu_advanced.mc_btns.") != std::string::npos &&
                    leaf.size() == 8 && leaf.compare(0, 3, "opt") == 0 &&
                    leaf.compare(4, 4, "_btn") == 0 && leaf[3] >= '0' && leaf[3] <= '5') {
                    g_qa_advanced_request = false;
                    g_qa_advanced_response = false;
                    g_qa_active = false;
                    g_qa_rows_active = false;
                    g_qa_hint_pending = false;
                    g_qa_clip_refresh = 8;
#if MC4_ENABLE_NATIVE_LOGGING
                    g_qa_selection_refresh = 0;
#endif
                    // General and QA share menu_advanced; selecting General may
                    // leave that SWF cached without another settings request.
                    g_qa_refresh_general = leaf[3] == '1';
                    g_qa_refresh = g_qa_refresh_general ? 2 : 0;
                    if (g_qa_refresh_general) {
                        const uint32_t base = host.GetElfLoader().GetBaseAddress();
                        host.RunFunction(base + 0x5ce17c,
                            {g_qa_owner_manager, base + 0x1606b48, uint32_t(-1)});
                    }
                }
#if MC4_ENABLE_NATIVE_LOGGING
                static unsigned count = 0;
                if (count++ < 256) LOGI("[QA-EVENT] type=%s path=%s", type.c_str(), path.c_str());
#endif
            }
        }
        ContinuePush(jit, host, 0x4070, host.GetElfLoader().GetBaseAddress() + 0xf6a8a0);
    });
#if MC4_ENABLE_NATIVE_LOGGING
    thunks.RegisterThunk("mc4_qa_member_trace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static unsigned count = 0;
        const uint32_t value = jit.Regs()[1];
        if (g_qa_active && count < 128 && GuestAsString(host, jit.Regs()[8]) == "id" &&
            GuestRange(host, value, 12) && host.MemoryRead8(value) == 2) {
            double id;
            memcpy(&id, host.GetGuestMemoryBase() + value + 4, sizeof(id));
            LOGI("[QA-MEMBER] object=%08X id=%g", jit.Regs()[6], id);
            ++count;
        }
        jit.Regs()[0] = jit.Regs()[9];
        jit.Regs()[15] = host.GetElfLoader().GetBaseAddress() + 0xfa6348;
    });
#endif
}

// --- install entry (phase3_vfs.c:1450-1485) ---
void Phase3VfsInstall(DynarmicHost& host, const char* apk_path, const char* obb_dir) {
    if (g_installed.load()) return;
    char mode[PROP_VALUE_MAX];
    if (__system_property_get("debug.mc4.phase3", mode) > 0 && strcmp(mode, "off") == 0) {
        LOGI("phase3 VFS disabled by debug.mc4.phase3=off");
        return;
    }
    Phase3RegisterThunks(host);
    if (apk_path && *apk_path) {
        g_apk_path = apk_path;
    } else if (!FindApkPath()) {
        LOGE("phase3 VFS blocked: cannot find base APK path");
        return;
    }
    if (!ParseApkAssets(obb_dir)) return;
    if (!InstallAudioApi(host)) return;
    if (!InstallTouchResponse(host)) return;
    if (!InstallCheatGate(host))
        LOGE("phase3 VFS: native cheat gate unavailable; original menu remains fail-closed");
    if (!InstallIapRoute(host))
        LOGE("phase3 VFS: native IAB local route unavailable; store remains original");
    g_installed = 1;
    LOGI("phase3 VFS installed: unpacked APK assets -> virtual ZIP; APK fd=%d virtual_size=%lld",
         g_archive.apk_fd, (long long)g_archive.size);
}

bool Phase3Installed() { return g_installed.load() != 0; }

// Historical phase-5 diagnostic override. The PerformanceProfile is embedded
// at app+864. The diagnostic caller serializes against RunFunctionAt with the
// host mutex; independent worker-core guest execution is not covered here.
bool Phase3ForceMaxQuality(DynarmicHost& host) {
    constexpr uint32_t kAppInstanceOffset = 0x17B7D88u;
    const uint64_t app_slot = static_cast<uint64_t>(host.GetElfLoader().GetBaseAddress()) +
                              kAppInstanceOffset;
    const size_t guest_size = host.GetGuestMemorySize();
    if (app_slot + sizeof(uint32_t) > guest_size) return false;

    const uint32_t app = host.MemoryRead32(static_cast<uint32_t>(app_slot));
    constexpr uint32_t kProfileBase = 864u;
    constexpr uint32_t kLastField = kProfileBase + 101u;
    if (!app || static_cast<uint64_t>(app) + kLastField >= guest_size) return false;

    host.MemoryWrite32(app + 912u, 0x3f800000u);
    host.MemoryWrite8(app + 927u, 0);
    host.MemoryWrite32(app + kProfileBase + 48u, 0x3f800000u);
    host.MemoryWrite8(app + kProfileBase + 60u, 1);
    host.MemoryWrite8(app + kProfileBase + 68u, 1);
    host.MemoryWrite8(app + kProfileBase + 69u, 1);
    host.MemoryWrite8(app + kProfileBase + 71u, 1);
    host.MemoryWrite8(app + kProfileBase + 76u, 0);
    host.MemoryWrite8(app + kProfileBase + 80u, 1);
    host.MemoryWrite8(app + kProfileBase + 101u, 1);
    return true;
}

}  // namespace mc4
