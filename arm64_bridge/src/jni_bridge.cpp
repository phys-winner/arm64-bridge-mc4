// MC4 arm32-to-arm64 bridge, JNI entry points.
//
// Java loads exactly one native library ("ModernCombat4") — this bridge. The
// 32-bit game library itself runs under the Dynarmic JIT; libphase3vfs.so and
// libofflinecheats.so are NOT loaded as guests: their behavior lives here as
// host code (mc4_phase3.cpp / mc4_cheats.cpp), so the Java contract
// (MC4.loadLib -> phase3VfsInstall, OfflineCatalog.ensureNative ->
// gateSelfTest, OfflineCheatBridge.apply/...) is unchanged.
//
// Guest Java_* exports are registered per class as host natives that marshal
// into RunFunction(guest_symbol, {FakeEnv(), clazz, args...}) — the guest
// sees the same JNIEnv* / jobject / jint arguments the original
// System.loadLibrary build gave it. Marshalling follows softfp AAPCS:
// floats as raw bits in r0-r3, 64-bit args in even-aligned pairs or on the
// stack at sp+0/sp+4.

#include <jni.h>
#include <GLES2/gl2.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <array>
#include <thread>
#include <unordered_map>
#include <cstring>
#include <cstdio>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "jni_fake_env.h"
#include "thunks_glstat.h"
#include "thunks_opensles.h"
#include "mc4_phase3.h"
#include "mc4_cheats.h"

#define LOG_TAG "Arm32Bridge_JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" int IndexApk(const char* apk_path);

std::unique_ptr<DynarmicHost> g_host;
JavaVM* g_jvm = nullptr;
JavaVM* GetHostJavaVM() { return g_jvm; }

// Guest worker threads must attach to the JVM before any JNI use; the fake
// env's stored host env is then refreshed to this thread's JNIEnv.
// ART safepoint check for long-running guest JIT threads: makes a trivial
// JNI call that transitions through JniMethodEnd, triggering the ART
// safepoint/garbage-collector check. Without this, worker threads doing
// pure guest JIT execution never yield to the GC and the GLThread blocks
// forever at GoToRunnable (the 2026-09-18 loader hang).
void BridgeSafepointCheck() {
    if (!g_jvm) return;
    JNIEnv* env = nullptr;
    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env)
        return;
    env->ExceptionCheck();
}

void BridgeAttachCurrentThread() {
    if (!g_jvm) return;
    JNIEnv* env = nullptr;
    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK)
        return;
    if (g_jvm->AttachCurrentThread(&env, nullptr) == JNI_OK && env)
        FakeJniEnv::Instance().AttachHostEnv(env);
}
std::string g_saved_apk_path;
std::string g_saved_files_dir;

static uint32_t FakeEnv() { return FakeJniEnv::Instance().EnvTableGuestAddr(); }

// jobject/jclass host pointers are 64-bit; the guest sees a 32-bit handle.
// The fake env interns objects and hands out handles, so marshal every
// reference through it. Java's static natives can arrive before any guest
// symbol exists; class objects are interned like any other.
static uint32_t J(jobject o) {
    return o ? FakeJniEnv::Instance().AddObjectRef(o) : 0;
}

// Softfp: a jfloat argument travels as its raw IEEE-754 bits in a 32-bit
// register. (thunk_types.h WriteSF writes into jit registers, not values.)
static uint32_t F(jfloat v) {
    uint32_t bits;
    memcpy(&bits, &v, sizeof(bits));
    return bits;
}

static std::unordered_map<std::string, uint32_t> g_guest_syms;

static uint32_t GuestSym(const char* name) {
    auto it = g_guest_syms.find(name);
    if (it != g_guest_syms.end()) return it->second;
    uint32_t a = g_host ? g_host->GetElfLoader().GetSymbolAddress(name) : 0;
    if (a) LOGI("guest native %s -> 0x%08X", name, a);
    else LOGE("guest native not exported: %s", name);
    g_guest_syms[name] = a;
    return a;
}

// Guest jstring handle (from env->NewStringUTF) -> host jstring; a raw guest
// char* is re-wrapped as a fallback.
static jstring ResolveGuestJString(JNIEnv* env, uint32_t handle) {
    if (!g_host || !handle) return nullptr;
    if (jobject o = FakeJniEnv::Instance().ResolveObject(handle)) {
        return static_cast<jstring>(o);
    }
    const char* s = reinterpret_cast<const char*>(
        GuestToHost(g_host->GetGuestMemoryBase(), handle));
    return s ? env->NewStringUTF(s) : nullptr;
}

// ---------------------------------------------------------------------------
// Guest loading
// ---------------------------------------------------------------------------

static std::vector<std::string> ApkCandidates(const char* lib) {
    return {std::string("assets/guest_libs/") + lib,
            std::string("lib/armeabi-v7a/") + lib};
}

static bool ExtractFromApk(const std::string& apk_path,
                           const std::vector<std::string>& candidate_names,
                           std::vector<uint8_t>& out_data) {
    // ZIP reader for STORED entries (packaging keeps the guest lib
    // uncompressed). DEFLATED guest libs are rejected loudly.
    if (apk_path.empty()) return false;
    int fd = open(apk_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOGE("ExtractFromApk: Failed to open APK: %s", apk_path.c_str());
        return false;
    }

    off_t file_len = lseek(fd, 0, SEEK_END);
    if (file_len < 22) { close(fd); return false; }
    off_t search_len = file_len < 65536 + 22 ? file_len : 65536 + 22;
    off_t search_start = file_len - search_len;
    std::vector<uint8_t> buf(search_len);
    pread(fd, buf.data(), search_len, search_start);

    off_t eocd_offset = -1;
    for (ssize_t i = search_len - 22; i >= 0; --i) {
        if (buf[i] == 0x50 && buf[i + 1] == 0x4b && buf[i + 2] == 0x05 && buf[i + 3] == 0x06) {
            eocd_offset = search_start + i;
            break;
        }
    }
    if (eocd_offset < 0) { close(fd); return false; }

    uint8_t eocd[22];
    pread(fd, eocd, 22, eocd_offset);
    uint16_t num_entries = *reinterpret_cast<uint16_t*>(eocd + 10);
    uint32_t cd_size = *reinterpret_cast<uint32_t*>(eocd + 12);
    uint32_t cd_offset = *reinterpret_cast<uint32_t*>(eocd + 16);

    std::vector<uint8_t> cd(cd_size);
    pread(fd, cd.data(), cd_size, cd_offset);

    uint32_t pos = 0;
    for (int i = 0; i < num_entries && pos + 46 <= cd_size; ++i) {
        if (*reinterpret_cast<uint32_t*>(cd.data() + pos) != 0x02014b50) break;
        uint16_t method = *reinterpret_cast<uint16_t*>(cd.data() + pos + 10);
        uint32_t csize = *reinterpret_cast<uint32_t*>(cd.data() + pos + 20);
        uint32_t usize = *reinterpret_cast<uint32_t*>(cd.data() + pos + 24);
        uint16_t fn_len = *reinterpret_cast<uint16_t*>(cd.data() + pos + 28);
        uint16_t extra_len = *reinterpret_cast<uint16_t*>(cd.data() + pos + 30);
        uint16_t comm_len = *reinterpret_cast<uint16_t*>(cd.data() + pos + 32);
        uint32_t local_hdr_offset = *reinterpret_cast<uint32_t*>(cd.data() + pos + 42);

        std::string entry_name(reinterpret_cast<char*>(cd.data() + pos + 46), fn_len);
        for (const auto& cand : candidate_names) {
            if (entry_name != cand) continue;
            uint8_t local_hdr[30];
            pread(fd, local_hdr, 30, local_hdr_offset);
            uint16_t l_fn_len = *reinterpret_cast<uint16_t*>(local_hdr + 26);
            uint16_t l_extra_len = *reinterpret_cast<uint16_t*>(local_hdr + 28);
            off_t raw_offset = local_hdr_offset + 30 + l_fn_len + l_extra_len;
            if (method == 0) {  // STORED
                out_data.resize(usize);
                if (pread(fd, out_data.data(), usize, raw_offset) != (ssize_t)usize) {
                    LOGE("ExtractFromApk: short read for %s", entry_name.c_str());
                    out_data.clear();
                    close(fd);
                    return false;
                }
                LOGI("Found candidate in APK: %s (size %u)", entry_name.c_str(), usize);
                close(fd);
                return true;
            }
            close(fd);
            LOGE("ExtractFromApk: guest lib %s is compressed (method=%u)", cand.c_str(), method);
            return false;
        }
        pos += 46 + fn_len + extra_len + comm_len;
    }
    close(fd);
    return false;
}

// APK path fallback when setPaths has not run yet: the process always maps
// its own base.apk (same /proc/self/maps walk the phase3 VFS uses).
static bool FindApkPathFromMaps() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    char line[4096];
    bool found = false;
    while (fgets(line, sizeof(line), maps)) {
        const char* hit = strstr(line, "/base.apk");
        if (!hit) continue;
        const char* start = hit;
        while (start > line && start[-1] != ' ') --start;
        const char* end = hit + strlen("/base.apk");
        while (*end && *end != ' ' && *end != '\r' && *end != '\n') ++end;
        if ((size_t)(end - start) > 0) {
            g_saved_apk_path.assign(start, (size_t)(end - start));
            found = true;
            break;
        }
    }
    fclose(maps);
    return found;
}

static std::mutex g_load_mutex;
static std::atomic<bool> g_cache_unavailable{false};
// Resolve the app-owned external OBB directory through Android's Context API.
// MC4.c is published in onCreate before the game's loadLib() call.
static std::string GetAppObbDir(JNIEnv* env) {
    jclass cls = env->FindClass("com/gameloft/android/ANMP/GloftM4HM/MC4");
    if (!cls) { env->ExceptionClear(); return {}; }
    jfieldID field = env->GetStaticFieldID(
        cls, "c", "Lcom/gameloft/android/ANMP/GloftM4HM/MC4;");
    if (!field) { env->ExceptionClear(); env->DeleteLocalRef(cls); return {}; }
    jobject activity = env->GetStaticObjectField(cls, field);
    env->DeleteLocalRef(cls);
    if (!activity) return {};
    jclass activity_class = env->GetObjectClass(activity);
    jmethodID get_obb_dir = env->GetMethodID(activity_class, "getObbDir", "()Ljava/io/File;");
    if (!get_obb_dir) {
        env->ExceptionClear();
        env->DeleteLocalRef(activity_class);
        env->DeleteLocalRef(activity);
        return {};
    }
    jobject file = env->CallObjectMethod(activity, get_obb_dir);
    env->DeleteLocalRef(activity_class);
    env->DeleteLocalRef(activity);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return {}; }
    if (!file) return {};
    jclass file_class = env->GetObjectClass(file);
    jmethodID get_path = env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
    if (!get_path) {
        env->ExceptionClear();
        env->DeleteLocalRef(file_class);
        env->DeleteLocalRef(file);
        return {};
    }
    jstring path = static_cast<jstring>(env->CallObjectMethod(file, get_path));
    env->DeleteLocalRef(file_class);
    env->DeleteLocalRef(file);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return {}; }
    if (!path) return {};
    const char* chars = env->GetStringUTFChars(path, nullptr);
    std::string result = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(path, chars);
    env->DeleteLocalRef(path);
    LOGI("Android getObbDir: %s", result.empty() ? "<unavailable>" : result.c_str());
    return result;
}

static bool EnsureGameLoaded(JNIEnv* env) {
    // Two Java threads can reach their first native simultaneously; serialize
    // the load so the second waits for a fully-initialized host instead of
    // racing a half-built one (or re-creating a host the first thread is
    // still populating).
    std::lock_guard<std::mutex> load_lock(g_load_mutex);
    auto ensure_vfs = [&]() -> bool {
        if (mc4::Phase3Installed()) return true;
        // A missing/corrupt source is a launch-time configuration error. The
        // legacy installer invokes several natives in a tight loop; parsing
        // the APK and hashing a bad OBB again cannot make that run recover.
        if (g_cache_unavailable.load()) return false;
        const std::string obb_dir = GetAppObbDir(env);
        mc4::Phase3VfsInstall(*g_host,
                              g_saved_apk_path.empty() ? nullptr : g_saved_apk_path.c_str(),
                              obb_dir.c_str());
        if (!mc4::Phase3Installed()) {
            g_cache_unavailable = true;
            LOGE("guest startup blocked: phase3 virtual filesystem is not ready");
            return false;
        }
        return true;
    };
    if (g_host) return ensure_vfs();
    if (g_saved_apk_path.empty() && !FindApkPathFromMaps()) {
        LOGE("APK path unknown (setPaths not called, /proc/self/maps miss)");
    }

    g_host = std::make_unique<DynarmicHost>();
    if (!g_host->Initialize()) {
        LOGE("Failed to initialize Dynarmic host");
        g_host.reset();
        return false;
    }

    constexpr const char* kGuestLib = "libModernCombat4.so";

    // 1. Loose .so for fast iteration: adb push the rebuilt guest library.
    const char* base_dirs[] = {g_saved_files_dir.c_str(), "/data/local/tmp", "/sdcard"};
    bool loaded = false;
    for (const char* dir : base_dirs) {
        if (!dir || !*dir) continue;
        std::string game = std::string(dir) + "/" + kGuestLib;
        if (access(game.c_str(), R_OK) != 0) continue;
        loaded = g_host->LoadGame(game);
        LOGI("Load from %s: %s", dir, loaded ? "ok" : "failed");
        if (loaded) break;
    }

    // 2. Out of the APK (shipping path). IndexApk lets thunks_libc stream
    // STORED assets straight from the APK file.
    if (!loaded && !g_saved_apk_path.empty()) {
        std::vector<uint8_t> game_data;
        if (ExtractFromApk(g_saved_apk_path, ApkCandidates(kGuestLib), game_data)) {
            IndexApk(g_saved_apk_path.c_str());
            loaded = g_host->LoadGameFromMemory(game_data.data(), game_data.size());
            LOGI("Load from APK: %s", loaded ? "ok" : "failed");
        }
    }

    if (!loaded) {
        LOGE("Could not locate or extract %s", kGuestLib);
        g_host.reset();
        return false;
    }

    FakeJniEnv& fj = FakeJniEnv::Instance();
    fj.SetJavaVM(g_jvm);
    fj.Init(*g_host);
    fj.AttachHostEnv(env);

    // System.loadLibrary calls JNI_OnLoad after relocation; do the same with
    // the fake VM table (32-bit guest cannot hold the real 64-bit vm pointer).
    uint32_t on_load = g_host->GetElfLoader().GetSymbolAddress("JNI_OnLoad");
    if (on_load) {
        uint32_t ver = g_host->RunFunction(on_load, {fj.VmTableGuestAddr(), 0});
        LOGI("Guest JNI_OnLoad -> 0x%08X", ver);
    }

    mc4::Phase3SetJavaVM(g_jvm);
    mc4::Phase3RegisterThunks(*g_host);
    // MC4.loadLib is reached only after the installer and GL activity have
    // begun guest work. Install the APK-backed OBB filesystem here, before the
    // first forwarded guest JNI export can enter data-pack initialization.
    return ensure_vfs();
}

// ---------------------------------------------------------------------------
// Forwarding macro family. NULL jstrings pass a 0 handle (guests null-check).
// ---------------------------------------------------------------------------

#define GUEST_RUN(sym, ...) g_host->RunFunction(sym, __VA_ARGS__)

#define GUEST_VOID_0(name, guest)                                                    \
    static void name(JNIEnv* env, jclass clazz) {                                    \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest)) GUEST_RUN(s, {FakeEnv(), J(clazz)});          \
    }
#define GUEST_VOID_1I(name, guest)                                                   \
    static void name(JNIEnv* env, jclass clazz, jint a) {                            \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest)) GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a}); \
    }
#define GUEST_VOID_2I(name, guest)                                                   \
    static void name(JNIEnv* env, jclass clazz, jint a, jint b) {                    \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a, (uint32_t)b});              \
    }
#define GUEST_VOID_3I(name, guest)                                                   \
    static void name(JNIEnv* env, jclass clazz, jint a, jint b, jint c) {            \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a, (uint32_t)b, (uint32_t)c}); \
    }
#define GUEST_VOID_4I(name, guest)                                                   \
    static void name(JNIEnv* env, jclass clazz, jint a, jint b, jint c, jint d) {    \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a, (uint32_t)b, (uint32_t)c,   \
                              (uint32_t)d});                                         \
    }
#define GUEST_VOID_1IZ(name, guest)                                                  \
    static void name(JNIEnv* env, jclass clazz, jint a, jboolean b) {                \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a, (uint32_t)(b ? 1 : 0)});    \
    }
#define GUEST_VOID_1Z(name, guest)                                                   \
    static void name(JNIEnv* env, jclass clazz, jboolean b) {                        \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)(b ? 1 : 0)});                 \
    }
// (FFF)V softfp: three raw float words in r2-r4 (r0=env, r1=clazz).
#define GUEST_VOID_3F(name, guest)                                                   \
    static void name(JNIEnv* env, jclass clazz, jfloat x, jfloat y, jfloat z) {      \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), F(x), F(y), F(z)});    \
    }
// (FFI)V softfp: two float words then an int.
#define GUEST_VOID_FFI(name, guest)                                                  \
    static void name(JNIEnv* env, jclass clazz, jfloat x, jfloat y, jint z) {        \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), F(x), F(y), (uint32_t)z});   \
    }
// (IFFI)V softfp: int, float, float, int.
#define GUEST_VOID_IFFI(name, guest)                                                 \
    static void name(JNIEnv* env, jclass clazz, jint a, jfloat x, jfloat y, jint z) {\
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a, F(x), F(y),     \
                              (uint32_t)z});                                         \
    }
#define GUEST_VOID_1STR(name, guest)                                                 \
    static void name(JNIEnv* env, jclass clazz, jstring str) {                       \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest)) {                                          \
            uint32_t h = str ? FakeJniEnv::Instance().AddObjectRef(str) : 0;         \
            GUEST_RUN(s, {FakeEnv(), J(clazz), h});                                     \
        }                                                                            \
    }
#define GUEST_INT_0(name, guest)                                                     \
    static jint name(JNIEnv* env, jclass clazz) {                                    \
        if (!EnsureGameLoaded(env)) return 0;                                        \
        if (uint32_t s = GuestSym(guest))                                            \
            return (jint)GUEST_RUN(s, {FakeEnv(), J(clazz)});                           \
        return 0;                                                                    \
    }
#define GUEST_INT_1I(name, guest)                                                    \
    static jint name(JNIEnv* env, jclass clazz, jint a) {                            \
        if (!EnsureGameLoaded(env)) return 0;                                        \
        if (uint32_t s = GuestSym(guest))                                            \
            return (jint)GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a});              \
        return 0;                                                                    \
    }
#define GUEST_Z_0(name, guest)                                                       \
    static jboolean name(JNIEnv* env, jclass clazz) {                                \
        if (!EnsureGameLoaded(env)) return JNI_FALSE;                                \
        if (uint32_t s = GuestSym(guest))                                            \
            return GUEST_RUN(s, {FakeEnv(), J(clazz)}) ? JNI_TRUE : JNI_FALSE;          \
        return JNI_FALSE;                                                            \
    }
#define GUEST_Z_1I(name, guest)                                                      \
    static jboolean name(JNIEnv* env, jclass clazz, jint a) {                        \
        if (!EnsureGameLoaded(env)) return JNI_FALSE;                                \
        if (uint32_t s = GuestSym(guest))                                            \
            return GUEST_RUN(s, {FakeEnv(), J(clazz), (uint32_t)a}) ? JNI_TRUE : JNI_FALSE; \
        return JNI_FALSE;                                                            \
    }
#define GUEST_STR_0(name, guest)                                                     \
    static jstring name(JNIEnv* env, jclass clazz) {                                 \
        if (!EnsureGameLoaded(env)) return nullptr;                                  \
        if (uint32_t s = GuestSym(guest))                                            \
            return ResolveGuestJString(env, GUEST_RUN(s, {FakeEnv(), J(clazz)}));       \
        return nullptr;                                                              \
    }

// --- instance (jobject) variants ---
#define GUEST_VOID_0_OBJ(name, guest)                                                \
    static void name(JNIEnv* env, jobject obj) {                                     \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest)) GUEST_RUN(s, {FakeEnv(), J(obj)});            \
    }
#define GUEST_VOID_1I_OBJ(name, guest)                                               \
    static void name(JNIEnv* env, jobject obj, jint a) {                             \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest)) GUEST_RUN(s, {FakeEnv(), J(obj), (uint32_t)a}); \
    }
#define GUEST_VOID_2I_OBJ(name, guest)                                               \
    static void name(JNIEnv* env, jobject obj, jint a, jint b) {                     \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(obj), (uint32_t)a, (uint32_t)b});                \
    }
#define GUEST_STR_0_OBJ(name, guest)                                                 \
    static jstring name(JNIEnv* env, jobject obj) {                                  \
        if (!EnsureGameLoaded(env)) return nullptr;                                  \
        if (uint32_t s = GuestSym(guest))                                            \
            return ResolveGuestJString(env, GUEST_RUN(s, {FakeEnv(), J(obj)}));         \
        return nullptr;                                                              \
    }
#define GUEST_STR_1I_OBJ(name, guest)                                                \
    static jstring name(JNIEnv* env, jobject obj, jint a) {                          \
        if (!EnsureGameLoaded(env)) return nullptr;                                  \
        if (uint32_t s = GuestSym(guest))                                            \
            return ResolveGuestJString(env, GUEST_RUN(s, {FakeEnv(), J(obj), (uint32_t)a})); \
        return nullptr;                                                              \
    }
#define GUEST_Z_1STR_OBJ(name, guest)                                                \
    static jboolean name(JNIEnv* env, jobject obj, jstring str) {                    \
        if (!EnsureGameLoaded(env)) return JNI_FALSE;                                \
        if (uint32_t s = GuestSym(guest)) {                                          \
            uint32_t h = str ? FakeJniEnv::Instance().AddObjectRef(str) : 0;         \
            return GUEST_RUN(s, {FakeEnv(), J(obj), h}) ? JNI_TRUE : JNI_FALSE;         \
        }                                                                            \
        return JNI_FALSE;                                                            \
    }
// (J)V instance: jlong fits r2:r3.
#define GUEST_VOID_1_LONG_OBJ(name, guest)                                           \
    static void name(JNIEnv* env, jobject obj, jlong v) {                            \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(obj), (uint32_t)v, (uint32_t)(v >> 32)});        \
    }
// (IJ)V instance: jint in r2, then the jlong cannot take r3 (odd) -> stack
// sp+0/sp+4; r3 is a pad word.
#define GUEST_VOID_1I_LONG_OBJ(name, guest)                                          \
    static void name(JNIEnv* env, jobject obj, jint a, jlong v) {                    \
        if (!EnsureGameLoaded(env)) return;                                          \
        if (uint32_t s = GuestSym(guest))                                            \
            GUEST_RUN(s, {FakeEnv(), J(obj), (uint32_t)a, 0, (uint32_t)v,               \
                              (uint32_t)(v >> 32)});                                 \
    }
// (J)I instance.
#define GUEST_INT_1_LONG_OBJ(name, guest)                                            \
    static jint name(JNIEnv* env, jobject obj, jlong v) {                            \
        if (!EnsureGameLoaded(env)) return 0;                                        \
        if (uint32_t s = GuestSym(guest))                                            \
            return (jint)GUEST_RUN(s, {FakeEnv(), J(obj), (uint32_t)v, (uint32_t)(v >> 32)}); \
        return 0;                                                                    \
    }

// ---------------------------------------------------------------------------
// GL2JNILib — com.gameloft.glf.GL2JNILib (all static)
// ---------------------------------------------------------------------------

GUEST_VOID_0(GL2_initGL, "Java_com_gameloft_glf_GL2JNILib_initGL")
GUEST_VOID_0(GL2_InitViewSettings, "Java_com_gameloft_glf_GL2JNILib_InitViewSettings")

// Bring-up probe: Java-side retry loops show up here as a climbing init
// counter or a step counter that resets. Remove with phase-7 diagnostics.
static std::atomic<uint32_t> s_gl2_init_calls{0};
// set when the root-movie sprite is known to be advancing (STAGENOTIFY);
// gates MMLOAD so guest code never runs before the movie stage is alive.

static void GL2_init(JNIEnv* env, jclass clazz) {
    uint32_t n = s_gl2_init_calls.fetch_add(1, std::memory_order_relaxed) + 1;
    LOGI("[LOOP-PROBE] init call #%u", n);
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_glf_GL2JNILib_init")) {
        uint32_t r = GUEST_RUN(s, {FakeEnv(), J(clazz)});
        LOGI("[INIT-TAIL] init returned r=%08X tail: %s", r,
             FakeJniEnv::Instance().JniDispatchTail().c_str());
    }
}


static std::mutex s_touch_mutex;
static std::vector<std::array<jint, 4>> s_touch_events;

static void GL2_touchEvent(JNIEnv*, jclass, jint action, jint x, jint y, jint id) {
    if (action < 0 || action > 2 || id < 0 || id > 31) return;
    std::lock_guard<std::mutex> lock(s_touch_mutex);
    s_touch_events.push_back({action, x, y, id});
}

static void FlushTouchEvents(JNIEnv*, jclass clazz) {
    if (!g_host) return;
    std::vector<std::array<jint, 4>> events;
    {
        std::lock_guard<std::mutex> lock(s_touch_mutex);
        events.swap(s_touch_events);
    }
    if (events.empty()) return;
    static const uint32_t symbol = g_host->GetElfLoader().GetSymbolAddress(
        "Java_com_gameloft_glf_GL2JNILib_touchEvent");
    if (!symbol) return;
    const uint32_t cls = J(clazz), fake_env = FakeEnv();
    for (const auto& event : events) {
#if MC4_ENABLE_NATIVE_LOGGING
        static bool fixture_active = false;
        static unsigned fixture_samples = 0;
        if (event[3] == 7 || event[3] == 19) fixture_active = true;
        if (fixture_active && fixture_samples++ < 64)
            LOGI("[TOUCH-FIFO] action=%d x=%d y=%d id=%d", event[0], event[1], event[2], event[3]);
#endif
        g_host->RunFunction(symbol, {fake_env, cls, (uint32_t)event[0],
                            (uint32_t)event[1], (uint32_t)event[2], (uint32_t)event[3]});
    }
}

static void GL2_step(JNIEnv* env, jclass clazz) {
    if (!g_host) return;
    g_host->DrainDeferred();
    // GL2_step is called for every rendered frame; this guest export is
    // immutable for the lifetime of the loaded guest ELF. Avoid rebuilding
    // and hashing its long std::string key on the render thread each frame.
    static std::atomic<uint32_t> cached_step_symbol{0};
    uint32_t symbol = cached_step_symbol.load(std::memory_order_relaxed);
    if (!symbol) {
        symbol = GuestSym("Java_com_gameloft_glf_GL2JNILib_step");
        if (symbol) cached_step_symbol.store(symbol, std::memory_order_relaxed);
    }
    if (symbol) {
        FlushTouchEvents(env, clazz);
        const std::array<uint32_t, 2> args{FakeEnv(), J(clazz)};
        g_host->RunFunction(symbol, std::span<const uint32_t>(args));
        mc4::Phase3PumpLocalUi(*g_host);
#if MC4_GL_TIMING_ENABLED
        static unsigned frames = 0;
        static auto started = std::chrono::steady_clock::now();
        if (++frames % 128 == 0) {
            const auto now = std::chrono::steady_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - started).count();
            started = now;
            const uint32_t slot = g_host->FindSymbol("_ZN11Application10s_instanceE");
            const uint32_t app = slot ? g_host->MemoryRead32(slot) : 0;
            const uint32_t driver = GuestRangeValid(g_host->GetGuestMemorySize(), app, 0x360)
                ? g_host->MemoryRead32(app + 0x35c) : 0;
            const uint32_t fps = GuestRangeValid(g_host->GetGuestMemorySize(), driver, 0x1a8)
                ? g_host->MemoryRead32(driver + 0x78) : 0;
            LOGI("[FRAME-PERF] steps=128 wall_ms=%lld swaps=%u draws=%u+%u native_fps=%u",
                 (long long)elapsed, glstat::g_n[glstat::Swap].exchange(0),
                 glstat::g_n[glstat::DrawArrays].exchange(0),
                 glstat::g_n[glstat::DrawElements].exchange(0), fps);
#if MC4_ENABLE_NATIVE_LOGGING
            g_host->GetThunkManager().DumpThreadProfile();
#endif
            char timing[512] = {};
            size_t used = 0;
            for (int category = 0; category < glstat::TIME_COUNT && used < sizeof(timing) - 64; ++category) {
                const auto calls = glstat::g_time_calls[category].exchange(0);
                const auto ns = glstat::g_time_ns[category].exchange(0);
                used += snprintf(timing + used, sizeof(timing) - used, " %s:%u/%lluus",
                                 glstat::kTimeNames[category], calls, (unsigned long long)(ns / 1000));
            }
            LOGI("[GL-PERF] count/time%s", timing);
        }
#endif
    }
}

GUEST_VOID_2I(GL2_resize, "Java_com_gameloft_glf_GL2JNILib_resize")
GUEST_VOID_1IZ(GL2_keyboardEvent, "Java_com_gameloft_glf_GL2JNILib_keyboardEvent")
// Sensor events DROPPED (2026-09-17): they arrive on the main Java thread
// and would run guest code that contends for guest mutexes held by the
// loader pass -- the exact deadlock frozen in /data/anr/trace_04 (the main
// thread blocked in accelerometerEvent on a bridge pthread mutex while the
// loader run thread waited on the guest cond). The menu/load needs no
// sensor input; the old real-threads lineage shipped the same drop.
static void GL2_accelerometerEvent(JNIEnv*, jclass, jfloat, jfloat, jfloat) {}
static void GL2_gyroscopeEvent(JNIEnv*, jclass, jfloat, jfloat, jfloat) {}
GUEST_VOID_0(GL2_destroy, "Java_com_gameloft_glf_GL2JNILib_destroy")
GUEST_VOID_0(GL2_lowBattery, "Java_com_gameloft_glf_GL2JNILib_lowBattery")
GUEST_INT_0(GL2_getNumExtraContext, "Java_com_gameloft_glf_GL2JNILib_getNumExtraContext")
GUEST_VOID_1I(GL2_setNumExtraContext, "Java_com_gameloft_glf_GL2JNILib_setNumExtraContext")
static void GL2_stateChanged(JNIEnv* env, jclass clazz, jboolean active) {
    if (!EnsureGameLoaded(env)) return;
    FlushTouchEvents(env, clazz);
    if (uint32_t symbol = GuestSym("Java_com_gameloft_glf_GL2JNILib_stateChanged"))
        g_host->RunFunction(symbol, {FakeEnv(), J(clazz), (uint32_t)(active ? 1 : 0)});
}
GUEST_VOID_1I(GL2_orientationChanged, "Java_com_gameloft_glf_GL2JNILib_orientationChanged")
GUEST_VOID_3I(GL2_nativeTouchPadMoved, "Java_com_gameloft_glf_GL2JNILib_nativeTouchPadMoved")
GUEST_VOID_3I(GL2_nativeTouchPadPressed, "Java_com_gameloft_glf_GL2JNILib_nativeTouchPadPressed")
GUEST_VOID_3I(GL2_nativeTouchPadReleased, "Java_com_gameloft_glf_GL2JNILib_nativeTouchPadReleased")
// (ZZ)V: two boolean words.
static void GL2_nativeKeyboardEnabled(JNIEnv* env, jclass clazz, jboolean a, jboolean b) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_glf_GL2JNILib_nativeKeyboardEnabled"))
        g_host->RunFunction(s, {FakeEnv(), J(clazz), (uint32_t)(a ? 1 : 0), (uint32_t)(b ? 1 : 0)});
}
GUEST_VOID_1Z(GL2_nativeSetDoubleDn, "Java_com_gameloft_glf_GL2JNILib_nativeSetDoubleDn")
GUEST_VOID_1Z(GL2_nativeSetDoubleUp, "Java_com_gameloft_glf_GL2JNILib_nativeSetDoubleUp")
GUEST_VOID_1I(GL2_nativeSetMogaConnected, "Java_com_gameloft_glf_GL2JNILib_nativeSetMogaConnected")
GUEST_VOID_FFI(GL2_nativeSetTouchPadDT, "Java_com_gameloft_glf_GL2JNILib_nativeSetTouchPadDT")
GUEST_VOID_FFI(GL2_nativeSetTouchPadDTLeft, "Java_com_gameloft_glf_GL2JNILib_nativeSetTouchPadDTLeft")
GUEST_VOID_FFI(GL2_nativeSetTouchPadSprint, "Java_com_gameloft_glf_GL2JNILib_nativeSetTouchPadSprint")
GUEST_VOID_IFFI(GL2_nativeSetTouchPadTouchEvent, "Java_com_gameloft_glf_GL2JNILib_nativeSetTouchPadTouchEvent")

static void GL2_nativeSetTouchPadDirections(JNIEnv* env, jclass clazz, jboolean a, jboolean b,
                                            jboolean c, jboolean d, jboolean e, jboolean f,
                                            jboolean g, jboolean h, jboolean i) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_glf_GL2JNILib_nativeSetTouchPadDirections")) {
        g_host->RunFunction(s, {FakeEnv(), J(clazz), (uint32_t)(a ? 1 : 0), (uint32_t)(b ? 1 : 0),
                                (uint32_t)(c ? 1 : 0), (uint32_t)(d ? 1 : 0), (uint32_t)(e ? 1 : 0),
                                (uint32_t)(f ? 1 : 0), (uint32_t)(g ? 1 : 0), (uint32_t)(h ? 1 : 0),
                                (uint32_t)(i ? 1 : 0)});
    }
}

static jboolean GL2_processTouchpadAsPointer(JNIEnv* env, jclass clazz, jint a, jobject parent,
                                             jboolean b) {
    if (!EnsureGameLoaded(env)) return JNI_FALSE;
    if (uint32_t s = GuestSym("Java_com_gameloft_glf_GL2JNILib_processTouchpadAsPointer")) {
        uint32_t h = parent ? FakeJniEnv::Instance().AddObjectRef(parent) : 0;
        return g_host->RunFunction(s, {FakeEnv(), J(clazz), (uint32_t)a, h,
                                       (uint32_t)(b ? 1 : 0)})
                   ? JNI_TRUE : JNI_FALSE;
    }
    return JNI_FALSE;
}


// setPaths(String,String,String): capture paths host-side (the APK path feeds
// guest extraction + phase3 VFS) and forward.
static void GL2_setPaths(JNIEnv* env, jclass clazz, jstring apk, jstring write, jstring read) {
    if (apk) {
        const char* s = env->GetStringUTFChars(apk, nullptr);
        if (s) { g_saved_apk_path = s; env->ReleaseStringUTFChars(apk, s); }
    }
    if (write) {
        const char* s = env->GetStringUTFChars(write, nullptr);
        if (s) { g_saved_files_dir = s; env->ReleaseStringUTFChars(write, s); }
    }
    LOGI("Paths: apk='%s' files='%s'", g_saved_apk_path.c_str(), g_saved_files_dir.c_str());
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_glf_GL2JNILib_setPaths")) {
        FakeJniEnv& fj = FakeJniEnv::Instance();
        g_host->RunFunction(s, {FakeEnv(), J(clazz), apk ? fj.AddObjectRef(apk) : 0,
                                write ? fj.AddObjectRef(write) : 0,
                                read ? fj.AddObjectRef(read) : 0});
    }
}

// ---------------------------------------------------------------------------
// MC4 — com.gameloft.android.ANMP.GloftM4HM.MC4
// ---------------------------------------------------------------------------

GUEST_VOID_0_OBJ(MC4_nativeMC4Init, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeMC4Init")
GUEST_VOID_0(MC4_pauseGame, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_pauseGame")
GUEST_VOID_0(MC4_resumeGame, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_resumeGame")
GUEST_VOID_1STR(MC4_splashScreenFunc, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_splashScreenFunc")
GUEST_STR_0(MC4_nativeGetGlliveParams, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeGetGlliveParams")
GUEST_STR_0_OBJ(MC4_nativeGetKeyboardText, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeGetKeyboardText")
static void MC4_nativeHandleKey(JNIEnv* env, jobject obj, jint key) {
    if (!EnsureGameLoaded(env)) return;
    std::lock_guard<std::recursive_mutex> lock(g_host->GetMutex());
    if (key == 4) {
        const uint32_t instance = g_host->FindSymbol("_ZN11Application10s_instanceE");
        const uint32_t state = g_host->FindSymbol("_ZN4iFPS19GetCurrentStateTypeEv");
        const uint32_t pause = g_host->FindSymbol("_ZN11Application12RequestPauseEv");
        const uint32_t app = instance ? g_host->MemoryRead32(instance) : 0;
        const uint32_t gameplay_slot = g_host->FindSymbol("_ZN8Gameplay10s_instanceE");
        const uint32_t gameplay = gameplay_slot ? g_host->MemoryRead32(gameplay_slot) : 0;
        const uint32_t hud_pause = g_host->FindSymbol("_ZN3Hud5PauseEbbb");
        const uint32_t hud_unpause = g_host->FindSymbol("_ZN3Hud7UnPauseEb");
        LOGI("[BACK] app=%08X gameplay=%08X state=%08X pause=%08X hud_pause=%08X hud_unpause=%08X",
             app, gameplay, state, pause, hud_pause, hud_unpause);
        if (GuestRangeValid(g_host->GetGuestMemorySize(), app, 0xad8) &&
            GuestRangeValid(g_host->GetGuestMemorySize(), gameplay, 0x4d))
            LOGI("[BACK] automat=%08X request=%u paused=%u",
                 g_host->MemoryRead32(app + 0xad4), g_host->MemoryRead8(app + 0x809),
                 g_host->MemoryRead8(gameplay + 0x4c));
        if (app && GuestRangeValid(g_host->GetGuestMemorySize(), app, 0xad8) && state && pause &&
            gameplay && GuestRangeValid(g_host->GetGuestMemorySize(), gameplay, 0x4d) &&
            hud_pause && hud_unpause &&
            g_host->MemoryRead32(hud_pause + 0x2b0) == 0xe5cb104cu &&
            g_host->MemoryRead32(hud_unpause + 0x50) == 0xe5c3604cu &&
            !g_host->MemoryRead8(gameplay + 0x4c) &&
            g_host->MemoryRead32(state) == 0xe5900ad4u &&
            g_host->MemoryRead32(pause) == 0xe3a03001u &&
            g_host->MemoryRead32(pause + 4) == 0xe5c03809u) {
            LOGI("[BACK] querying state");
            const uint32_t state_type = g_host->RunFunction(state, {app});
            LOGI("[BACK] state=%u", state_type);
            if (state_type == 2) {
                // Request the HUD's normal pause transition during combat;
                // its Pause/UnPause pair owns Gameplay+0x4c, including submenus.
                // Menus and loading retain the original Back handling.
                g_host->RunFunction(pause, {app});
                LOGI("[BACK] pause submitted");
                return;
            }
        }
    }
    LOGI("[BACK] original key path=%d", key);
    if (uint32_t symbol = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeHandleKey"))
        g_host->RunFunction(symbol, {FakeEnv(), J(obj), static_cast<uint32_t>(key)});
}
GUEST_VOID_0_OBJ(MC4_nativeHideKeyboard, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeHideKeyboard")
GUEST_Z_1STR_OBJ(MC4_nativeonEditorAction, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeonEditorAction")
GUEST_VOID_0(MC4_nativeExitGyroCalibration, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeExitGyroCalibration")
GUEST_VOID_0(MC4_nativeLoginToMultiplayerUseGPGS, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeLoginToMultiplayerUseGPGS")
GUEST_Z_1I(MC4_nativeSetIsMogaConnected, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeSetIsMogaConnected")
GUEST_VOID_1I(MC4_setCurrentOrientation, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_setCurrentOrientation")

// SplashScreenActivity.splashScreenFuncGLOT(String)V: no dedicated guest
// export exists; it forwards to the same splash renderer the guest exports
// for MC4.splashScreenFunc.
GUEST_VOID_1STR(SS_splashScreenFuncGLOT, "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_splashScreenFunc")

// ---------------------------------------------------------------------------
// Installer / DRM (GDRMPolicy instance, GameInstaller mixed)
// ---------------------------------------------------------------------------

GUEST_VOID_0(GameInstaller_initNative, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GameInstaller_initNative")
GUEST_VOID_0(GameInstaller_nativeStart, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GameInstaller_nativeStart")
GUEST_VOID_0_OBJ(GameInstaller_getPublicKey, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GameInstaller_getPublicKey")

GUEST_VOID_3I(GDRMPolicy_initNativeAP, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_initNativeAP")
GUEST_STR_1I_OBJ(GDRMPolicy_getConstString, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_getConstString")
GUEST_STR_0_OBJ(GDRMPolicy_getPrefFile, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_getPrefFile")
GUEST_INT_1_LONG_OBJ(GDRMPolicy_nativeAllow, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_nativeAllow")
GUEST_VOID_2I_OBJ(GDRMPolicy_processServer, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_processServer")
GUEST_VOID_2I_OBJ(GDRMPolicy_setConst, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_setConst")
GUEST_VOID_1I_LONG_OBJ(GDRMPolicy_setLongConst, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_setLongConst")
GUEST_VOID_1_LONG_OBJ(GDRMPolicy_setTime, "Java_com_gameloft_android_ANMP_GloftM4HM_installer_GDRMPolicy_setTime")

// ---------------------------------------------------------------------------
// GLUtils / misc singletons (static)
// ---------------------------------------------------------------------------

GUEST_VOID_0(Device_nativeInit, "Java_com_gameloft_android_ANMP_GloftM4HM_GLUtils_Device_nativeInit")
GUEST_VOID_0(SUtils_nativeInit, "Java_com_gameloft_android_ANMP_GloftM4HM_GLUtils_SUtils_nativeInit")
GUEST_VOID_0(SUtils_onVideoFinished, "Java_com_gameloft_android_ANMP_GloftM4HM_GLUtils_SUtils_onVideoFinished")
GUEST_VOID_0(SendInfo_initMethods, "Java_com_gameloft_android_ANMP_GloftM4HM_SendInfo_initMethods")
GUEST_VOID_0(DataSharing_nativeInit, "Java_com_gameloft_android_ANMP_GloftM4HM_DataSharing_nativeInit")
GUEST_VOID_1I(NetworkStateReceiver_setConnectionType, "Java_com_gameloft_android_ANMP_GloftM4HM_GLUtils_NetworkStateReceiver_setConnectionType")

GUEST_VOID_0(MyVideoView_Init, "Java_com_gameloft_android_ANMP_GloftM4HM_MyVideoView_Init")
static void MyVideoView_SetFinished(JNIEnv*, jclass clazz) {
    // Android may recreate the intro-video Activity after the MC4 guest
    // process exits. Do not boot another complete game runtime merely to
    // update state that is absent from this process.
    if (!g_host) {
        LOGI("MyVideoView.SetFinished: no guest runtime in this process");
        return;
    }
    if (uint32_t symbol = GuestSym(
            "Java_com_gameloft_android_ANMP_GloftM4HM_MyVideoView_SetFinished"))
        g_host->RunFunction(symbol, {FakeEnv(), J(clazz)});
}
GUEST_VOID_0(MyVideoView_playMovie, "Java_com_gameloft_android_ANMP_GloftM4HM_MyVideoView_playMovie")
GUEST_STR_0(MyVideoView_nativeGetInvalidBackMsg, "Java_com_gameloft_android_ANMP_GloftM4HM_MyVideoView_nativeGetInvalidBackMsg")

// SUtils.nativeGetPreference/nativeSetPreference are plain Java methods in
// smali (no `native` keyword, no guest export) — nothing to register; the
// smali bodies call back into the engine themselves.

// ---------------------------------------------------------------------------
// IAB (static)
// ---------------------------------------------------------------------------

static void InAppBilling_nativeInit(JNIEnv* env, jclass clazz, jobject context) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_InAppBilling_nativeInit")) {
        uint32_t h = context ? FakeJniEnv::Instance().AddObjectRef(context) : 0;
        g_host->RunFunction(s, {FakeEnv(), J(clazz), h});
    }
}
static jobject InAppBilling_nativeSendData(JNIEnv* env, jclass clazz, jobject bundle) {
    if (!EnsureGameLoaded(env)) return nullptr;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_InAppBilling_nativeSendData")) {
        uint32_t h = bundle ? FakeJniEnv::Instance().AddObjectRef(bundle) : 0;
        uint32_t res = g_host->RunFunction(s, {FakeEnv(), J(clazz), h});
        if (res) return FakeJniEnv::Instance().ResolveObject(res);
    }
    return nullptr;
}
static void InAppBilling_nativeSetContext(JNIEnv* env, jclass clazz, jobject context) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_InAppBilling_nativeSetContext")) {
        uint32_t h = context ? FakeJniEnv::Instance().AddObjectRef(context) : 0;
        g_host->RunFunction(s, {FakeEnv(), J(clazz), h});
    }
}
static void InAppBilling_nativeSetIABObject(JNIEnv* env, jclass clazz, jobject iab) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_InAppBilling_nativeSetIABObject")) {
        uint32_t h = iab ? FakeJniEnv::Instance().AddObjectRef(iab) : 0;
        g_host->RunFunction(s, {FakeEnv(), J(clazz), h});
    }
}

// iab.s (static): bq/gk pass object handles; gn()J returns r0:r1; in/rn take
// (J) as r2:r3.
static jint iab_s_bq(JNIEnv* env, jclass clazz, jobject pubkey, jstring data, jstring sig) {
    if (!EnsureGameLoaded(env)) return 0;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_s_bq")) {
        FakeJniEnv& fj = FakeJniEnv::Instance();
        return (jint)g_host->RunFunction(s, {FakeEnv(), J(clazz),
                                             pubkey ? fj.AddObjectRef(pubkey) : 0,
                                             data ? fj.AddObjectRef(data) : 0,
                                             sig ? fj.AddObjectRef(sig) : 0});
    }
    return 0;
}
static jobject iab_s_gk(JNIEnv* env, jclass clazz, jstring str) {
    if (!EnsureGameLoaded(env)) return nullptr;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_s_gk")) {
        uint32_t h = str ? FakeJniEnv::Instance().AddObjectRef(str) : 0;
        uint32_t res = g_host->RunFunction(s, {FakeEnv(), J(clazz), h});
        if (res) return FakeJniEnv::Instance().ResolveObject(res);
    }
    return nullptr;
}
static jlong iab_s_gn(JNIEnv* env, jclass clazz) {
    if (!EnsureGameLoaded(env)) return 0;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_s_gn")) {
        uint32_t lo = g_host->RunFunction(s, {FakeEnv(), J(clazz)});
        return (jlong)(((uint64_t)g_host->GetLastR1() << 32) | lo);
    }
    return 0;
}
static jboolean iab_s_in(JNIEnv* env, jclass clazz, jlong v) {
    if (!EnsureGameLoaded(env)) return JNI_FALSE;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_s_in")) {
        return g_host->RunFunction(s, {FakeEnv(), J(clazz), (uint32_t)v, (uint32_t)(v >> 32)})
                       ? JNI_TRUE : JNI_FALSE;
    }
    return JNI_FALSE;
}
static void iab_s_rn(JNIEnv* env, jclass clazz, jlong v) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_iab_s_rn")) {
        g_host->RunFunction(s, {FakeEnv(), J(clazz), (uint32_t)v, (uint32_t)(v >> 32)});
    }
}

// ---------------------------------------------------------------------------
// Social facades (phase 4 kept native methods on fail-closed Java facades)
// ---------------------------------------------------------------------------

GUEST_VOID_0(PlatformAndroid_nativeInit, "Java_com_gameloft_GLSocialLib_PlatformAndroid_nativeInit")
GUEST_VOID_0(GameAPI_nativeInit, "Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeInit")
GUEST_VOID_0(GameAPI_nativeGameAPIComplete, "Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeGameAPIComplete")
GUEST_VOID_1STR(GameAPI_nativeGameAPIDidNotComplete, "Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeGameAPIDidNotComplete")
GUEST_VOID_0(GameAPI_nativeGameAPIDidPlusOneButton, "Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeGameAPIDidPlusOneButton")
GUEST_VOID_0(GameAPI_nativeGameAPINotifyLogout, "Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeGameAPINotifyLogout")
GUEST_VOID_0(GameAPI_nativeGameAPISetCanceled, "Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeGameAPISetCanceled")

// (Ljava/lang/String;Z[B)V: three 32-bit handles/words.
static void GameAPI_nativeGameAPICompleteWithData(JNIEnv* env, jclass clazz, jstring data,
                                                  jboolean ok, jbyteArray extra) {
    if (!EnsureGameLoaded(env)) return;
    if (uint32_t s = GuestSym("Java_com_gameloft_GLSocialLib_GameAPI_GameAPIAndroidGLSocialLib_nativeGameAPICompleteWithData")) {
        FakeJniEnv& fj = FakeJniEnv::Instance();
        g_host->RunFunction(s, {FakeEnv(), J(clazz), data ? fj.AddObjectRef(data) : 0,
                                (uint32_t)(ok ? 1 : 0), extra ? fj.AddObjectRef(extra) : 0});
    }
}

// ---------------------------------------------------------------------------
// phase3 / offline-cheat host natives (Java contract unchanged)
// ---------------------------------------------------------------------------

static void Native_Phase3VfsInstall(JNIEnv* env, jclass clazz) {
    const bool ready = EnsureGameLoaded(env);
    jfieldID error_field = env->GetStaticFieldID(clazz, "phase3CacheError", "Z");
    if (error_field) {
        env->SetStaticBooleanField(clazz, error_field,
                                   g_cache_unavailable.load() ? JNI_TRUE : JNI_FALSE);
    } else {
        env->ExceptionClear();
        LOGE("phase3CacheError field missing from MC4 class");
    }
    if (!ready) return;
    const std::string obb_dir = GetAppObbDir(env);
    mc4::Phase3VfsInstall(*g_host,
                          g_saved_apk_path.empty() ? nullptr : g_saved_apk_path.c_str(),
                          obb_dir.c_str());
}

static void Native_Phase3VfsMaxQuality(JNIEnv* env, jclass) {
#if MC4_ENABLE_MAX_QUALITY_DIAGNOSTIC
    if (!EnsureGameLoaded(env) || !g_host) return;

    static std::atomic<bool> worker_started{false};
    if (worker_started.exchange(true)) return;
    DynarmicHost* host = g_host.get();
    try {
        std::thread([host] {
            int applied = 0;
            for (int attempt = 0; attempt < 28800; ++attempt) {
                auto& run_mutex = host->GetMutex();
                if (run_mutex.try_lock()) {
                    std::lock_guard<std::recursive_mutex> lock(
                        run_mutex, std::adopt_lock);
                    if (mc4::Phase3ForceMaxQuality(*host)) {
                        if (applied == 0)
                            LOGI("max-quality diagnostic applied on attempt %d", attempt);
                        ++applied;
                    }
                }
                usleep(250000);
            }
            LOGI("max-quality diagnostic worker ended after %d writes", applied);
        }).detach();
    } catch (...) {
        worker_started.store(false);
        LOGE("max-quality diagnostic worker could not start");
    }
#else
    (void)env;
#endif
}

static jboolean Native_GateReady(JNIEnv*, jclass) {
    return mc4::Phase3GateReady() ? JNI_TRUE : JNI_FALSE;
}

static void Native_GateSelfTest(JNIEnv*, jclass) {
    LOGI("cheat gate self-test: option17=%d option18=%d option22=%d option31=%d option32=%d",
         (int)mc4::Phase3AllowCheatOption(17), (int)mc4::Phase3AllowCheatOption(18),
         (int)mc4::Phase3AllowCheatOption(22), (int)mc4::Phase3AllowCheatOption(31),
         (int)mc4::Phase3AllowCheatOption(32));
}

static void Native_SetEntitlement(JNIEnv*, jclass, jint option) {
    mc4::Phase3SetCheatEntitlement(option);
}

static jboolean Native_CheatApply(JNIEnv* env, jclass, jint option) {
    if (!EnsureGameLoaded(env)) return JNI_FALSE;
    return mc4::OfflineCheatApply(*g_host, option) ? JNI_TRUE : JNI_FALSE;
}

// ---------------------------------------------------------------------------
// Registration tables
// ---------------------------------------------------------------------------

static const JNINativeMethod g_gl2jni_methods[] = {
    {"init", "()V", (void*)GL2_init},
    {"initGL", "()V", (void*)GL2_initGL},
    {"InitViewSettings", "()V", (void*)GL2_InitViewSettings},
    {"step", "()V", (void*)GL2_step},
    {"resize", "(II)V", (void*)GL2_resize},
    {"touchEvent", "(IIII)V", (void*)GL2_touchEvent},
    {"keyboardEvent", "(IZ)V", (void*)GL2_keyboardEvent},
    {"accelerometerEvent", "(FFF)V", (void*)GL2_accelerometerEvent},
    {"gyroscopeEvent", "(FFF)V", (void*)GL2_gyroscopeEvent},
    {"destroy", "()V", (void*)GL2_destroy},
    {"lowBattery", "()V", (void*)GL2_lowBattery},
    {"getNumExtraContext", "()I", (void*)GL2_getNumExtraContext},
    {"setNumExtraContext", "(I)V", (void*)GL2_setNumExtraContext},
    {"stateChanged", "(Z)V", (void*)GL2_stateChanged},
    {"orientationChanged", "(I)V", (void*)GL2_orientationChanged},
    {"nativeTouchPadMoved", "(III)V", (void*)GL2_nativeTouchPadMoved},
    {"nativeTouchPadPressed", "(III)V", (void*)GL2_nativeTouchPadPressed},
    {"nativeTouchPadReleased", "(III)V", (void*)GL2_nativeTouchPadReleased},
    {"nativeKeyboardEnabled", "(ZZ)V", (void*)GL2_nativeKeyboardEnabled},
    {"nativeSetDoubleDn", "(Z)V", (void*)GL2_nativeSetDoubleDn},
    {"nativeSetDoubleUp", "(Z)V", (void*)GL2_nativeSetDoubleUp},
    {"nativeSetMogaConnected", "(I)V", (void*)GL2_nativeSetMogaConnected},
    {"nativeSetTouchPadDT", "(FFI)V", (void*)GL2_nativeSetTouchPadDT},
    {"nativeSetTouchPadDTLeft", "(FFI)V", (void*)GL2_nativeSetTouchPadDTLeft},
    {"nativeSetTouchPadSprint", "(FFI)V", (void*)GL2_nativeSetTouchPadSprint},
    {"nativeSetTouchPadTouchEvent", "(IFFI)V", (void*)GL2_nativeSetTouchPadTouchEvent},
    {"nativeSetTouchPadDirections", "(ZZZZZZZZZ)V", (void*)GL2_nativeSetTouchPadDirections},
    {"processTouchpadAsPointer", "(ILandroid/view/ViewParent;Z)Z", (void*)GL2_processTouchpadAsPointer},
    {"setPaths", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", (void*)GL2_setPaths},
};

static const JNINativeMethod g_mc4_methods[] = {
    {"nativeMC4Init", "()V", (void*)MC4_nativeMC4Init},
    {"pauseGame", "()V", (void*)MC4_pauseGame},
    {"resumeGame", "()V", (void*)MC4_resumeGame},
    {"splashScreenFunc", "(Ljava/lang/String;)V", (void*)MC4_splashScreenFunc},
    {"nativeGetGlliveParams", "()Ljava/lang/String;", (void*)MC4_nativeGetGlliveParams},
    {"nativeGetKeyboardText", "()Ljava/lang/String;", (void*)MC4_nativeGetKeyboardText},
    {"nativeHandleKey", "(I)V", (void*)MC4_nativeHandleKey},
    {"nativeHideKeyboard", "()V", (void*)MC4_nativeHideKeyboard},
    {"nativeonEditorAction", "(Ljava/lang/String;)Z", (void*)MC4_nativeonEditorAction},
    {"nativeExitGyroCalibration", "()V", (void*)MC4_nativeExitGyroCalibration},
    {"nativeLoginToMultiplayerUseGPGS", "()V", (void*)MC4_nativeLoginToMultiplayerUseGPGS},
    {"nativeSetIsMogaConnected", "(I)Z", (void*)MC4_nativeSetIsMogaConnected},
    {"setCurrentOrientation", "(I)V", (void*)MC4_setCurrentOrientation},
    {"phase3VfsInstall", "()V", (void*)Native_Phase3VfsInstall},
    {"phase3VfsMaxQuality", "()V", (void*)Native_Phase3VfsMaxQuality},
};

static const JNINativeMethod g_offline_cheat_methods[] = {
    {"apply", "(I)Z", (void*)Native_CheatApply},
    {"setEntitlement", "(I)V", (void*)Native_SetEntitlement},
    {"gateReady", "()Z", (void*)Native_GateReady},
    {"gateSelfTest", "()V", (void*)Native_GateSelfTest},
};

static const JNINativeMethod g_installer_methods[] = {
    {"initNative", "()V", (void*)GameInstaller_initNative},
    {"nativeStart", "()V", (void*)GameInstaller_nativeStart},
    {"getPublicKey", "()V", (void*)GameInstaller_getPublicKey},
};

static const JNINativeMethod g_gdrm_methods[] = {
    {"initNativeAP", "(III)V", (void*)GDRMPolicy_initNativeAP},
    {"getConstString", "(I)Ljava/lang/String;", (void*)GDRMPolicy_getConstString},
    {"getPrefFile", "()Ljava/lang/String;", (void*)GDRMPolicy_getPrefFile},
    {"nativeAllow", "(J)I", (void*)GDRMPolicy_nativeAllow},
    {"processServer", "(II)V", (void*)GDRMPolicy_processServer},
    {"setConst", "(II)V", (void*)GDRMPolicy_setConst},
    {"setLongConst", "(IJ)V", (void*)GDRMPolicy_setLongConst},
    {"setTime", "(J)V", (void*)GDRMPolicy_setTime},
};

static const JNINativeMethod g_device_methods[] = {
    {"nativeInit", "()V", (void*)Device_nativeInit},
};

static const JNINativeMethod g_sutils_methods[] = {
    {"nativeInit", "()V", (void*)SUtils_nativeInit},
    {"onVideoFinished", "()V", (void*)SUtils_onVideoFinished},
};

static const JNINativeMethod g_network_methods[] = {
    {"setConnectionType", "(I)V", (void*)NetworkStateReceiver_setConnectionType},
};

static const JNINativeMethod g_sendinfo_methods[] = {
    {"initMethods", "()V", (void*)SendInfo_initMethods},
};

static const JNINativeMethod g_datasharing_methods[] = {
    {"nativeInit", "()V", (void*)DataSharing_nativeInit},
};

static jobject ZipFileContentProvider_openEmbeddedMedia(JNIEnv* env, jclass, jstring name) {
    if (!name || !mc4::Phase3Installed()) return nullptr;
    jclass pfd_class = env->FindClass("android/os/ParcelFileDescriptor");
    if (!pfd_class) return nullptr;
    jclass afd_class = env->FindClass("android/content/res/AssetFileDescriptor");
    if (!afd_class) { env->DeleteLocalRef(pfd_class); return nullptr; }
    jmethodID adopt = env->GetStaticMethodID(pfd_class, "adoptFd",
                                            "(I)Landroid/os/ParcelFileDescriptor;");
    jmethodID close_method = adopt ? env->GetMethodID(pfd_class, "close", "()V") : nullptr;
    jmethodID ctor = close_method ? env->GetMethodID(afd_class, "<init>",
                                            "(Landroid/os/ParcelFileDescriptor;JJ)V") : nullptr;
    jobject result = nullptr;
    if (ctor) {
        const char* path = env->GetStringUTFChars(name, nullptr);
        off64_t offset = 0, length = 0;
        const int fd = path ? mc4::Phase3OpenMedia(path, &offset, &length) : -1;
        if (path) env->ReleaseStringUTFChars(name, path);
        if (fd >= 0) {
            jobject pfd = env->CallStaticObjectMethod(pfd_class, adopt, (jint)fd);
            if (!pfd) close(fd);
            else {
                result = env->NewObject(afd_class, ctor, pfd, (jlong)offset, (jlong)length);
                if (!result) {
                    // Ownership has transferred to PFD. Close through it once,
                    // preserving the original construction error.
                    jthrowable error = env->ExceptionOccurred();
                    if (error) env->ExceptionClear();
                    env->CallVoidMethod(pfd, close_method);
                    if (error) {
                        env->ExceptionClear();
                        env->Throw(error);
                        env->DeleteLocalRef(error);
                    }
                }
                env->DeleteLocalRef(pfd);
            }
        }
    }
    env->DeleteLocalRef(afd_class);
    env->DeleteLocalRef(pfd_class);
    return result;
}

static const JNINativeMethod g_zip_provider_methods[] = {
    {"openEmbeddedMedia", "(Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;",
        (void*)ZipFileContentProvider_openEmbeddedMedia},
};

static const JNINativeMethod g_video_methods[] = {
    {"Init", "()V", (void*)MyVideoView_Init},
    {"SetFinished", "()V", (void*)MyVideoView_SetFinished},
    {"playMovie", "()V", (void*)MyVideoView_playMovie},
    {"nativeGetInvalidBackMsg", "()Ljava/lang/String;", (void*)MyVideoView_nativeGetInvalidBackMsg},
};

static const JNINativeMethod g_splash_methods[] = {
    {"splashScreenFuncGLOT", "(Ljava/lang/String;)V", (void*)SS_splashScreenFuncGLOT},
};

static const JNINativeMethod g_iab_methods[] = {
    {"nativeInit", "(Landroid/content/Context;)V", (void*)InAppBilling_nativeInit},
    {"nativeSendData", "(Landroid/os/Bundle;)Landroid/os/Bundle;", (void*)InAppBilling_nativeSendData},
    {"nativeSetContext", "(Landroid/content/Context;)V", (void*)InAppBilling_nativeSetContext},
    {"nativeSetIABObject", "(Lcom/gameloft/android/ANMP/GloftM4HM/iab/InAppBilling;)V", (void*)InAppBilling_nativeSetIABObject},
};

static const JNINativeMethod g_iab_s_methods[] = {
    {"bq", "(Ljava/security/PublicKey;Ljava/lang/String;Ljava/lang/String;)I", (void*)iab_s_bq},
    {"gk", "(Ljava/lang/String;)Ljava/security/PublicKey;", (void*)iab_s_gk},
    {"gn", "()J", (void*)iab_s_gn},
    {"in", "(J)Z", (void*)iab_s_in},
    {"rn", "(J)V", (void*)iab_s_rn},
};

static const JNINativeMethod g_platform_methods[] = {
    {"nativeInit", "()V", (void*)PlatformAndroid_nativeInit},
};

static const JNINativeMethod g_gameapi_methods[] = {
    {"nativeInit", "()V", (void*)GameAPI_nativeInit},
    {"nativeGameAPIComplete", "()V", (void*)GameAPI_nativeGameAPIComplete},
    {"nativeGameAPICompleteWithData", "(Ljava/lang/String;Z[B)V", (void*)GameAPI_nativeGameAPICompleteWithData},
    {"nativeGameAPIDidNotComplete", "(Ljava/lang/String;)V", (void*)GameAPI_nativeGameAPIDidNotComplete},
    {"nativeGameAPIDidPlusOneButton", "()V", (void*)GameAPI_nativeGameAPIDidPlusOneButton},
    {"nativeGameAPINotifyLogout", "()V", (void*)GameAPI_nativeGameAPINotifyLogout},
    {"nativeGameAPISetCanceled", "()V", (void*)GameAPI_nativeGameAPISetCanceled},
};

// ---------------------------------------------------------------------------
// JNI_OnLoad
// ---------------------------------------------------------------------------

struct ClassTable {
    const char* name;
    const JNINativeMethod* methods;
    size_t count;
};

static bool RegisterClassNatives(JNIEnv* env, const ClassTable& t) {
    jclass cls = env->FindClass(t.name);
    if (!cls) {
        if (env->ExceptionCheck()) {
#if MC4_ENABLE_NATIVE_LOGGING
            env->ExceptionDescribe();
#endif
            env->ExceptionClear();
        }
        LOGE("Class not found: %s -- natives not registered", t.name);
        return false;
    }
    jint rc = env->RegisterNatives(cls, t.methods, t.count);
    if (rc != JNI_OK) {
        LOGE("RegisterNatives failed for %s", t.name);
        if (env->ExceptionCheck()) {
#if MC4_ENABLE_NATIVE_LOGGING
            env->ExceptionDescribe();
#endif
            env->ExceptionClear();
        }
        env->DeleteLocalRef(cls);
        return false;
    }
    env->DeleteLocalRef(cls);
    LOGI("Registered %d natives on %s", (int)t.count, t.name);
    return true;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    LOGI("JNI_OnLoad: MC4 ARM64 host for the 32-bit guest");

    static const ClassTable tables[] = {
        {"com/gameloft/glf/GL2JNILib", g_gl2jni_methods, sizeof(g_gl2jni_methods) / sizeof(g_gl2jni_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/MC4", g_mc4_methods, sizeof(g_mc4_methods) / sizeof(g_mc4_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge", g_offline_cheat_methods, sizeof(g_offline_cheat_methods) / sizeof(g_offline_cheat_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/installer/GameInstaller", g_installer_methods, sizeof(g_installer_methods) / sizeof(g_installer_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/installer/GDRMPolicy", g_gdrm_methods, sizeof(g_gdrm_methods) / sizeof(g_gdrm_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/GLUtils/Device", g_device_methods, sizeof(g_device_methods) / sizeof(g_device_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/GLUtils/SUtils", g_sutils_methods, sizeof(g_sutils_methods) / sizeof(g_sutils_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/GLUtils/NetworkStateReceiver", g_network_methods, sizeof(g_network_methods) / sizeof(g_network_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/SendInfo", g_sendinfo_methods, sizeof(g_sendinfo_methods) / sizeof(g_sendinfo_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/DataSharing", g_datasharing_methods, sizeof(g_datasharing_methods) / sizeof(g_datasharing_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/MyVideoView", g_video_methods, sizeof(g_video_methods) / sizeof(g_video_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/ZipFileContentProvider", g_zip_provider_methods, sizeof(g_zip_provider_methods) / sizeof(g_zip_provider_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/SplashScreenActivity", g_splash_methods, sizeof(g_splash_methods) / sizeof(g_splash_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/iab/InAppBilling", g_iab_methods, sizeof(g_iab_methods) / sizeof(g_iab_methods[0])},
        {"com/gameloft/android/ANMP/GloftM4HM/iab/s", g_iab_s_methods, sizeof(g_iab_s_methods) / sizeof(g_iab_s_methods[0])},
        {"com/gameloft/GLSocialLib/PlatformAndroid", g_platform_methods, sizeof(g_platform_methods) / sizeof(g_platform_methods[0])},
        {"com/gameloft/GLSocialLib/GameAPI/GameAPIAndroidGLSocialLib", g_gameapi_methods, sizeof(g_gameapi_methods) / sizeof(g_gameapi_methods[0])},
    };

    int failed = 0;
    for (const auto& t : tables) {
        if (!RegisterClassNatives(env, t)) ++failed;
    }
    if (failed) {
        LOGE("JNI_OnLoad: %d class table(s) failed to register", failed);
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
