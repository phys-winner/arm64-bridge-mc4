#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_types.h"
#include <android/log.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <chrono>

#define LOG_TAG "Arm32Bridge_Thunks"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

uint32_t ThunkManager::s_screenWidth = 1213;
uint32_t ThunkManager::s_screenHeight = 540;
uint32_t ThunkManager::s_virtualWidth = 0;
uint32_t ThunkManager::s_virtualHeight = 0;
uint32_t ThunkManager::s_forced_dpi = 0;
uint32_t ThunkManager::s_ui_inset = 0;

ThunkManager::ThunkManager(DynarmicHost& host) : m_host(host) {
    for (auto& entry : m_fast_thunks) {
        entry.store(nullptr, std::memory_order_relaxed);
    }
}

ThunkManager::~ThunkManager() = default;

#include "thunks_opensles.h"

void ThunkManager::RegisterAllThunks() {
    RegisterGLThunks();
    RegisterOpenSLESThunks(*this, m_host);
    RegisterLibcThunks();
    // The guest-visible JNIEnv/JavaVM tables live in FakeJniEnv; jni_bridge.cpp
    // calls FakeJniEnv::Instance().Init(host) once the host JavaVM is known.
}

#include <jni.h>
#include <sys/system_properties.h>
#include <cmath>
#include <cctype>
#include <cstring>

JavaVM* GetHostJavaVM();
void BridgeAttachCurrentThread();

std::string QueryDeviceLanguage() {
    std::string lang = "en";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getLang = env->GetMethodID(locCls, "getLanguage", "()Ljava/lang/String;");
                        if (getLang) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getLang);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    lang = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (lang.empty() || lang == "en") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.locale", prop) > 0 ||
            __system_property_get("ro.product.locale", prop) > 0 ||
            __system_property_get("persist.sys.language", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash) *dash = '\0';
            char* under = strchr(prop, '_');
            if (under) *under = '\0';
            if (strlen(prop) > 0) lang = prop;
        }
    }
    for (char& c : lang) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lang;
}

std::string QueryDeviceCountryCode() {
    std::string country = "US";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getCountry = env->GetMethodID(locCls, "getCountry", "()Ljava/lang/String;");
                        if (getCountry) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getCountry);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    country = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (country.empty() || country == "US") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.country", prop) > 0 ||
            __system_property_get("ro.product.locale.region", prop) > 0) {
            if (strlen(prop) > 0) country = prop;
        } else if (__system_property_get("persist.sys.locale", prop) > 0 ||
                   __system_property_get("ro.product.locale", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash && strlen(dash + 1) >= 2) {
                country = std::string(dash + 1, 2);
            } else {
                char* under = strchr(prop, '_');
                if (under && strlen(under + 1) >= 2) {
                    country = std::string(under + 1, 2);
                }
            }
        }
    }
    for (char& c : country) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return country;
}

uint32_t QueryDeviceDensity() {
    if (ThunkManager::s_forced_dpi > 0) {
        return ThunkManager::s_forced_dpi;
    }
    uint32_t density = 0;
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getDM = env->GetMethodID(resCls, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;");
                        if (getDM) {
                            jobject dmObj = env->CallObjectMethod(resObj, getDM);
                            if (dmObj) {
                                jclass dmCls = env->FindClass("android/util/DisplayMetrics");
                                jfieldID fid = env->GetFieldID(dmCls, "densityDpi", "I");
                                if (fid) {
                                    density = static_cast<uint32_t>(env->GetIntField(dmObj, fid));
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (density == 0) {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.sf.lcd_density", prop) > 0 ||
            __system_property_get("qemu.sf.lcd_density", prop) > 0) {
            density = static_cast<uint32_t>(atoi(prop));
        }
    }
    if (density == 0) {
        density = 320;
    }
    return density;
}

uint32_t QueryDeviceIsPad() {
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            // Configuration.screenLayout is the platform answer; the diagonal
            // fallback below covers devices that report it wrong.
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getCfg = env->GetMethodID(resCls, "getConfiguration", "()Landroid/content/res/Configuration;");
                        if (getCfg) {
                            jobject cfgObj = env->CallObjectMethod(resObj, getCfg);
                            if (cfgObj) {
                                jclass cfgCls = env->FindClass("android/content/res/Configuration");
                                jfieldID slFid = env->GetFieldID(cfgCls, "screenLayout", "I");
                                if (slFid) {
                                    jint screenLayout = env->GetIntField(cfgObj, slFid);
                                    if ((screenLayout & 0x0F) >= 3) { // SCREENLAYOUT_SIZE_LARGE or XLARGE
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        if (attached) jvm->DetachCurrentThread();
                                        return 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }

    uint32_t w = ThunkManager::s_screenWidth;
    uint32_t h = ThunkManager::s_screenHeight;
    uint32_t dpi = QueryDeviceDensity();
    if (w > 0 && h > 0 && dpi > 0) {
        double w_in = static_cast<double>(w) / static_cast<double>(dpi);
        double h_in = static_cast<double>(h) / static_cast<double>(dpi);
        double diag = sqrt(w_in * w_in + h_in * h_in);
        if (diag >= 6.5) return 1;
    }
    return 0;
}


uint32_t ThunkManager::RegisterThunk(const std::string& name, ThunkHandler handler) {
    std::lock_guard<std::mutex> lock(m_registration_mutex);
    return RegisterThunkLocked(name, std::move(handler));
}

uint32_t ThunkManager::RegisterThunkLocked(const std::string& name, ThunkHandler handler) {
    auto existing = m_symbol_to_address.find(name);
    if (existing != m_symbol_to_address.end()) {
        uint32_t addr = existing->second;
        uint32_t svc = m_host.MemoryRead32(addr) & 0x00FFFFFF;
        m_id_to_handler[svc] = std::move(handler);
        m_id_to_name[svc] = name;
        PublishFastThunk(svc, name, m_id_to_handler[svc]);
        return addr;
    }

    uint32_t thunk_id = static_cast<uint32_t>(m_id_to_handler.size() + 1);
    uint32_t thunk_addr = m_next_thunk_addr;
    m_next_thunk_addr += 8; // 2 instructions per trampoline

    // Write ARM32 trampoline instructions into guest memory:
    // 0: SVC #thunk_id (0xEF000000 | thunk_id)
    // 4: BX LR (0xE12FFF1E)
    uint32_t svc_instr = 0xEF000000 | (thunk_id & 0x00FFFFFF);
    uint32_t bx_lr_instr = 0xE12FFF1E;

    m_host.MemoryWrite32(thunk_addr, svc_instr);
    m_host.MemoryWrite32(thunk_addr + 4, bx_lr_instr);
    // Trampolines are also created at runtime (dlsym, OpenSL ES vtables), so the JIT may
    // already hold a translation of this address range.
    m_host.InvalidateGuestCode(thunk_addr, 8);

    m_symbol_to_address[name] = thunk_addr;
    m_id_to_handler[thunk_id] = std::move(handler);
    m_id_to_name[thunk_id] = name;
    PublishFastThunk(thunk_id, name, m_id_to_handler[thunk_id]);
    return thunk_addr;
}

void ThunkManager::PublishFastThunk(uint32_t thunk_id, const std::string& name,
                                    const ThunkHandler& handler) {
    if (thunk_id >= kFastThunkCapacity) return;

    auto entry = std::make_unique<FastThunkEntry>();
    entry->name = name;
    entry->handler = handler;
    FastThunkEntry* published = entry.get();
    m_fast_thunk_storage.push_back(std::move(entry));
    m_fast_thunks[thunk_id].store(published, std::memory_order_release);
}

void ThunkManager::RegisterSymbol(const std::string& name, uint32_t address) {
    std::lock_guard<std::mutex> lock(m_registration_mutex);
    m_symbol_to_address[name] = address;
}

uint32_t ThunkManager::GetOrCreateThunkAddress(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_registration_mutex);
    auto it = m_symbol_to_address.find(name);
    if (it != m_symbol_to_address.end()) {
        return it->second;
    }
    // Default dummy stub if not explicitly registered
    return RegisterThunkLocked(name, [name](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("[THUNK] Default stub executed for: %s", name.c_str());
        jit.Regs()[0] = 0;
    });
}

uint32_t ThunkManager::FindThunkAddress(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_registration_mutex);
    auto it = m_symbol_to_address.find(name);
    return it == m_symbol_to_address.end() ? 0 : it->second;
}

// Last thunk invoked (name ptr) and a dispatch counter. Written on every SVC
// dispatch, read by the RunFunction watchdog to identify a stuck guest loop.
static std::atomic<const char*> g_last_thunk_name{nullptr};
static std::atomic<uint64_t> g_thunk_dispatch_count{0};
const char* LastThunkName() { return g_last_thunk_name.load(std::memory_order_relaxed); }
uint64_t ThunkDispatchCount() { return g_thunk_dispatch_count.load(std::memory_order_relaxed); }

#if MC4_ENABLE_NATIVE_LOGGING
thread_local std::array<ThunkManager::ProfileCounter, ThunkManager::kFastThunkCapacity>
    ThunkManager::s_thread_profile{};
thread_local uint64_t ThunkManager::s_thread_profile_overflow = 0;
#endif

void ThunkManager::DumpThreadProfile() {
#if MC4_ENABLE_NATIVE_LOGGING
    struct Rank {
        uint32_t id = 0;
        ProfileCounter counter{};
    };
    std::array<Rank, 12> top{};
    uint64_t total_calls = 0, total_ns = 0;
    for (uint32_t id = 0; id < kFastThunkCapacity; ++id) {
        const ProfileCounter sample = s_thread_profile[id];
        s_thread_profile[id] = {};
        if (!sample.calls) continue;
        total_calls += sample.calls;
        total_ns += sample.nanoseconds;
        for (size_t rank = 0; rank < top.size(); ++rank) {
            if (sample.nanoseconds > top[rank].counter.nanoseconds ||
                (sample.nanoseconds == top[rank].counter.nanoseconds &&
                 sample.calls > top[rank].counter.calls)) {
                for (size_t move = top.size() - 1; move > rank; --move)
                    top[move] = top[move - 1];
                top[rank] = {id, sample};
                break;
            }
        }
    }
    const uint64_t overflow = s_thread_profile_overflow;
    s_thread_profile_overflow = 0;
    LOGI("[THUNK-PERF] total_calls=%llu inclusive_us=%llu overflow=%llu",
         (unsigned long long)total_calls, (unsigned long long)(total_ns / 1000),
         (unsigned long long)overflow);
    for (const Rank& rank : top) {
        if (!rank.counter.calls) break;
        FastThunkEntry* entry = m_fast_thunks[rank.id].load(std::memory_order_acquire);
        LOGI("[THUNK-PERF] %.48s count=%llu us=%llu avg_ns=%llu",
             entry ? entry->name.c_str() : "?", (unsigned long long)rank.counter.calls,
             (unsigned long long)(rank.counter.nanoseconds / 1000),
             (unsigned long long)(rank.counter.nanoseconds / rank.counter.calls));
    }
#endif
}

// SVC dispatch runs thousands of times per frame on the render thread. Keep
// integer IDs in a thread-local ring; resolve/format names only on a crash.
namespace {
constexpr uint32_t kThunkHistorySize = 16;
static_assert((kThunkHistorySize & (kThunkHistorySize - 1)) == 0);
struct ThunkHistory {
    std::array<uint32_t, kThunkHistorySize> ids{};
    uint32_t next = 0;
    uint32_t size = 0;
};
thread_local ThunkHistory g_thunk_history;
}

uint32_t ThunkManager::CopyRecentThunkNames(char (*out)[48], uint32_t count) const {
    if (!out || !count) return 0;
    std::lock_guard<std::mutex> lock(m_registration_mutex);
    const uint32_t copied = std::min(count, g_thunk_history.size);
    const uint32_t oldest = (g_thunk_history.next + kThunkHistorySize - g_thunk_history.size) % kThunkHistorySize;
    for (uint32_t i = 0; i < copied; ++i) {
        const uint32_t id = g_thunk_history.ids[(oldest + i) % kThunkHistorySize];
        const auto it = m_id_to_name.find(id);
        std::snprintf(out[i], 48, "%s", it == m_id_to_name.end() ? "?" : it->second.c_str());
    }
    return copied;
}

std::string ThunkManager::FindThunkNameForProgramCounter(uint32_t guest_pc) const {
    if (guest_pc < 0x10000u || guest_pc >= 0x40000000u) return {};

    uint32_t trampoline = guest_pc & ~7u;
    if ((guest_pc & 7u) == 4u) trampoline = guest_pc - 4u;
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        const uint32_t addr = attempt == 0 ? trampoline : trampoline - 8u;
        if (addr < 0x10000u) break;
        const uint32_t instruction = m_host.MemoryRead32(addr);
        if ((instruction & 0xFF000000u) != 0xEF000000u) continue;

        const uint32_t thunk_id = instruction & 0x00FFFFFFu;
        if (thunk_id < kFastThunkCapacity) {
            FastThunkEntry* entry = m_fast_thunks[thunk_id].load(std::memory_order_acquire);
            if (entry) return entry->name;
        }

        std::lock_guard<std::mutex> lock(m_registration_mutex);
        const auto it = m_id_to_name.find(thunk_id);
        if (it != m_id_to_name.end()) return it->second;
    }
    return {};
}

void ThunkManager::DispatchThunkEntry(uint32_t thunk_id, const char* name,
                                      const ThunkHandler& handler,
                                      Dynarmic::A32::Jit& jit) {
    g_thunk_dispatch_count.fetch_add(1, std::memory_order_relaxed);
    g_last_thunk_name.store(name, std::memory_order_relaxed);
    g_thunk_history.ids[g_thunk_history.next] = thunk_id;
    g_thunk_history.next = (g_thunk_history.next + 1) & (kThunkHistorySize - 1);
    if (g_thunk_history.size < kThunkHistorySize) ++g_thunk_history.size;

    // A wild guest call can reach a thunk with garbage state; contain host
    // exceptions instead of letting them escape through the JIT frame.
    try {
#if MC4_ENABLE_NATIVE_LOGGING
        ProfileCounter* sample = thunk_id < kFastThunkCapacity
            ? &s_thread_profile[thunk_id] : nullptr;
        if (sample) ++sample->calls;
        else ++s_thread_profile_overflow;
        struct HandlerTime {
            ProfileCounter* sample;
            std::chrono::steady_clock::time_point started;
            ~HandlerTime() {
                if (sample) sample->nanoseconds += static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - started).count());
            }
        } timing{sample, sample ? std::chrono::steady_clock::now()
                                : std::chrono::steady_clock::time_point{}};
#endif
        handler(jit, m_host);
    } catch (const std::exception& e) {
        LOGE("[THUNK-EXC] %s threw: %s", name, e.what());
        jit.Regs()[0] = 0;
    } catch (...) {
        LOGE("[THUNK-EXC] %s threw (unknown)", name);
        jit.Regs()[0] = 0;
    }
}

void ThunkManager::DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit) {
    if (thunk_id < kFastThunkCapacity) {
        FastThunkEntry* entry = m_fast_thunks[thunk_id].load(std::memory_order_acquire);
        if (entry) {
            DispatchThunkEntry(thunk_id, entry->name.c_str(), entry->handler, jit);
            return;
        }
    }

    auto it = m_id_to_handler.find(thunk_id);

    if (it != m_id_to_handler.end()) {
        auto name_it = m_id_to_name.find(thunk_id);
        const char* name = name_it != m_id_to_name.end() ? name_it->second.c_str() : "?";
        DispatchThunkEntry(thunk_id, name, it->second, jit);
    } else {
        auto name_it = m_id_to_name.find(thunk_id);
        const char* name = (name_it != m_id_to_name.end()) ? name_it->second.c_str() : "unknown";
        LOGE("[THUNK] Unknown thunk ID: %u (%s) at PC: 0x%08X", thunk_id, name, jit.Regs()[15]);
        jit.Regs()[0] = 0;
    }
}
