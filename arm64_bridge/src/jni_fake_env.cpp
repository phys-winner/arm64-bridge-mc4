#include "jni_fake_env.h"
#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <algorithm>
#include <set>
#include <atomic>
#include <map>
#include <mutex>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <limits>

#define LOG_TAG "Arm32Bridge_FakeJni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// JNIEnv table slot count (through GetObjectRefType)
static thread_local JNIEnv* thread_local_env = nullptr;

static const uint32_t kEnvSlots = 233;

static const uint32_t kEnvTableBytes = kEnvSlots * 4;
// JavaVM (JNIInvokeInterface) slots: 0..7
static const uint32_t kVmSlots = 8;

FakeJniEnv& FakeJniEnv::Instance() {
    static FakeJniEnv inst;
    return inst;
}

void FakeJniEnv::Init(DynarmicHost& host) {
    if (m_host == &host) return;
    // Host was recreated (first load attempt failed before the Activity
    // existed) � old tables pointed into freed guest memory.
    m_host = &host;
    m_env_table = 0;
    m_vm_table = 0;
    m_next_obj_handle = 0x00020000;
    m_next_mid_handle = 0x00030000;
    m_next_fid_handle = 0x00040000;
    m_objects.clear();
    m_objects_by_hash.clear();
    m_lru.clear();
    m_methods.clear();
    m_fields.clear();
    m_method_ids.clear();
    m_field_ids.clear();
    m_direct_bufs.clear();
    m_jstr_utf.clear();
    m_primitive_array_kinds.clear();
    {
        std::lock_guard<std::mutex> critical_lock(m_primitive_array_mutex);
        m_primitive_array_leases.clear();
    }
    ThunkManager& tm = host.GetThunkManager();

    // Guest memory for tables
    m_env_table = host.GuestAlloc(kEnvTableBytes, 4);
    m_vm_table = host.GuestAlloc(kVmSlots * 4, 4);

    uint8_t* mem = host.GetGuestMemoryBase();
    auto register_slot = [&](uint32_t table, uint32_t offset, bool is_vm, const char* name) {
        uint32_t thunk = tm.RegisterThunk(
            std::string("jni_") + (is_vm ? "vm" : "env") + "_" + std::to_string(offset),
            [this, offset, is_vm](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                if (is_vm) DispatchVmSlot(offset, jit);
                else DispatchEnvSlot(offset, jit);
            });
        host.MemoryWrite32(table + offset, thunk);
    };

    // Register all env slots: known offsets get real handlers (via DispatchEnvSlot
    // switch), everything else logs-and-zeroes on first use.
    for (uint32_t off = 0; off < kEnvSlots; ++off) {
        register_slot(m_env_table, off * 4, false, nullptr);
    }
    for (uint32_t off = 0; off < kVmSlots; ++off) {
        register_slot(m_vm_table, off * 4, true, nullptr);
    }

    // JNI ABI: guest code does `ldr r, [env]; ldr r, [r, #off]; blx r` �
    // i.e. [env] must point to the function-pointer table itself. Slot 0 of
    // both tables is reserved by the spec, so make it a self-pointer.
    host.MemoryWrite32(m_env_table, m_env_table);
    host.MemoryWrite32(m_vm_table, m_vm_table);

    LOGI("Fake JNI tables: env=0x%08X (%u bytes), vm=0x%08X", m_env_table, kEnvTableBytes, m_vm_table);
}

void FakeJniEnv::AttachHostEnv(JNIEnv* env) {
    thread_local_env = env;
}

// A thread that attaches itself and then exits still attached leaves the
// runtime's Thread object behind, and a checked build aborts the process over
// it. Guest worker threads (audio, streaming, a JIT's own helpers) come and go
// and none of them knows it is talking to a bridge, so the detach hangs off a
// TLS destructor instead of being left to whoever created the thread. Only
// threads attached here get the key set - detaching one the VM owns is worse
// than leaking it.
static pthread_key_t s_detach_key;
static JavaVM* s_detach_vm = nullptr;

static void DetachOnThreadExit(void*) {
    if (s_detach_vm) s_detach_vm->DetachCurrentThread();
    thread_local_env = nullptr;
}

JNIEnv* FakeJniEnv::GetEnv() {
    if (thread_local_env) return thread_local_env;
    if (!m_vm) return nullptr;
    JNIEnv* env = nullptr;
    if (m_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
        thread_local_env = env;
        return env;
    }
    if (m_vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
        thread_local_env = env;
        static std::once_flag once;
        std::call_once(once, [this] {
            s_detach_vm = m_vm;
            pthread_key_create(&s_detach_key, DetachOnThreadExit);
        });
        pthread_setspecific(s_detach_key, reinterpret_cast<void*>(1));
    }
    return env;
}

// -------------------------------------------------------------
// Handles
// -------------------------------------------------------------

// Cap on live global refs. ART's own limit is 51200 and hitting it kills the
// process outright, so the table has to stay well under it and reclaim rather
// than stop caching - a "cache full, hand out a ref and forget it" branch is the
// original leak with a delay on it.
static const size_t kMaxObjectRefs = 8192;

int32_t FakeJniEnv::IdentityHash(JNIEnv* env, jobject o) {
    static jclass system = nullptr;
    static jmethodID identity_hash = nullptr;
    if (!identity_hash) {
        jclass local = env->FindClass("java/lang/System");
        if (!local) { env->ExceptionClear(); return 0; }
        if (!system) system = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        identity_hash = env->GetStaticMethodID(system, "identityHashCode", "(Ljava/lang/Object;)I");
        if (!identity_hash) { env->ExceptionClear(); return 0; }
    }
    int32_t h = env->CallStaticIntMethod(system, identity_hash, o);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return 0; }
    return h;
}

void FakeJniEnv::TouchRef(uint32_t handle) const {
    auto it = m_objects.find(handle);
    if (it != m_objects.end() && it->second.pins == 0) {
        m_lru.splice(m_lru.begin(), m_lru, it->second.lru);
    }
}

void FakeJniEnv::EvictOneRef(JNIEnv* env) {
    if (m_lru.empty()) return;  // everything pinned; the table grows past the cap
    uint32_t handle = m_lru.back();
    m_lru.pop_back();

    auto it = m_objects.find(handle);
    if (it == m_objects.end()) return;

    auto bucket = m_objects_by_hash.find(it->second.hash);
    if (bucket != m_objects_by_hash.end()) {
        auto& v = bucket->second;
        v.erase(std::remove(v.begin(), v.end(), handle), v.end());
        if (v.empty()) m_objects_by_hash.erase(bucket);
    }
    // The UTF-8 copy of a jstring lives as long as the jstring's handle does;
    // leaving it behind strands the arena block and, worse, keeps a dead handle
    // mapped to it.
    auto utf = m_jstr_utf.find(handle);
    if (utf != m_jstr_utf.end()) {
        if (m_host) m_host->GuestFree(utf->second);
        m_jstr_utf.erase(utf);
    }
    m_primitive_array_kinds.erase(handle);
    env->DeleteGlobalRef(it->second.global);
    m_objects.erase(it);
}

bool FakeJniEnv::GetPrimitiveArrayKind(JNIEnv* env, jobject array, uint32_t handle,
                                       PrimitiveArrayKind& kind) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto cached = m_primitive_array_kinds.find(handle);
        if (cached != m_primitive_array_kinds.end()) {
            kind = cached->second;
            return true;
        }
    }

    static constexpr const char* kArrayDescriptors[] = {
        "[Z", "[B", "[C", "[S", "[I", "[J", "[F", "[D",
    };
    std::lock_guard<std::mutex> critical_lock(m_primitive_array_mutex);
    for (size_t i = 0; i < m_primitive_array_classes.size(); ++i) {
        if (!m_primitive_array_classes[i]) {
            jclass local = env->FindClass(kArrayDescriptors[i]);
            if (!local) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("[JNI] cannot resolve primitive array class %s", kArrayDescriptors[i]);
                return false;
            }
            m_primitive_array_classes[i] = static_cast<jclass>(env->NewGlobalRef(local));
            env->DeleteLocalRef(local);
            if (!m_primitive_array_classes[i]) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("[JNI] cannot retain primitive array class %s", kArrayDescriptors[i]);
                return false;
            }
        }
        if (!env->IsInstanceOf(array, m_primitive_array_classes[i])) continue;

        kind = static_cast<PrimitiveArrayKind>(i);
        // The array is pinned by GetPrimitiveArrayCritical before this helper
        // is called, so its interned guest handle cannot be evicted here.
        std::lock_guard<std::mutex> object_lock(m_mutex);
        if (m_objects.find(handle) != m_objects.end())
            m_primitive_array_kinds[handle] = kind;
        return true;
    }
    return false;
}

uint32_t FakeJniEnv::AcquirePrimitiveArray(JNIEnv* env, uint32_t array_handle,
                                           uint32_t is_copy_out, PrimitiveArrayKind kind,
                                           bool critical) {
    if (!env || !m_host) return 0;

    jobject array = nullptr;
    {
        std::lock_guard<std::mutex> object_lock(m_mutex);
        auto it = m_objects.find(array_handle);
        if (it == m_objects.end()) return 0;
        if (it->second.pins == 0) m_lru.erase(it->second.lru);
        ++it->second.pins;
        array = it->second.global;
    }
    const auto unpin_array = [&] { PinObjectRef(array_handle, -1); };

    PrimitiveArrayKind actual_kind = kind;
    if (!GetPrimitiveArrayKind(env, array, array_handle, actual_kind) ||
        (!critical && actual_kind != kind)) {
        LOGE("[JNI] primitive-array type mismatch array=%08X expected=%u actual=%u",
             array_handle, static_cast<unsigned>(kind), static_cast<unsigned>(actual_kind));
        unpin_array();
        return 0;
    }
    kind = actual_kind;

    static constexpr size_t kElementSizes[] = {
        sizeof(jboolean), sizeof(jbyte), sizeof(jchar), sizeof(jshort),
        sizeof(jint), sizeof(jlong), sizeof(jfloat), sizeof(jdouble),
    };
    const jsize element_count = env->GetArrayLength(static_cast<jarray>(array));
    const size_t element_size = kElementSizes[static_cast<size_t>(kind)];
    const uint64_t byte_count64 = element_count < 0
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(element_count) * element_size;
    if (element_count < 0 || byte_count64 > std::numeric_limits<uint32_t>::max()) {
        unpin_array();
        return 0;
    }

    const size_t byte_count = static_cast<size_t>(byte_count64);
    const uint32_t guest = m_host->GuestAlloc(byte_count ? byte_count : 1, 16);
    if (!guest) {
        unpin_array();
        return 0;
    }

    void* source = nullptr;
    if (byte_count == 0) {
        m_host->GetGuestMemoryBase()[guest] = 0;
        source = m_host->GetGuestMemoryBase() + guest;
    } else if (critical) {
        source = env->GetPrimitiveArrayCritical(static_cast<jarray>(array), nullptr);
        if (source) {
            if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
            env->ReleasePrimitiveArrayCritical(static_cast<jarray>(array), source, JNI_ABORT);
        }
    } else {
        jboolean host_is_copy = JNI_FALSE;
        switch (kind) {
            case PrimitiveArrayKind::Boolean:
                source = env->GetBooleanArrayElements(static_cast<jbooleanArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseBooleanArrayElements(static_cast<jbooleanArray>(array),
                        static_cast<jboolean*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Byte:
                source = env->GetByteArrayElements(static_cast<jbyteArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseByteArrayElements(static_cast<jbyteArray>(array),
                        static_cast<jbyte*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Char:
                source = env->GetCharArrayElements(static_cast<jcharArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseCharArrayElements(static_cast<jcharArray>(array),
                        static_cast<jchar*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Short:
                source = env->GetShortArrayElements(static_cast<jshortArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseShortArrayElements(static_cast<jshortArray>(array),
                        static_cast<jshort*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Int:
                source = env->GetIntArrayElements(static_cast<jintArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseIntArrayElements(static_cast<jintArray>(array),
                        static_cast<jint*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Long:
                source = env->GetLongArrayElements(static_cast<jlongArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseLongArrayElements(static_cast<jlongArray>(array),
                        static_cast<jlong*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Float:
                source = env->GetFloatArrayElements(static_cast<jfloatArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseFloatArrayElements(static_cast<jfloatArray>(array),
                        static_cast<jfloat*>(source), JNI_ABORT);
                }
                break;
            case PrimitiveArrayKind::Double:
                source = env->GetDoubleArrayElements(static_cast<jdoubleArray>(array), &host_is_copy);
                if (source) {
                    if (byte_count) memcpy(m_host->GetGuestMemoryBase() + guest, source, byte_count);
                    env->ReleaseDoubleArrayElements(static_cast<jdoubleArray>(array),
                        static_cast<jdouble*>(source), JNI_ABORT);
                }
                break;
        }
    }

    if (!source) {
        m_host->GuestFree(guest);
        unpin_array();
        return 0;
    }

    PrimitiveArrayLease lease{array_handle, element_count, byte_count, kind};
    bool inserted = false;
    {
        std::lock_guard<std::mutex> critical_lock(m_primitive_array_mutex);
        inserted = m_primitive_array_leases.emplace(guest, lease).second;
    }
    if (!inserted) {
        LOGE("[JNI] duplicate primitive-array guest lease %08X", guest);
        m_host->GuestFree(guest);
        unpin_array();
        return 0;
    }

    if (is_copy_out) m_host->MemoryWrite8(is_copy_out, JNI_TRUE);
    if (critical) {
        static std::atomic<bool> logged_first_acquire{false};
        if (!logged_first_acquire.exchange(true, std::memory_order_relaxed))
            LOGI("[JNI-CRITICAL] acquired array=%08X kind=%u elements=%d bytes=%zu guest=%08X",
                 array_handle, static_cast<unsigned>(kind), element_count, byte_count, guest);
    }
    return guest;
}

void FakeJniEnv::ReleasePrimitiveArray(JNIEnv* env, uint32_t array_handle,
                                       uint32_t guest_addr, jint mode,
                                       const PrimitiveArrayKind* expected_kind) {
    if (!env || !m_host) return;

    PrimitiveArrayLease lease;
    bool found = false;
    {
        std::lock_guard<std::mutex> critical_lock(m_primitive_array_mutex);
        auto it = m_primitive_array_leases.find(guest_addr);
        if (it != m_primitive_array_leases.end() && it->second.array_handle == array_handle &&
            (!expected_kind || it->second.kind == *expected_kind)) {
            lease = it->second;
            found = true;
            if (mode != JNI_COMMIT) m_primitive_array_leases.erase(it);
        }
    }
    if (!found) {
        LOGE("[JNI] unmatched primitive-array release array=%08X guest=%08X mode=%d",
             array_handle, guest_addr, mode);
        return;
    }

    if (mode != JNI_ABORT && lease.byte_count) {
        jobject array = ResolveObject(array_handle);
        if (!array) {
            LOGE("[JNI] lost pinned primitive array handle=%08X", array_handle);
        } else {
            const void* data = m_host->GetGuestMemoryBase() + guest_addr;
            switch (lease.kind) {
                case PrimitiveArrayKind::Boolean:
                    env->SetBooleanArrayRegion(static_cast<jbooleanArray>(array), 0,
                        lease.element_count, static_cast<const jboolean*>(data));
                    break;
                case PrimitiveArrayKind::Byte:
                    env->SetByteArrayRegion(static_cast<jbyteArray>(array), 0,
                        lease.element_count, static_cast<const jbyte*>(data));
                    break;
                case PrimitiveArrayKind::Char:
                    env->SetCharArrayRegion(static_cast<jcharArray>(array), 0,
                        lease.element_count, static_cast<const jchar*>(data));
                    break;
                case PrimitiveArrayKind::Short:
                    env->SetShortArrayRegion(static_cast<jshortArray>(array), 0,
                        lease.element_count, static_cast<const jshort*>(data));
                    break;
                case PrimitiveArrayKind::Int:
                    env->SetIntArrayRegion(static_cast<jintArray>(array), 0,
                        lease.element_count, static_cast<const jint*>(data));
                    break;
                case PrimitiveArrayKind::Long:
                    env->SetLongArrayRegion(static_cast<jlongArray>(array), 0,
                        lease.element_count, static_cast<const jlong*>(data));
                    break;
                case PrimitiveArrayKind::Float:
                    env->SetFloatArrayRegion(static_cast<jfloatArray>(array), 0,
                        lease.element_count, static_cast<const jfloat*>(data));
                    break;
                case PrimitiveArrayKind::Double:
                    env->SetDoubleArrayRegion(static_cast<jdoubleArray>(array), 0,
                        lease.element_count, static_cast<const jdouble*>(data));
                    break;
            }
        }
    }

    if (expected_kind == nullptr) {
        static std::atomic<bool> logged_first_release{false};
        if (!logged_first_release.exchange(true, std::memory_order_relaxed))
            LOGI("[JNI-CRITICAL] released array=%08X guest=%08X mode=%d",
                 array_handle, guest_addr, mode);
    }
    if (mode != JNI_COMMIT) {
        m_host->GuestFree(guest_addr);
        PinObjectRef(array_handle, -1);
    }
}

uint32_t FakeJniEnv::AddObjectRef(jobject o) {
    if (!o) return 0;
    JNIEnv* env = GetEnv();
    if (!env) return 0;
    int32_t hash = IdentityHash(env, o);

    std::lock_guard<std::mutex> lk(m_mutex);
    for (uint32_t h : m_objects_by_hash[hash]) {
        auto it = m_objects.find(h);
        if (it != m_objects.end() && env->IsSameObject(it->second.global, o)) {
            TouchRef(h);
            return h;
        }
    }
    // Eviction rehashes both maps, so nothing looked up above survives it.
    if (m_objects.size() >= kMaxObjectRefs) EvictOneRef(env);

    jobject global = env->NewGlobalRef(o);
    if (!global) return 0;
    uint32_t h = m_next_obj_handle;
    m_next_obj_handle += 4;

    ObjRef& ref = m_objects[h];
    ref.global = global;
    ref.hash = hash;
    ref.pins = 0;
    m_lru.push_front(h);
    ref.lru = m_lru.begin();
    m_objects_by_hash[hash].push_back(h);
    return h;
}

jobject FakeJniEnv::ResolveObject(uint32_t handle) const {
    if (!handle) return nullptr;
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_objects.find(handle);
    if (it == m_objects.end()) return nullptr;
    // Resolving counts as using: an object a slot is part way through working
    // with must not be the one another thread picks to evict.
    TouchRef(handle);
    return it->second.global;
}

void FakeJniEnv::PinObjectRef(uint32_t handle, int delta) {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_objects.find(handle);
    if (it == m_objects.end()) return;
    ObjRef& ref = it->second;
    const bool was = ref.pins > 0;
    ref.pins += delta;
    if (ref.pins < 0) ref.pins = 0;
    const bool now = ref.pins > 0;
    if (now == was) return;
    if (now) {
        m_lru.erase(ref.lru);
    } else {
        m_lru.push_front(handle);
        ref.lru = m_lru.begin();
    }
}

void FakeJniEnv::DemoteObjectRef(uint32_t handle) {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_objects.find(handle);
    if (it != m_objects.end() && it->second.pins == 0) {
        m_lru.splice(m_lru.end(), m_lru, it->second.lru);
    }
}

// One id per jmethodID. Guests that reach Java through reflection ask for the
// same method on every call; appending unconditionally grew this table, and the
// signature string in each entry, for the life of the process.
//
// Dedup by mid alone is only correct because handles are interned: clsHandle for
// a given class is now stable, so the first registration's copy stays right.
uint32_t FakeJniEnv::AddMethod(jmethodID mid, bool isStatic, uint32_t clsHandle, const std::string& sig) {
    if (!mid) return 0;
    std::lock_guard<std::mutex> lk(m_mutex);
    auto known = m_method_ids.find(mid);
    if (known != m_method_ids.end()) return known->second;

    uint32_t h = m_next_mid_handle;
    m_next_mid_handle += 4;
    MethodInfo mi;
    mi.mid = mid;
    mi.isStatic = isStatic;
    mi.clsHandle = clsHandle;
    mi.sig = sig;
    m_methods[h] = mi;
    m_method_ids[mid] = h;
    return h;
}

uint32_t FakeJniEnv::AddField(jfieldID fid) {
    if (!fid) return 0;
    std::lock_guard<std::mutex> lk(m_mutex);
    auto known = m_field_ids.find(fid);
    if (known != m_field_ids.end()) return known->second;

    uint32_t h = m_next_fid_handle;
    m_next_fid_handle += 4;
    m_fields[h] = fid;
    m_field_ids[fid] = h;
    return h;
}

// -------------------------------------------------------------
// Signature parsing & guest arg reading
// -------------------------------------------------------------

std::vector<char> FakeJniEnv::ParseParams(const std::string& sig) const {
    std::vector<char> out;
    size_t i = sig.find('(');
    if (i == std::string::npos) return out;
    for (++i; i < sig.size() && sig[i] != ')'; ++i) {
        char c = sig[i];
        if (c == 'L') {
            while (sig[i] != ';') ++i;
            out.push_back('L');
        } else if (c == '[') {
            while (sig[i] == '[') ++i;
            if (sig[i] == 'L') while (sig[i] != ';') ++i;
            out.push_back('L');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// A-variant: r3 points to an array of jvalue (8 bytes each on ARM32)
std::vector<FakeJniEnv::GuestArg> FakeJniEnv::ReadArgsA(Dynarmic::A32::Jit& jit,
                                                        const std::vector<char>& params,
                                                        uint32_t jvalue_guest) {
    std::vector<GuestArg> args;
    uint8_t* mem = m_host->GetGuestMemoryBase();
    uint32_t p = jvalue_guest;
    for (char t : params) {
        GuestArg a;
        a.type = t;
        switch (t) {
            case 'L':
                a.obj = ResolveObject(*reinterpret_cast<uint32_t*>(mem + p));
                break;
            case 'J':
                a.v = *reinterpret_cast<uint64_t*>(mem + p);
                break;
            case 'D':
                a.v = *reinterpret_cast<uint64_t*>(mem + p);
                break;
            case 'F': {
                float f; memcpy(&f, mem + p, 4);
                a.v = *reinterpret_cast<uint32_t*>(mem + p);
                break;
            }
            default:
                a.v = static_cast<uint32_t>(*reinterpret_cast<uint32_t*>(mem + p));
                break;
        }
        args.push_back(a);
        p += 8;
    }
    return args;
}

// V-variant: r3 is a va_list (guest stack pointer); 64-bit slots aligned to 8
std::vector<FakeJniEnv::GuestArg> FakeJniEnv::ReadArgsV(Dynarmic::A32::Jit& jit,
                                                        const std::vector<char>& params,
                                                        uint32_t va_list_guest) {
    std::vector<GuestArg> args;
    uint8_t* mem = m_host->GetGuestMemoryBase();
    uint32_t p = va_list_guest;
    for (char t : params) {
        GuestArg a;
        a.type = t;
        if (t == 'J' || t == 'D' || t == 'F') {
            p = (p + 7) & ~7u;
            uint64_t raw = 0;
            memcpy(&raw, mem + p, sizeof(raw));
            p += 8;
            if (t == 'F') {
                double promoted;
                float f;
                memcpy(&promoted, &raw, sizeof(promoted));
                f = static_cast<float>(promoted); // C default argument promotion
                uint32_t bits;
                memcpy(&bits, &f, sizeof(bits));
                a.v = bits;
            } else {
                a.v = raw;
            }
        } else {
            uint32_t raw = *reinterpret_cast<uint32_t*>(mem + p);
            if (t == 'L') a.obj = ResolveObject(raw);
            else a.v = raw;
            p += 4;
        }
        args.push_back(a);
    }
    return args;
}

// Plain vararg: first vararg in r3, then guest stack
std::vector<FakeJniEnv::GuestArg> FakeJniEnv::ReadArgsVar(Dynarmic::A32::Jit& jit,
                                                          const std::vector<char>& params) {
    return ReadArgsVarFromReg(3, jit, params);
}

// Varargs starting at an arbitrary register (CallNonvirtual*: first arg is r4
// because env/obj/clazz/mid occupy r0-r3), continuing on the guest stack.
std::vector<FakeJniEnv::GuestArg> FakeJniEnv::ReadArgsVarFromReg(int first_reg,
                                                                 Dynarmic::A32::Jit& jit,
                                                                 const std::vector<char>& params) {
    std::vector<GuestArg> args;
    uint8_t* mem = m_host->GetGuestMemoryBase();
    // Regs r_first..r3, then the stack starting at sp (args already spilled
    // there by the guest per AAPCS).
    uint32_t p = jit.Regs()[13];
    int reg = first_reg;
    for (char t : params) {
        GuestArg a;
        a.type = t;
        if (t == 'J' || t == 'D' || t == 'F') {
            // AAPCS32 aligns 64-bit arguments to an even core-register pair or
            // an 8-byte stack slot. Variadic float arguments are promoted to double.
            if (reg <= 3 && (reg & 1)) ++reg;
            uint64_t raw64 = 0;
            if (reg <= 2) {
                raw64 = static_cast<uint64_t>(jit.Regs()[reg]) |
                        (static_cast<uint64_t>(jit.Regs()[reg + 1]) << 32);
                reg += 2;
            } else {
                reg = 4;
                p = (p + 7) & ~7u;
                memcpy(&raw64, mem + p, sizeof(raw64));
                p += 8;
            }
            if (t == 'F') {
                double promoted;
                float f;
                uint32_t bits;
                memcpy(&promoted, &raw64, sizeof(promoted));
                f = static_cast<float>(promoted);
                memcpy(&bits, &f, sizeof(bits));
                a.v = bits;
            } else {
                a.v = raw64;
            }
        } else {
            uint32_t raw;
            if (reg <= 3) {
                raw = jit.Regs()[reg++];
            } else {
                raw = *reinterpret_cast<uint32_t*>(mem + p);
                p += 4;
            }
            if (t == 'L') a.obj = ResolveObject(raw);
            else a.v = raw;
        }
        args.push_back(a);
    }
    return args;
}

// -------------------------------------------------------------
// Host-side call marshaling
// -------------------------------------------------------------

void FakeJniEnv::CallMethod(Dynarmic::A32::Jit& jit, uint32_t mid_handle, uint32_t obj_handle,
                            char retType, const std::vector<GuestArg>& args, bool isStatic,
                            bool isNonvirtual, uint32_t class_handle) {
    MethodInfo mi;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto mi_it = m_methods.find(mid_handle);
        if (mi_it == m_methods.end()) {
            LOGE("CallMethod: unknown method handle 0x%08X", mid_handle);
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
            return;
        }
        mi = mi_it->second; // copy; host JNI call below runs without the lock
    }
    jobject obj = ResolveObject(obj_handle);
    jclass clazz = isNonvirtual ? static_cast<jclass>(ResolveObject(class_handle)) : nullptr;
    if (!obj || (isNonvirtual && !clazz)) {
        jit.Regs()[0] = 0;
        jit.Regs()[1] = 0;
        return;
    }

    std::vector<jvalue> jvs(args.size());
    for (size_t i = 0; i < args.size(); ++i) {
        jvalue& jv = jvs[i];
        const GuestArg& a = args[i];
        switch (a.type) {
            case 'Z': jv.z = static_cast<jboolean>(a.v); break;
            case 'B': jv.b = static_cast<jbyte>(a.v); break;
            case 'C': jv.c = static_cast<jchar>(a.v); break;
            case 'S': jv.s = static_cast<jshort>(a.v); break;
            case 'I': jv.i = static_cast<jint>(a.v); break;
            case 'J': jv.j = static_cast<jlong>(a.v); break;
            case 'F': { float f; memcpy(&f, &a.v, 4); jv.f = f; break; }
            case 'D': { double d; memcpy(&d, &a.v, 8); jv.d = d; break; }
            case 'L': jv.l = a.obj; break;
        }
    }

    JNIEnv* env = GetEnv();
    if (!env) {
        jit.Regs()[0] = 0;
        jit.Regs()[1] = 0;
        return;
    }
    bool pending = env->ExceptionCheck();
    if (pending) { env->ExceptionClear(); }
    const jvalue* call_args = jvs.empty() ? nullptr : jvs.data();

    switch (retType) {
        case 'V':
            if (isStatic) env->CallStaticVoidMethodA(static_cast<jclass>(obj), mi.mid, call_args);
            else if (isNonvirtual) env->CallNonvirtualVoidMethodA(obj, clazz, mi.mid, call_args);
            else env->CallVoidMethodA(obj, mi.mid, call_args);
            break;
        case 'Z': {
            jboolean r = isStatic ? env->CallStaticBooleanMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                       : isNonvirtual ? env->CallNonvirtualBooleanMethodA(obj, clazz, mi.mid, call_args)
                                      : env->CallBooleanMethodA(obj, mi.mid, call_args);
#if MC4_ENABLE_JNI_BOOLEAN_PROBE
            // Bring-up probe: which boolean gates does the guest poll, and what
            // do they return? First 40 distinct mid results, plus EVERY
            // setCurrentContext(I) result (its per-index failures drive the
            // device-recreation loop).
            {
                static std::mutex zm;
                static std::set<jmethodID> zseen;
                static std::map<std::pair<jmethodID, uint32_t>, int> zctx;
                std::lock_guard<std::mutex> lk(zm);
                if (zseen.insert(mi.mid).second && zseen.size() <= 60)
                    LOGI("[JNI-PROBE] boolean call mid=%p -> %u (sig %s)",
                         (void*)mi.mid, r ? 1u : 0u, mi.sig.c_str());
                if (mi.sig == "(I)Z" && !args.empty()) {
                    auto key = std::make_pair(mi.mid, static_cast<uint32_t>(args[0].v));
                    if (++zctx[key] <= 6)
                        LOGI("[CTX-PROBE] setCurrentContext(%u) -> %u",
                             static_cast<uint32_t>(args[0].v), r ? 1u : 0u);
                }
            }
#endif
            jit.Regs()[0] = r ? 1 : 0;
            break;
        }
        case 'B': {
            jbyte r = isStatic ? env->CallStaticByteMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                     : isNonvirtual ? env->CallNonvirtualByteMethodA(obj, clazz, mi.mid, call_args)
                                    : env->CallByteMethodA(obj, mi.mid, call_args);
            jit.Regs()[0] = static_cast<uint32_t>(static_cast<int32_t>(r));
            break;
        }
        case 'C': {
            jchar r = isStatic ? env->CallStaticCharMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                     : isNonvirtual ? env->CallNonvirtualCharMethodA(obj, clazz, mi.mid, call_args)
                                    : env->CallCharMethodA(obj, mi.mid, call_args);
            jit.Regs()[0] = static_cast<uint32_t>(r);
            break;
        }
        case 'S': {
            jshort r = isStatic ? env->CallStaticShortMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                      : isNonvirtual ? env->CallNonvirtualShortMethodA(obj, clazz, mi.mid, call_args)
                                     : env->CallShortMethodA(obj, mi.mid, call_args);
            jit.Regs()[0] = static_cast<uint32_t>(static_cast<int32_t>(r));
            break;
        }
        case 'I': {
            jint r = isStatic ? env->CallStaticIntMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                    : isNonvirtual ? env->CallNonvirtualIntMethodA(obj, clazz, mi.mid, call_args)
                                   : env->CallIntMethodA(obj, mi.mid, call_args);
            jit.Regs()[0] = static_cast<uint32_t>(r);
            break;
        }
        case 'J': {
            jlong r = isStatic ? env->CallStaticLongMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                     : isNonvirtual ? env->CallNonvirtualLongMethodA(obj, clazz, mi.mid, call_args)
                                    : env->CallLongMethodA(obj, mi.mid, call_args);
            jit.Regs()[0] = static_cast<uint32_t>(r & 0xFFFFFFFFu);
            jit.Regs()[1] = static_cast<uint32_t>(static_cast<uint64_t>(r) >> 32);
            break;
        }
        case 'F': {
            jfloat r = isStatic ? env->CallStaticFloatMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                      : isNonvirtual ? env->CallNonvirtualFloatMethodA(obj, clazz, mi.mid, call_args)
                                     : env->CallFloatMethodA(obj, mi.mid, call_args);
            WriteSF(jit, 0, r);
            break;
        }
        case 'D': {
            jdouble r = isStatic ? env->CallStaticDoubleMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                       : isNonvirtual ? env->CallNonvirtualDoubleMethodA(obj, clazz, mi.mid, call_args)
                                      : env->CallDoubleMethodA(obj, mi.mid, call_args);
            WriteDF(jit, 0, r);
            break;
        }
        case 'L': {
            jobject r = isStatic ? env->CallStaticObjectMethodA(static_cast<jclass>(obj), mi.mid, call_args)
                       : isNonvirtual ? env->CallNonvirtualObjectMethodA(obj, clazz, mi.mid, call_args)
                                      : env->CallObjectMethodA(obj, mi.mid, call_args);
            // Bring-up: name any Java exception a guest-initiated call raised.
            if (env->ExceptionCheck()) {
                jthrowable ex = env->ExceptionOccurred();
                if (ex) {
                    jclass cls = env->GetObjectClass(ex);
                    jmethodID getName = env->GetMethodID(cls, "getName", "()Ljava/lang/String;");
                    jstring nm = getName ? (jstring)env->CallObjectMethod(ex, getName) : nullptr;
                    const char* s = nm ? env->GetStringUTFChars(nm, nullptr) : nullptr;
                    LOGE("[JAVA-EXC] static=%d nonvirtual=%d sig=%s -> %s",
                         isStatic, isNonvirtual, mi.sig.c_str(), s ? s : "?");
                    if (s) env->ReleaseStringUTFChars(nm, s);
                    env->DeleteLocalRef(nm);
                    env->DeleteLocalRef(cls);
                    env->DeleteLocalRef(ex);
                }
                env->ExceptionClear();
            }
            jit.Regs()[0] = AddObjectRef(r);
            if (r) env->DeleteLocalRef(r);
            break;
        }
        default:
            jit.Regs()[0] = 0;
            break;
    }
}

// -------------------------------------------------------------
// Direct ByteBuffer bridging
// -------------------------------------------------------------

uint32_t FakeJniEnv::RegisterDirectBuffer(jobject buf) {
    JNIEnv* env = GetEnv();
    if (!env) return 0;
    // fmodProcess hands us the same ByteBuffer on every audio callback (~125/s).
    // A fresh entry per call burned a permanent JNI global ref and a
    // capacity-sized arena block each time. One entry per live buffer, so the
    // scan is over one or two elements.
    for (const auto& [h, db] : m_direct_bufs) {
        if (env->IsSameObject(db.jobj, buf)) return h;
    }
    void* p = env->GetDirectBufferAddress(buf);
    jlong cap = env->GetDirectBufferCapacity(buf);
    if (!p || cap <= 0) return 0;
    uint32_t handle = m_next_obj_handle;
    m_next_obj_handle += 4;
    DirectBuf db;
    db.jobj = env->NewGlobalRef(buf);
    db.hostPtr = p;
    db.capacity = cap;
    db.scratch = m_host->GuestAlloc(static_cast<size_t>(cap), 16);
    m_direct_bufs[handle] = db;
    return handle;
}

void FakeJniEnv::CommitDirectBuffer(uint32_t handle) {
    auto it = m_direct_bufs.find(handle);
    if (it == m_direct_bufs.end()) return;
    DirectBuf& db = it->second;
    memcpy(db.hostPtr, m_host->GetGuestMemoryBase() + db.scratch, static_cast<size_t>(db.capacity));
}

jlong FakeJniEnv::DirectBufferCapacity(uint32_t handle) const {
    auto it = m_direct_bufs.find(handle);
    return (it != m_direct_bufs.end()) ? it->second.capacity : 0;
}

// -------------------------------------------------------------
// Dispatch
// -------------------------------------------------------------

// Helpers
static const char* ReadGuestStr(DynarmicHost& host, uint32_t gaddr) {
    if (!gaddr) return nullptr;
    return reinterpret_cast<const char*>(host.GetGuestMemoryBase() + gaddr);
}

void FakeJniEnv::DispatchVmSlot(uint32_t offset, Dynarmic::A32::Jit& jit) {
    LOGI("[JNI-VM] slot %u (off 0x%X) r0=0x%08X r1=0x%08X r2=0x%08X lr=0x%08X", offset / 4, offset, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[14]);
    switch (offset) {
        case 16: // AttachCurrentThread(vm, penv, args)
        case 24: // GetEnv(vm, penv, version)
        case 28: // AttachCurrentThreadAsDaemon(vm, penv, args)
        {
            uint32_t out = jit.Regs()[1];
            if (out) m_host->MemoryWrite32(out, m_env_table);
            jit.Regs()[0] = 0; // JNI_OK
            break;
        }
        case 20: // DetachCurrentThread(vm)
        {
            jit.Regs()[0] = 0; // JNI_OK
            break;
        }
        default:
            static bool warned_vm[64];
            if (offset / 4 < 64 && !warned_vm[offset / 4]) {
                warned_vm[offset / 4] = true;
                LOGI("[JNI-VM] unhandled slot %u (off 0x%X) at PC 0x%08X", offset / 4, offset, jit.Regs()[15]);
            }
            jit.Regs()[0] = 0;
            break;
    }
}

// Bring-up JNI tail ring (see DispatchEnvSlot).
static uint32_t* g_jni_ring_off = nullptr;
static uint32_t* g_jni_ring_lr = nullptr;
static uint32_t g_jni_ring_i = 0;

std::string FakeJniEnv::JniDispatchTail() const {
    if (!g_jni_ring_off || g_jni_ring_i == 0) return "(empty)";
    char line[32];
    std::string out;
    uint32_t start = g_jni_ring_i > 24 ? g_jni_ring_i - 24 : 0;
    for (uint32_t i = start; i < g_jni_ring_i; ++i) {
        uint32_t idx = i & 31;
        snprintf(line, sizeof(line), "%u@%08X:LR%08X ", g_jni_ring_off[idx] / 4,
                 g_jni_ring_off[idx], g_jni_ring_lr[idx]);
        out += line;
    }
    return out;
}

void FakeJniEnv::DispatchEnvSlot(uint32_t offset, Dynarmic::A32::Jit& jit) {
    JNIEnv* e = GetEnv();
    uint8_t* mem = m_host->GetGuestMemoryBase();

    // Bring-up: ring of the last JNI dispatches; GL2_init dumps the tail when
    // the guest init returns, to name the call right before an early exit.
    {
        static uint32_t ring_off[32];
        static uint32_t ring_lr[32];
        static uint32_t ring_i = 0;
        ring_off[ring_i & 31] = offset;
        ring_lr[ring_i & 31] = jit.Regs()[14];
        ++ring_i;
        g_jni_ring_off = ring_off;
        g_jni_ring_lr = ring_lr;
        g_jni_ring_i = ring_i;
    }

    if (!e) {
        LOGE("[JNI] no host env attached (slot %u)", offset / 4);
        jit.Regs()[0] = 0;
        return;
    }

    auto dispatch_method_call = [&](char ret_type, uint32_t base_offset,
                                    bool is_static, bool is_nonvirtual) {
        const uint32_t mid_handle = jit.Regs()[is_nonvirtual ? 3 : 2];
        const uint32_t obj_handle = jit.Regs()[1];
        const uint32_t class_handle = is_nonvirtual ? jit.Regs()[2] : 0;
        std::string signature;
        {
            std::lock_guard<std::mutex> method_lock(m_mutex);
            auto it = m_methods.find(mid_handle);
            if (it == m_methods.end()) {
                LOGE("[JNI] method call has unknown method handle=%08X at slot %u",
                     mid_handle, offset / 4);
                jit.Regs()[0] = 0;
                jit.Regs()[1] = 0;
                return;
            }
            signature = it->second.sig;
        }
        const std::vector<char> params = ParseParams(signature);
        const uint32_t variant = offset - base_offset;
        std::vector<GuestArg> args;
        if (variant == 0) {
            args = ReadArgsVarFromReg(is_nonvirtual ? 4 : 3, jit, params);
        } else if (variant == 4) {
            args = ReadArgsV(jit, params, jit.Regs()[is_nonvirtual ? 4 : 3]);
        } else if (variant == 8) {
            args = ReadArgsA(jit, params, jit.Regs()[is_nonvirtual ? 4 : 3]);
        } else {
            LOGE("[JNI] invalid method variant offset=%u base=%u", offset, base_offset);
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
            return;
        }
        CallMethod(jit, mid_handle, obj_handle, ret_type, args,
                   is_static, is_nonvirtual, class_handle);
    };

    switch (offset) {
        // ---- class / object basics ----
        case 24: { // FindClass
            const char* name = ReadGuestStr(*m_host, jit.Regs()[1]);
            jclass c = e->FindClass(name);
            if (!c) { e->ExceptionClear(); jit.Regs()[0] = 0; }
            else {
                jit.Regs()[0] = AddObjectRef(c);
                e->DeleteLocalRef(c);
            }
            break;
        }
        case 40: { // GetSuperclass
            jobject o = ResolveObject(jit.Regs()[1]);
            jclass c = e->GetSuperclass(static_cast<jclass>(o));
            jit.Regs()[0] = c ? AddObjectRef(c) : 0;
            if (c) e->DeleteLocalRef(c);
            break;
        }
        // Handles are shared, so dropping the host ref in DeleteGlobalRef/
        // DeleteLocalRef would invalidate any copy the guest still holds. What
        // the three calls do instead is set how willing the table is to reclaim
        // the entry - which is as close to the real lifetime as a shared handle
        // gets, and it is what keeps the table off ART's 51200 limit.
        case 84: { // NewGlobalRef -> same handle, plus a pin
            jobject o = ResolveObject(jit.Regs()[1]);
            if (!o) { jit.Regs()[0] = 0; break; }
            PinObjectRef(jit.Regs()[1], +1);
            jit.Regs()[0] = jit.Regs()[1];
            break;
        }
        case 88: // DeleteGlobalRef -> drop the pin
            PinObjectRef(jit.Regs()[1], -1);
            jit.Regs()[0] = 0;
            break;
        case 92: // DeleteLocalRef -> next in line to be evicted
            DemoteObjectRef(jit.Regs()[1]);
            jit.Regs()[0] = 0;
            break;
        case 76: // PushLocalFrame; guest handles are shared interned refs, not JNI locals
            jit.Regs()[0] = 0; // JNI_OK
            break;
        case 80: // PopLocalFrame; preserve the returned guest handle
            jit.Regs()[0] = jit.Regs()[1];
            break;
        case 100: { // NewLocalRef
            jobject o = ResolveObject(jit.Regs()[1]);
            jit.Regs()[0] = AddObjectRef(o);
            break;
        }
        case 124: { // GetObjectClass
            jobject o = ResolveObject(jit.Regs()[1]);
            if (!o) { jit.Regs()[0] = 0; break; } // guest expects null, ART would abort
            jclass c = e->GetObjectClass(o);
            jit.Regs()[0] = c ? AddObjectRef(c) : 0;
            if (c) e->DeleteLocalRef(c);
            break;
        }
        case 128: { // IsInstanceOf
            jobject o = ResolveObject(jit.Regs()[1]);
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[2]));
            jit.Regs()[0] = e->IsInstanceOf(o, c) ? 1 : 0;
            break;
        }

        // ---- method/field IDs ----
        case 132: { // GetMethodID
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            const char* name = ReadGuestStr(*m_host, jit.Regs()[2]);
            const char* sig = ReadGuestStr(*m_host, jit.Regs()[3]);
            if (!c) { jit.Regs()[0] = 0; break; }
            jmethodID mid = e->GetMethodID(c, name, sig);
            if (!mid) {
                e->ExceptionClear();
                LOGE("[JNI] GetMethodID failed: %s%s (cls=0x%08X)", name, sig, jit.Regs()[1]);
                jit.Regs()[0] = 0;
            } else {
                jit.Regs()[0] = AddMethod(mid, false, jit.Regs()[1], sig);
            }
            break;
        }
        case 376: { // GetFieldID
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            const char* name = ReadGuestStr(*m_host, jit.Regs()[2]);
            const char* sig = ReadGuestStr(*m_host, jit.Regs()[3]);
            jfieldID fid = e->GetFieldID(c, name, sig);
            if (!fid) {
                e->ExceptionClear();
                LOGE("[JNI] GetFieldID failed: %s%s", name, sig);
                jit.Regs()[0] = 0;
            } else {
                jit.Regs()[0] = AddField(fid);
            }
            break;
        }
        // ---- static fields (GDRMPolicy.setConst/setLongConst and the whole
        // game-state persistence live here; unhandled stubs made the guest's
        // license/catalog state read as garbage and looped the loader) ----
        case 576: { // GetStaticFieldID
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            const char* name = ReadGuestStr(*m_host, jit.Regs()[2]);
            const char* sig = ReadGuestStr(*m_host, jit.Regs()[3]);
            if (!c) { jit.Regs()[0] = 0; break; }
            jfieldID fid = e->GetStaticFieldID(c, name, sig);
            if (!fid) {
                e->ExceptionClear();
                LOGE("[JNI] GetStaticFieldID failed: %s%s", name ? name : "?", sig ? sig : "?");
                jit.Regs()[0] = 0;
            } else {
                jit.Regs()[0] = AddField(fid);
            }
            break;
        }
        case 580: { // GetStaticObjectField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            if (!c || it == m_fields.end()) { jit.Regs()[0] = 0; break; }
            jobject r = e->GetStaticObjectField(c, it->second);
            jit.Regs()[0] = r ? AddObjectRef(r) : 0;
            if (r) e->DeleteLocalRef(r);
            break;
        }
        case 584: { // GetStaticBooleanField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            if (!c || it == m_fields.end()) { jit.Regs()[0] = 0; break; }
            jit.Regs()[0] = e->GetStaticBooleanField(c, it->second) ? 1u : 0u;
            break;
        }
        case 600: { // GetStaticIntField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            if (!c || it == m_fields.end()) { jit.Regs()[0] = 0; break; }
            jit.Regs()[0] = static_cast<uint32_t>(e->GetStaticIntField(c, it->second));
            break;
        }
        case 604: { // GetStaticLongField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            if (!c || it == m_fields.end()) { jit.Regs()[1] = 0; break; }
            jlong v = e->GetStaticLongField(c, it->second);
            jit.Regs()[0] = static_cast<uint32_t>(v & 0xFFFFFFFFu);
            jit.Regs()[1] = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
            break;
        }
        case 616: { // SetStaticObjectField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            jobject v = ResolveObject(jit.Regs()[3]);
            if (c && it != m_fields.end()) e->SetStaticObjectField(c, it->second, v);
            break;
        }
        case 636: { // SetStaticIntField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            if (c && it != m_fields.end()) e->SetStaticIntField(c, it->second, static_cast<jint>(jit.Regs()[3]));
            break;
        }
        case 640: { // SetStaticLongField
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            auto it = m_fields.find(jit.Regs()[2]);
            if (c && it != m_fields.end()) {
                jlong v = (static_cast<jlong>(jit.Regs()[4]) << 32) | jit.Regs()[3];
                e->SetStaticLongField(c, it->second, v);
            }
            break;
        }

        case 452: { // GetStaticMethodID
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            const char* name = ReadGuestStr(*m_host, jit.Regs()[2]);
            const char* sig = ReadGuestStr(*m_host, jit.Regs()[3]);
            if (!c) { jit.Regs()[0] = 0; break; }
            // Bring-up probe: which static methods does the guest resolve?
            {
                static std::mutex log_m;
                static std::set<std::string> seen;
                std::lock_guard<std::mutex> lk(log_m);
                std::string key = std::string(name ? name : "?") + (sig ? sig : "");
                if (seen.insert(key).second && seen.size() <= 60)
                    LOGI("[JNI-PROBE] GetStaticMethodID %s", key.c_str());
            }
            jmethodID mid = e->GetStaticMethodID(c, name, sig);
            if (!mid) {
                e->ExceptionClear();
                LOGE("[JNI] GetStaticMethodID failed: %s%s (cls=0x%08X)", name, sig, jit.Regs()[1]);
                jit.Regs()[0] = 0;
            } else {
                {
                    static std::mutex rm;
                    static std::set<std::string> rseen;
                    std::lock_guard<std::mutex> lk(rm);
                    std::string key = std::string(name ? name : "?") + (sig ? sig : "");
                    if (rseen.insert(key).second)
                        LOGI("[JNI-PROBE] resolved %s%s as mid=%p",
                             name ? name : "?", sig ? sig : "", (void*)mid);
                }
                uint32_t mh = AddMethod(mid, true, jit.Regs()[1], sig);
                auto mit = m_methods.find(mh);
                if (mit != m_methods.end() && mit->second.name.empty() && name)
                    mit->second.name = name;
                jit.Regs()[0] = mh;
            }
            break;
        }

        // ---- object creation ----
        case 112: // NewObject (varargs)
        case 116: // NewObjectV
        case 120: { // NewObjectA
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            uint32_t mid_handle = jit.Regs()[2];
            MethodInfo mi;
            {
                std::lock_guard<std::mutex> method_lock(m_mutex);
                auto mi_it = m_methods.find(mid_handle);
                if (mi_it == m_methods.end()) { jit.Regs()[0] = 0; break; }
                mi = mi_it->second;
            }
            if (!c) { jit.Regs()[0] = 0; break; }
            std::vector<char> params = ParseParams(mi.sig);
            std::vector<GuestArg> args = offset == 112 ? ReadArgsVar(jit, params)
                                        : offset == 116 ? ReadArgsV(jit, params, jit.Regs()[3])
                                                        : ReadArgsA(jit, params, jit.Regs()[3]);
            // Build jvalues and call NewObjectA
            std::vector<jvalue> jvs(args.size());
            for (size_t i = 0; i < args.size(); ++i) {
                const GuestArg& a = args[i];
                switch (a.type) {
                    case 'Z': jvs[i].z = static_cast<jboolean>(a.v); break;
                    case 'B': jvs[i].b = static_cast<jbyte>(a.v); break;
                    case 'C': jvs[i].c = static_cast<jchar>(a.v); break;
                    case 'S': jvs[i].s = static_cast<jshort>(a.v); break;
                    case 'I': jvs[i].i = static_cast<jint>(a.v); break;
                    case 'J': jvs[i].j = static_cast<jlong>(a.v); break;
                    case 'F': { float f; memcpy(&f, &a.v, 4); jvs[i].f = f; break; }
                    case 'D': { double d; memcpy(&d, &a.v, 8); jvs[i].d = d; break; }
                    case 'L': jvs[i].l = a.obj; break;
                }
            }
            jobject o = e->NewObjectA(c, mi.mid, jvs.empty() ? nullptr : jvs.data());
            if (!o) { e->ExceptionClear(); LOGE("[JNI] NewObject failed"); jit.Regs()[0] = 0; }
            else {
                jit.Regs()[0] = AddObjectRef(o);
                e->DeleteLocalRef(o);
            }
            break;
        }

        // ---- instance method calls (JNI table offsets verified against NDK jni.h) ----
        case 136: case 140: case 144:
            dispatch_method_call('L', 136, false, false); break;
        case 148: case 152: case 156:
            dispatch_method_call('Z', 148, false, false); break;
        case 160: case 164: case 168:
            dispatch_method_call('B', 160, false, false); break;
        case 172: case 176: case 180:
            dispatch_method_call('C', 172, false, false); break;
        case 184: case 188: case 192:
            dispatch_method_call('S', 184, false, false); break;
        case 196: case 200: case 204:
            dispatch_method_call('I', 196, false, false); break;
        case 208: case 212: case 216:
            dispatch_method_call('J', 208, false, false); break;
        case 220: case 224: case 228:
            dispatch_method_call('F', 220, false, false); break;
        case 232: case 236: case 240:
            dispatch_method_call('D', 232, false, false); break;
        case 244: case 248: case 252:
            dispatch_method_call('V', 244, false, false); break;

        // Nonvirtual JNI methods require the explicit clazz argument. Arguments
        // begin in r4 (or the va_list/jvalue pointer in r4), unlike virtual calls.
        case 256: case 260: case 264:
            dispatch_method_call('L', 256, false, true); break;
        case 268: case 272: case 276:
            dispatch_method_call('Z', 268, false, true); break;
        case 280: case 284: case 288:
            dispatch_method_call('B', 280, false, true); break;
        case 292: case 296: case 300:
            dispatch_method_call('C', 292, false, true); break;
        case 304: case 308: case 312:
            dispatch_method_call('S', 304, false, true); break;
        case 316: case 320: case 324:
            dispatch_method_call('I', 316, false, true); break;
        case 328: case 332: case 336:
            dispatch_method_call('J', 328, false, true); break;
        case 340: case 344: case 348:
            dispatch_method_call('F', 340, false, true); break;
        case 352: case 356: case 360:
            dispatch_method_call('D', 352, false, true); break;
        case 364: case 368: case 372:
            dispatch_method_call('V', 364, false, true); break;

        // ---- static method calls ----
        case 456: case 460: case 464: { // CallStaticObjectMethod / V / A
            // Bring-up: the getPatchFileLocation hot loop polls through here;
            // log clazz/mid handles per call to see which one churns.
            {
                static std::atomic<uint32_t> csom{0};
                uint32_t n = csom.fetch_add(1, std::memory_order_relaxed) + 1;
                if (n <= 40 || (n % 500) == 0) {
                    auto mit = m_methods.find(jit.Regs()[2]);
                    const char* mname = mit != m_methods.end() ? mit->second.name.c_str() : "?";
                    LOGI("[CSOM] n=%u clazz=%08X mid=%08X LR=%08X %s sig=%s", n,
                         jit.Regs()[1], jit.Regs()[2], jit.Regs()[14],
                         mname, mit != m_methods.end() ? mit->second.sig.c_str() : "?");
                    // Bring-up: stack walk on the OBB poll to find the real
                    // re-entry driver (direct bl vs function-pointer table).
                    if (strcmp(mname, "getPatchFileLocation") == 0) {
                        uint8_t* mem = m_host->GetGuestMemoryBase();
                        if (mem) {
                            uint32_t sp = jit.Regs()[13];
                            char line[192]; int off = 0;
                            off += snprintf(line + off, sizeof(line) - off, "[POLL-STACK]");
                            for (int w = 0; w < 16 && off < (int)sizeof(line); ++w)
                                off += snprintf(line + off, sizeof(line) - off, " +%02x=%08X", w * 4,
                                                *reinterpret_cast<uint32_t*>(mem + sp + w * 4));
                            if (off < (int)sizeof(line)) off += snprintf(line + off, sizeof(line) - off, " SP=%08X", sp);
                            LOGI("%s", line);
                        }
                    }
                }
            }
            std::vector<char> params = ParseParams(m_methods[jit.Regs()[2]].sig);
            std::vector<GuestArg> args = (offset == 456) ? ReadArgsVar(jit, params)
                                        : (offset == 460) ? ReadArgsV(jit, params, jit.Regs()[3])
                                        : ReadArgsA(jit, params, jit.Regs()[3]);
            // Bring-up: per-iteration trace of the poll loop - log ALL JNI
            // method calls (any kind) for one full getPatchFileLocation cycle.
            {
                static std::atomic<uint32_t> all_calls{0};
                uint32_t n = all_calls.fetch_add(1, std::memory_order_relaxed) + 1;
                if (n >= 56000 && n < 56060) {
                    auto mit = m_methods.find(jit.Regs()[2]);
                    char a[64] = ""; 
                    if (args.size() >= 1)
                        snprintf(a, sizeof(a), " arg0=%08llX",
                                 static_cast<unsigned long long>(args[0].v));
                    LOGI("[JNI-ALL] n=%u mid=%08X %s sig=%s%s", n, jit.Regs()[2],
                         mit != m_methods.end() ? mit->second.name.c_str() : "?",
                         mit != m_methods.end() ? mit->second.sig.c_str() : "?", a);
                }
                if (n >= 56060) all_calls.store(0, std::memory_order_relaxed);
            }
            CallMethod(jit, jit.Regs()[2], jit.Regs()[1], 'L', args, true);
            break;
        }
        case 468: case 472: case 476: { // CallStaticBooleanMethod / V / A
            std::vector<char> params = ParseParams(m_methods[jit.Regs()[2]].sig);
            std::vector<GuestArg> args = (offset == 468) ? ReadArgsVar(jit, params)
                                        : (offset == 472) ? ReadArgsV(jit, params, jit.Regs()[3])
                                        : ReadArgsA(jit, params, jit.Regs()[3]);
            CallMethod(jit, jit.Regs()[2], jit.Regs()[1], 'Z', args, true);
            break;
        }
        case 516: case 520: case 524: { // CallStaticIntMethod / V / A
            std::vector<char> params = ParseParams(m_methods[jit.Regs()[2]].sig);
            std::vector<GuestArg> args = (offset == 516) ? ReadArgsVar(jit, params)
                                        : (offset == 520) ? ReadArgsV(jit, params, jit.Regs()[3])
                                        : ReadArgsA(jit, params, jit.Regs()[3]);
            CallMethod(jit, jit.Regs()[2], jit.Regs()[1], 'I', args, true);
            break;
        }
        case 528: case 532: case 536: { // CallStaticLongMethod / V / A
            std::vector<char> params = ParseParams(m_methods[jit.Regs()[2]].sig);
            std::vector<GuestArg> args = (offset == 528) ? ReadArgsVar(jit, params)
                                        : (offset == 532) ? ReadArgsV(jit, params, jit.Regs()[3])
                                        : ReadArgsA(jit, params, jit.Regs()[3]);
            CallMethod(jit, jit.Regs()[2], jit.Regs()[1], 'J', args, true);
            break;
        }
        case 564: case 568: case 572: { // CallStaticVoidMethod / V / A
            std::vector<char> params = ParseParams(m_methods[jit.Regs()[2]].sig);
            std::vector<GuestArg> args = (offset == 564) ? ReadArgsVar(jit, params)
                                        : (offset == 568) ? ReadArgsV(jit, params, jit.Regs()[3])
                                        : ReadArgsA(jit, params, jit.Regs()[3]);
            CallMethod(jit, jit.Regs()[2], jit.Regs()[1], 'V', args, true);
            break;
        }
        case 480: case 484: case 488:
            dispatch_method_call('B', 480, true, false); break;
        case 492: case 496: case 500:
            dispatch_method_call('C', 492, true, false); break;
        case 504: case 508: case 512:
            dispatch_method_call('S', 504, true, false); break;
        case 540: case 544: case 548:
            dispatch_method_call('F', 540, true, false); break;
        case 552: case 556: case 560:
            dispatch_method_call('D', 552, true, false); break;

        // ---- field access ----
        case 400: { // GetIntField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (!o || it == m_fields.end()) { jit.Regs()[0] = 0; break; }
            jit.Regs()[0] = static_cast<uint32_t>(e->GetIntField(o, it->second));
            break;
        }
        case 380: { // GetObjectField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (!o || it == m_fields.end()) { jit.Regs()[0] = 0; break; }
            jobject r = e->GetObjectField(o, it->second);
            jit.Regs()[0] = r ? AddObjectRef(r) : 0;
            if (r) e->DeleteLocalRef(r);
            break;
        }

        // ---- strings ----
        case 668: { // NewStringUTF
            const char* s = ReadGuestStr(*m_host, jit.Regs()[1]);
            jstring js = e->NewStringUTF(s ? s : "");
            jit.Regs()[0] = AddObjectRef(js);
            if (js) e->DeleteLocalRef(js);
            break;
        }
        case 656: { // GetStringLength
            jstring s = static_cast<jstring>(ResolveObject(jit.Regs()[1]));
            jit.Regs()[0] = s ? static_cast<uint32_t>(e->GetStringLength(s)) : 0;
            break;
        }
        case 660: { // GetStringChars (UTF-16)
            jstring s = static_cast<jstring>(ResolveObject(jit.Regs()[1]));
            if (!s) { jit.Regs()[0] = 0; break; }
            const jchar* chars = e->GetStringChars(s, nullptr);
            jsize len = e->GetStringLength(s);
            uint32_t guest = m_host->GuestAlloc((len + 1) * 2, 4);
            memcpy(mem + guest, chars, len * 2);
            memset(mem + guest + len * 2, 0, 2);
            e->ReleaseStringChars(s, chars);
            jit.Regs()[0] = guest;
            break;
        }
        case 664: // ReleaseStringChars -> the copy is ours, and this is the only
                  // call that says when it stops being needed
            m_host->GuestFree(jit.Regs()[2]);
            jit.Regs()[0] = 0;
            break;
        case 676: { // GetStringUTFChars
            jstring s = static_cast<jstring>(ResolveObject(jit.Regs()[1]));
            uint32_t isCopyOut = jit.Regs()[2];
            if (!s) { jit.Regs()[0] = 0; break; }
            auto cached = m_jstr_utf.find(jit.Regs()[1]);
            if (cached != m_jstr_utf.end()) {
                if (isCopyOut) m_host->MemoryWrite8(isCopyOut, 0);
                jit.Regs()[0] = cached->second;
                break;
            }
            const char* utf = e->GetStringUTFChars(s, nullptr);
            size_t len = utf ? strlen(utf) + 1 : 1;
            uint32_t guest = m_host->GuestAlloc(len, 4);
            memcpy(mem + guest, utf ? utf : "", len);
            e->ReleaseStringUTFChars(s, utf);
            m_jstr_utf[jit.Regs()[1]] = guest;
            if (isCopyOut) m_host->MemoryWrite8(isCopyOut, 0); // JNI_FALSE
            jit.Regs()[0] = guest;
            break;
        }
        case 680: // ReleaseStringUTFChars -> no-op on purpose: unlike
                  // GetStringChars this copy is cached in m_jstr_utf and handed
                  // back on the next call, so it lives exactly as long as the
                  // jstring's handle and is freed when that handle is evicted
            jit.Regs()[0] = 0;
            break;

        // ---- primitive arrays (byte family is what GameInstaller
        //      getPublicKey needs: NewByteArray + SetByteArrayRegion feed the
        //      LVL signature validator; a stub here failed license validation
        //      and dropped the game into the RETRY dialog) ----
        case 684: { // GetArrayLength
            jarray a = static_cast<jarray>(ResolveObject(jit.Regs()[1]));
            jit.Regs()[0] = a ? static_cast<uint32_t>(e->GetArrayLength(a)) : 0;
            break;
        }
        case 704: { // NewByteArray
            jbyteArray a = e->NewByteArray(static_cast<jsize>(jit.Regs()[1]));
            jit.Regs()[0] = a ? AddObjectRef(a) : 0;
            if (a) e->DeleteLocalRef(a);
            break;
        }
        // Primitive-array elements occupy eight consecutive JNI slots per kind:
        // eight Get<Type>ArrayElements entries followed by eight releases.
        case 732: case 736: case 740: case 744: case 748: case 752: case 756: case 760: {
            const auto kind = static_cast<PrimitiveArrayKind>((offset - 732) / 4);
            jit.Regs()[0] = AcquirePrimitiveArray(e, jit.Regs()[1], jit.Regs()[2], kind, false);
            break;
        }
        case 764: case 768: case 772: case 776: case 780: case 784: case 788: case 792: {
            const auto kind = static_cast<PrimitiveArrayKind>((offset - 764) / 4);
            ReleasePrimitiveArray(e, jit.Regs()[1], jit.Regs()[2],
                                  static_cast<jint>(jit.Regs()[3]), &kind);
            jit.Regs()[0] = 0;
            break;
        }
        case 800: { // GetByteArrayRegion(env, array, start, len, buf*)
            jbyteArray a = static_cast<jbyteArray>(ResolveObject(jit.Regs()[1]));
            jsize start = static_cast<jsize>(jit.Regs()[2]);
            jsize len = static_cast<jsize>(jit.Regs()[3]);
            uint32_t guest = m_host->MemoryRead32(jit.Regs()[13]);
            if (a && guest)
                e->GetByteArrayRegion(a, start, len, reinterpret_cast<jbyte*>(mem + guest));
            jit.Regs()[0] = 0;
            break;
        }
        case 832: { // SetByteArrayRegion(env, array, start, len, buf*)
            jbyteArray a = static_cast<jbyteArray>(ResolveObject(jit.Regs()[1]));
            jsize start = static_cast<jsize>(jit.Regs()[2]);
            jsize len = static_cast<jsize>(jit.Regs()[3]);
            uint32_t guest = m_host->MemoryRead32(jit.Regs()[13]);
            if (!a || !guest) { jit.Regs()[0] = 0; break; }
            e->SetByteArrayRegion(a, start, len, reinterpret_cast<const jbyte*>(mem + guest));
            jit.Regs()[0] = 0;
            break;
        }

        // ---- exceptions ----
        case 60: { // ExceptionOccurred
            jthrowable t = e->ExceptionOccurred();
            jit.Regs()[0] = t ? AddObjectRef(t) : 0;
            if (t) e->DeleteLocalRef(t);
            break;
        }
        case 64: // ExceptionDescribe
#if MC4_ENABLE_NATIVE_LOGGING
            e->ExceptionDescribe();
#else
            e->ExceptionClear();
#endif
            jit.Regs()[0] = 0;
            break;
        case 68: // ExceptionClear
            e->ExceptionClear();
            jit.Regs()[0] = 0;
            break;
        case 912: { // ExceptionCheck
            jit.Regs()[0] = e->ExceptionCheck() ? 1 : 0;
            break;
        }
        case 56: { // ThrowNew
            jclass c = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            const char* msg = ReadGuestStr(*m_host, jit.Regs()[2]);
            if (c) e->ThrowNew(c, msg);
            jit.Regs()[0] = 0;
            break;
        }
        case 72: { // FatalError
            const char* msg = ReadGuestStr(*m_host, jit.Regs()[1]);
            LOGE("[JNI] FatalError: %s", msg ? msg : "");
            jit.Regs()[0] = 0;
            break;
        }

        // ---- direct buffers ----
        case 920: { // GetDirectBufferAddress
            uint32_t handle = jit.Regs()[1];
            auto it = m_direct_bufs.find(handle);
            if (it != m_direct_bufs.end()) {
                jit.Regs()[0] = it->second.scratch;
                break;
            }
            jobject buf = ResolveObject(handle);
            if (!buf) { jit.Regs()[0] = 0; break; }
            void* p = e->GetDirectBufferAddress(buf);
            if (!p) { jit.Regs()[0] = 0; break; }
            // Unknown buffer: mirror host content into guest scratch (read-only view)
            uint32_t newHandle = RegisterDirectBuffer(buf);
            jit.Regs()[0] = newHandle ? m_direct_bufs[newHandle].scratch : 0;
            break;
        }
        case 924: { // GetDirectBufferCapacity
            uint32_t handle = jit.Regs()[1];
            auto it = m_direct_bufs.find(handle);
            if (it != m_direct_bufs.end()) {
                jit.Regs()[0] = static_cast<uint32_t>(it->second.capacity);
                break;
            }
            jobject buf = ResolveObject(handle);
            jit.Regs()[0] = buf ? static_cast<uint32_t>(e->GetDirectBufferCapacity(buf)) : 0;
            break;
        }

        // ---- misc ----
        case 876: { // GetJavaVM
            uint32_t out = jit.Regs()[1];
            if (out) m_host->MemoryWrite32(out, m_vm_table);
            jit.Regs()[0] = 0;
            break;
        }
        case 888: // GetPrimitiveArrayCritical
            jit.Regs()[0] = AcquirePrimitiveArray(e, jit.Regs()[1], jit.Regs()[2],
                                                 PrimitiveArrayKind::Byte, true);
            break;
        case 892: // ReleasePrimitiveArrayCritical
            ReleasePrimitiveArray(e, jit.Regs()[1], jit.Regs()[2],
                                  static_cast<jint>(jit.Regs()[3]), nullptr);
            jit.Regs()[0] = 0;
            break;
        case 96: { // IsSameObject
            jobject a = ResolveObject(jit.Regs()[1]);
            jobject b = ResolveObject(jit.Regs()[2]);
            jit.Regs()[0] = e->IsSameObject(a, b) ? 1 : 0;
            break;
        }
        case 52: { // Throw
            jobject t = ResolveObject(jit.Regs()[1]);
            if (t) e->Throw(static_cast<jthrowable>(t));
            jit.Regs()[0] = 0;
            break;
        }
        case 384: { // GetBooleanField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            jit.Regs()[0] = (o && it != m_fields.end())
                ? (e->GetBooleanField(o, it->second) ? 1u : 0u) : 0;
            break;
        }
        case 388: { // GetByteField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            jbyte v = (o && it != m_fields.end()) ? e->GetByteField(o, it->second) : 0;
            jit.Regs()[0] = static_cast<uint32_t>(static_cast<int32_t>(v));
            break;
        }
        case 392: { // GetCharField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            jit.Regs()[0] = (o && it != m_fields.end())
                ? static_cast<uint32_t>(e->GetCharField(o, it->second)) : 0;
            break;
        }
        case 396: { // GetShortField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            jshort v = (o && it != m_fields.end()) ? e->GetShortField(o, it->second) : 0;
            jit.Regs()[0] = static_cast<uint32_t>(static_cast<int32_t>(v));
            break;
        }
        case 404: { // GetLongField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            jlong v = (o && it != m_fields.end()) ? e->GetLongField(o, it->second) : 0;
            jit.Regs()[0] = static_cast<uint32_t>(static_cast<uint64_t>(v));
            jit.Regs()[1] = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
            break;
        }
        case 408: { // GetFloatField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            const jfloat v = (o && it != m_fields.end()) ? e->GetFloatField(o, it->second) : 0.0f;
            WriteSF(jit, 0, v);
            break;
        }
        case 412: { // GetDoubleField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            const jdouble v = (o && it != m_fields.end()) ? e->GetDoubleField(o, it->second) : 0.0;
            WriteDF(jit, 0, v);
            break;
        }
        case 416: { // SetObjectField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end())
                e->SetObjectField(o, it->second, ResolveObject(jit.Regs()[3]));
            jit.Regs()[0] = 0;
            break;
        }
        case 420: { // SetBooleanField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end())
                e->SetBooleanField(o, it->second, static_cast<jboolean>(jit.Regs()[3]));
            jit.Regs()[0] = 0;
            break;
        }
        case 424: { // SetByteField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end())
                e->SetByteField(o, it->second, static_cast<jbyte>(jit.Regs()[3]));
            jit.Regs()[0] = 0;
            break;
        }
        case 428: { // SetCharField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end())
                e->SetCharField(o, it->second, static_cast<jchar>(jit.Regs()[3]));
            jit.Regs()[0] = 0;
            break;
        }
        case 432: { // SetShortField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end())
                e->SetShortField(o, it->second, static_cast<jshort>(jit.Regs()[3]));
            jit.Regs()[0] = 0;
            break;
        }
        case 436: { // SetIntField
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end()) e->SetIntField(o, it->second, static_cast<jint>(jit.Regs()[3]));
            jit.Regs()[0] = 0;
            break;
        }
        case 440: { // SetLongField: AAPCS32 places the aligned 64-bit value at SP
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end()) {
                const uint32_t sp = jit.Regs()[13];
                const uint64_t bits = static_cast<uint64_t>(m_host->MemoryRead32(sp)) |
                    (static_cast<uint64_t>(m_host->MemoryRead32(sp + 4)) << 32);
                e->SetLongField(o, it->second, static_cast<jlong>(bits));
            }
            jit.Regs()[0] = 0;
            break;
        }
        case 444: { // SetFloatField (softfp value in r3)
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end()) e->SetFloatField(o, it->second, ReadSF(jit, 3));
            jit.Regs()[0] = 0;
            break;
        }
        case 448: { // SetDoubleField: AAPCS32 aligns the value on the stack
            jobject o = ResolveObject(jit.Regs()[1]);
            auto it = m_fields.find(jit.Regs()[2]);
            if (o && it != m_fields.end()) {
                const uint32_t sp = jit.Regs()[13];
                const uint64_t bits = static_cast<uint64_t>(m_host->MemoryRead32(sp)) |
                    (static_cast<uint64_t>(m_host->MemoryRead32(sp + 4)) << 32);
                jdouble value;
                memcpy(&value, &bits, sizeof(value));
                e->SetDoubleField(o, it->second, value);
            }
            jit.Regs()[0] = 0;
            break;
        }

        default: {
            static bool warned[240];
            uint32_t slot = offset / 4;
            if (slot < 240 && !warned[slot]) {
                warned[slot] = true;
                LOGE("[JNI] unhandled env slot %u (off 0x%X) at PC 0x%08X, r1=0x%08X r2=0x%08X r3=0x%08X",
                     slot, offset, jit.Regs()[15], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
            }
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
            break;
        }
    }
}
