#include "mc4_graphics.h"

#include "arm32_push.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"

#include <array>
#include <atomic>
#include <memory>
#include <android/log.h>

#define LOG_TAG "Arm32Bridge_Graphics"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace mc4 {
namespace {

constexpr uint32_t kFieldsMask = 0x3ffu;
constexpr uint32_t Pack(unsigned resolution, unsigned materials, unsigned shadows,
                        unsigned reflections, unsigned dof) {
    return kGraphicsPreferenceVersion | resolution | (materials << 2) |
           (shadows << 4) | (reflections << 6) | (dof << 8);
}
constexpr std::array<uint32_t, 4> kPresets{
    Pack(0, 0, 0, 0, 0), Pack(1, 1, 1, 1, 1),
    Pack(2, 2, 1, 1, 1), Pack(3, 2, 2, 2, 2),
};
std::atomic<uint32_t> g_preferences{kGraphicsPreferenceVersion};

bool ValidPreferences(uint32_t value) {
    if ((value & ~kFieldsMask) != kGraphicsPreferenceVersion) return false;
    for (unsigned shift = 2; shift <= 8; shift += 2)
        if (((value >> shift) & 3) == 3) return false;
    return true;
}

bool GuestRange(DynarmicHost& host, uint32_t address, uint32_t size) {
    return address && uint64_t(address) + size <= host.GetGuestMemorySize();
}

// Offsets verified against PerformanceProfile::Read and the actual consumers:
// main RT scale, LOWEND material variants, SHADOWMAP, reflections, armory DOF.
// The other profile fields include audio/cadence and must never be copied.
void ApplyGraphics(DynarmicHost& host, uint32_t app, uint32_t value) {
    const unsigned resolution = value & 3;
    if (resolution) {
        constexpr uint32_t scales[] = {0, 0x3f000000u, 0x3f400000u, 0x3f800000u};
        host.MemoryWrite32(app + 0x390u, scales[resolution]);
    }
    constexpr std::array<uint32_t, 4> offsets{0x3abu, 0x3c5u, 0x3b0u, 0x38au};
    for (unsigned index = 0; index < offsets.size(); ++index) {
        const unsigned selection = (value >> (2 + index * 2)) & 3;
        if (selection) host.MemoryWrite8(app + offsets[index], selection == 2);
    }
}

struct GraphicsSession {
    std::atomic<uint32_t> active{0};
    std::atomic<bool> invalid_receiver_logged{false};
};

}  // namespace

bool Phase3GraphicsLoad(uint32_t packed) {
    if (packed == 0) packed = kGraphicsPreferenceVersion;
    const bool valid = ValidPreferences(packed);
    g_preferences.store(valid ? packed : kGraphicsPreferenceVersion,
                        std::memory_order_release);
    return valid;
}

uint32_t Phase3GraphicsPacked() {
    return g_preferences.load(std::memory_order_acquire);
}

int Phase3GraphicsOptionValue(int option) {
    const uint32_t value = Phase3GraphicsPacked();
    if (option == 200) {
        for (unsigned preset = 0; preset < kPresets.size(); ++preset)
            if (value == kPresets[preset]) return static_cast<int>(preset);
        return 4;
    }
    if (option < 201 || option > 205) return -1;
    return static_cast<int>((value >> ((option - 201) * 2)) & 3);
}

bool Phase3GraphicsSetOption(int option, int index) {
    if (option < 200 || option > 205 || index < 0) return false;
    if (option == 200) {
        if (index > 4) return false;
        if (index < 4) g_preferences.store(kPresets[index], std::memory_order_release);
        return true; // Custom describes the existing independent selections.
    }
    if (index > (option == 201 ? 3 : 2)) return false;
    const unsigned shift = (option - 201) * 2;
    uint32_t before = g_preferences.load(std::memory_order_relaxed);
    uint32_t after;
    do {
        after = (before & ~(3u << shift)) | (uint32_t(index) << shift);
    } while (!g_preferences.compare_exchange_weak(before, after,
                 std::memory_order_release, std::memory_order_relaxed));
    return true;
}

bool Phase3GraphicsInstall(DynarmicHost& host) {
    const uint32_t base = host.GetElfLoader().GetBaseAddress();
    constexpr uint32_t kLateInit = 0x88d158u;
    constexpr uint32_t kDeretinated = 0x7b7e9cu;
    auto& manager = host.GetThunkManager();
    const uint32_t existing_init = manager.FindThunkAddress("mc4_graphics_late_init");
    const uint32_t existing_scale = manager.FindThunkAddress("mc4_graphics_deretinated");
    if (existing_init && existing_scale &&
        host.MemoryRead32(base + kLateInit) == host.MemoryRead32(existing_init) &&
        host.MemoryRead32(base + kDeretinated) == host.MemoryRead32(existing_scale))
        return true;

    struct Guard { uint32_t offset, word; };
    constexpr Guard guards[] = {
        {kLateInit, 0xe28dd06cu}, {0x88d15c, 0xe8bd8ff0u},
        {0x88c660, 0xe92d4ff0u}, {0x88c664, 0xe1a04000u}, // R4 remains Init's receiver.
        {kDeretinated, 0xe92d4008u}, {0x7b7ea0, 0xeef77a00u},
        {0x7b7ecc, 0xe5d00011u}, // Auto respects saved ForceRetina.
        {0x88cfec, 0xe5c6238au}, {0x88d02c, 0xe5c623c5u},
        {0x893ce4, 0x1d936ae4u}, // Render target scale.
        {0x536b08, 0xe5d333abu}, // LOWEND compiler gate.
        {0x536af0, 0xe5d323c5u}, {0x894114, 0xe5d333c5u}, // Shadow shader/RT.
        {0x8940fc, 0xe5d323b0u}, // Reflection RT.
        {0x5a6514, 0xe5d3338au}, // Named armory depth-of-field consumer.
    };
    for (const auto& guard : guards) {
        const uint64_t address = uint64_t(base) + guard.offset;
        if (address > UINT32_MAX || !GuestRange(host, uint32_t(address), 4) ||
            host.MemoryRead32(uint32_t(address)) != guard.word) {
            LOGE("graphics hooks blocked at offset %08X", guard.offset);
            return false;
        }
    }

    const auto session = std::make_shared<GraphicsSession>();
    const uint32_t init = manager.RegisterThunk("mc4_graphics_late_init",
        [session](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            const uint32_t base = host.GetElfLoader().GetBaseAddress();
            const uint32_t app = jit.Regs()[4];
            const uint64_t slot = uint64_t(base) + 0x17b7d88u;
            if (slot <= UINT32_MAX && GuestRange(host, uint32_t(slot), 4) &&
                GuestRange(host, app, 0x3d2) && host.MemoryRead32(uint32_t(slot)) == app) {
                uint32_t value = session->active.load(std::memory_order_acquire);
                if (!value) {
                    uint32_t empty = 0;
                    const uint32_t requested = Phase3GraphicsPacked();
                    session->active.compare_exchange_strong(empty, requested,
                        std::memory_order_acq_rel, std::memory_order_acquire);
                    value = session->active.load(std::memory_order_acquire);
                    LOGI("[GRAPHICS] active=%08X res=%u materials=%u shadows=%u reflections=%u dof=%u",
                         value, value & 3, (value >> 2) & 3, (value >> 4) & 3,
                         (value >> 6) & 3, (value >> 8) & 3);
                }
                ApplyGraphics(host, app, value);
            } else if (!session->invalid_receiver_logged.exchange(true)) {
                LOGE("[GRAPHICS] Init receiver mismatch r4=%08X slot=%08X; native profile retained",
                     app, slot <= UINT32_MAX && GuestRange(host, uint32_t(slot), 4)
                         ? host.MemoryRead32(uint32_t(slot)) : 0);
            }
            // Application::Init common return, after Android profile overrides.
            jit.Regs()[13] += 0x6c;
            jit.Regs()[15] = base + kLateInit + 4;
        });
    const uint32_t scale = manager.RegisterThunk("mc4_graphics_deretinated",
        [session](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            const unsigned resolution = session->active.load(std::memory_order_acquire) & 3;
            if (resolution) {
                // A custom scale must not overwrite/persist legacy ForceRetina.
                jit.Regs()[0] = resolution < 3 ? 1u : 0u;
                const uint32_t lr = jit.Regs()[14];
                jit.SetCpsr((jit.Cpsr() & ~0x20u) | ((lr & 1u) ? 0x20u : 0));
                jit.Regs()[15] = lr & ~1u;
                return;
            }
            jit.Regs()[13] = arm32::PushRegisters(jit.Regs()[13], 0x4008,
                [&jit](unsigned reg) { return jit.Regs()[reg]; },
                [&host](uint32_t address, uint32_t word) { host.MemoryWrite32(address, word); });
            jit.Regs()[15] = host.GetElfLoader().GetBaseAddress() + kDeretinated + 4;
        });
    host.MemoryWrite32(base + kLateInit, host.MemoryRead32(init));
    host.MemoryWrite32(base + kDeretinated, host.MemoryRead32(scale));
    host.InvalidateGuestCode(base + kLateInit, 4);
    host.InvalidateGuestCode(base + kDeretinated, 4);
#if MC4_ENABLE_NATIVE_LOGGING
    constexpr uint32_t shader = 0x5369fcu;
    if (host.MemoryRead32(base + shader) == 0xe92d43f0u &&
        host.MemoryRead32(base + shader + 4) == 0xe24dd014u &&
        host.MemoryRead32(base + shader + 8) == 0xe1a06000u) {
        const auto seen = std::make_shared<std::atomic<bool>>(false);
        const uint32_t trace = manager.RegisterThunk("mc4_graphics_first_material",
            [session, seen](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                if (!seen->exchange(true))
                    LOGI("[GRAPHICS] first material compiler active=%08X",
                         session->active.load(std::memory_order_acquire));
                jit.Regs()[13] = arm32::PushRegisters(jit.Regs()[13], 0x43f0,
                    [&jit](unsigned reg) { return jit.Regs()[reg]; },
                    [&host](uint32_t address, uint32_t word) { host.MemoryWrite32(address, word); });
                jit.Regs()[15] = host.GetElfLoader().GetBaseAddress() + 0x536a00u;
            });
        host.MemoryWrite32(base + shader, host.MemoryRead32(trace));
        host.InvalidateGuestCode(base + shader, 4);
    } else LOGE("[GRAPHICS] first material compiler trace blocked: unexpected code");
#endif
    return true;
}

}  // namespace mc4
