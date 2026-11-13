// MC4 offline cheats, host side of the arm64 bridge.
//
// Direct port of work/offline_cheats/offline_cheats.c (arm32 guest library).
// The original dlopen()ed libModernCombat4.so and dlsym()ed GameSettings
// symbols; under the bridge the game library is already loaded in the guest
// address space, so the same symbols resolve through the ELF loader and calls
// re-enter the JIT via RunFunction. Byte pokes (offsets 7/8/6/0xBF/0xC2/
// 0x348+n) write guest memory directly. The option filter (18..31, reject 22
// and 32) is identical -- Phase 4 offline cheat filter rules stay intact.

#include "mc4_cheats.h"

#include <android/log.h>
#include <jni.h>
#include <stdint.h>

#include <cstring>
#include <string>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "mc4_phase3.h"

#define LOG_TAG "MC4OfflineCheats"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace mc4 {

// Guest symbol addresses, resolved once (offline_cheats.c:9-12).
static uint32_t g_sym_get_instance = 0;
static uint32_t g_sym_set_god_mode = 0;
static uint32_t g_sym_set_debug_info = 0;
static uint32_t g_sym_save_settings = 0;

// (offline_cheats.c:14-31)
static bool ResolveSymbols(DynarmicHost& host) {
    if (g_sym_get_instance) return true;
    g_sym_get_instance = host.GetElfLoader().GetSymbolAddress("_ZN12GameSettings11GetInstanceEv");
    g_sym_set_god_mode = host.GetElfLoader().GetSymbolAddress("_ZN12GameSettings10SetGodModeEb");
    g_sym_set_debug_info = host.GetElfLoader().GetSymbolAddress("_ZN12GameSettings16SetShowDebugInfoEb");
    g_sym_save_settings = host.GetElfLoader().GetSymbolAddress("_ZN12GameSettings12SaveSettingsEb");
    if (!g_sym_get_instance || !g_sym_set_god_mode || !g_sym_set_debug_info ||
        !g_sym_save_settings) {
        LOGE("required GameSettings symbols missing");
        g_sym_get_instance = 0;
        return false;
    }
    return true;
}

// (offline_cheats.c:33-87)
bool OfflineCheatApply(DynarmicHost& host, int option) {
    LOGI("apply entry option=%d", option);
    if (option == 22 || option == 32) return false;
    if (option < 18 || option > 31) return false;
    if (!ResolveSymbols(host)) return false;
    LOGI("symbols resolved");

    // GameSettings::GetInstance() -> guest pointer in r0.
    const uint32_t settings = host.RunFunction(g_sym_get_instance);
    if (!settings) {
        LOGE("GameSettings instance is null");
        return false;
    }
    uint8_t* mem = host.GetGuestMemoryBase();

    switch (option) {
        case 18:
            // GameSettings::SetGodMode(settings, true)
            host.RunFunction(g_sym_set_god_mode, {settings, 1});
            break;
        case 20:
            // GameSettings::SetShowDebugInfo(settings, true)
            host.RunFunction(g_sym_set_debug_info, {settings, 1});
            break;
        case 21:
            mem[settings + 7] = 1;
            break;
        case 19:
            mem[settings + 8] = 1;
            break;
        case 23:
            mem[settings + 6] = 1;
            break;
        case 24:
            mem[settings + 0xBF] = 1;
            break;
        case 25:
            mem[settings + 0xC2] = 1;
            break;
        case 26:
        case 27:
        case 28:
        case 29:
        case 30:
        case 31:
            mem[settings + 0x348 + (option - 26)] = 1;
            break;
        default:
            return false;
    }

    // GameSettings::SaveSettings(settings, false)
    host.RunFunction(g_sym_save_settings, {settings, 0});
    LOGI("applied local option=%d", option);
    return true;
}

}  // namespace mc4
