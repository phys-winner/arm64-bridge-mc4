"""Guard Android gesture routing and the existing game's Back/IME semantics."""
from pathlib import Path
import os
import struct
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from test_manual_cheat_ui import method_body

ROOT = Path(__file__).resolve().parents[1]
SMALI = ROOT / "app/smali/com/gameloft/android/ANMP/GloftM4HM"
ANDROID = "{http://schemas.android.com/apk/res/android}"


class AndroidBackContract(unittest.TestCase):
    def test_manifest_keeps_native_language_choice_and_enables_back_callbacks(self):
        application = ET.parse(ROOT / "app/AndroidManifest.xml").getroot().find("application")
        self.assertNotIn(ANDROID + "localeConfig", application.attrib)
        activities = {item.get(ANDROID + "name"): item for item in application.findall("activity")}
        for name in (".MC4", ".MyVideoView"):
            self.assertEqual(activities[name].get(ANDROID + "enableOnBackInvokedCallback"), "true")

    def test_new_platform_types_cannot_load_on_old_android(self):
        for name in ("MC4", "MyVideoView"):
            source = (SMALI / (name + ".smali")).read_text(encoding="utf-8")
            self.assertNotIn("Landroid/window/", source)
            create = method_body(source, "onCreate")
            guard = create.index("if-lt v0, v1, :back_ready")
            self.assertIn("->SDK_INT:I", create[:guard])
            self.assertIn("const/16 v1, 0x21", create[:guard])
            self.assertLess(guard, create.index("PlatformBack;->register("))
            self.assertLess(create.index("PlatformBack;->register("), create.index("\n    :back_ready\n"))
            destroy = method_body(source, "onDestroy")
            self.assertLess(destroy.index("if-eqz v0, :back_released"),
                            destroy.index("PlatformBack;->unregister("))
            self.assertLess(destroy.index("PlatformBack;->unregister("), destroy.index("AppData;->ready()Z"))

    def test_platform_callback_calls_the_registered_activity_once(self):
        source = (SMALI / "PlatformBack.smali").read_text(encoding="utf-8")
        callback = method_body(source, "onBackInvoked")
        self.assertIn("->activity:Landroid/app/Activity;", callback)
        self.assertEqual(callback.count("->onBackPressed()V"), 1)
        self.assertNotIn("MC4;->c:", callback)
        register = method_body(source, "register")
        self.assertIn("const/4 v2, 0x0", register)  # IME still has higher priority.
        self.assertIn("registerOnBackInvokedCallback(ILandroid/window/OnBackInvokedCallback;)V", register)

    def test_main_gesture_uses_the_original_hardware_back_path(self):
        source = (SMALI / "MC4.smali").read_text(encoding="utf-8")
        back = method_body(source, "onBackPressed")
        self.assertIn("if-eqz v0, :done", back)
        self.assertIn("const/4 v1, 0x4", back)
        self.assertLess(back.index("const/4 v0, 0x0"), back.index("->onKeyDown("))
        self.assertLess(back.index("->onKeyDown("), back.index("const/4 v0, 0x1"))
        self.assertLess(back.index("const/4 v0, 0x1"), back.index("->onKeyUp("))
        self.assertNotIn("invoke-super", back)
        release = method_body(source, "onKeyUp")
        self.assertIn("->queueHandleKey(I)V", release)
        self.assertIn("->d()V", release)  # Existing keyboard cleanup stays on UI.
        self.assertNotIn("->nativeHandleKey(I)V", release)
        producer = method_body(source, "queueHandleKey")
        self.assertIn("if-eqz v0, :done", producer)
        self.assertIn("GLSurfaceView;->a(Ljava/lang/Runnable;)V", producer)
        self.assertNotIn("->nativeHandleKey(I)V", producer)
        runnable = (SMALI / "HandleKeyEvent.smali").read_text(encoding="utf-8")
        self.assertEqual(method_body(runnable, "run").count("->nativeHandleKey(I)V"), 1)

    def test_movie_gesture_preserves_existing_back_action_without_fake_key_up(self):
        source = (SMALI / "MyVideoView.smali").read_text(encoding="utf-8")
        back = method_body(source, "onBackPressed")
        self.assertIn("const/4 v1, 0x4", back)
        self.assertIn("->onKeyDown(ILandroid/view/KeyEvent;)Z", back)
        self.assertNotIn("->onKeyUp(", back)
        self.assertNotIn("invoke-super", back)
        press = method_body(source, "onKeyDown")
        self.assertIn("android.intent.category.HOME", press)
        self.assertIn("->nativeGetInvalidBackMsg()Ljava/lang/String;", press)

    def test_native_back_requests_pause_only_in_active_gameplay(self):
        source = (ROOT / "arm64_bridge/src/jni_bridge.cpp").read_text(encoding="utf-8")
        start = source.index("static void MC4_nativeHandleKey(")
        body = source[start:source.index("GUEST_VOID_0_OBJ(MC4_nativeHideKeyboard", start)]
        self.assertLess(body.index("EnsureGameLoaded(env)"), body.index("g_host->GetMutex()"))
        self.assertLess(body.index("g_host->GetMutex()"), body.index("if (key == 4)"))
        for symbol in ("_ZN11Application10s_instanceE", "_ZN4iFPS19GetCurrentStateTypeEv",
                       "_ZN11Application12RequestPauseEv", "_ZN8Gameplay10s_instanceE",
                       "_ZN3Hud5PauseEbbb", "_ZN3Hud7UnPauseEb"):
            self.assertIn('FindSymbol("' + symbol + '")', body)
        for guard in (
            "GuestRangeValid(g_host->GetGuestMemorySize(), app, 0xad8)",
            "GuestRangeValid(g_host->GetGuestMemorySize(), gameplay, 0x4d)",
            "g_host->MemoryRead32(hud_pause + 0x2b0) == 0xe5cb104cu",
            "g_host->MemoryRead32(hud_unpause + 0x50) == 0xe5c3604cu",
            "!g_host->MemoryRead8(gameplay + 0x4c)",
            "g_host->MemoryRead32(state) == 0xe5900ad4u",
            "g_host->MemoryRead32(pause) == 0xe3a03001u",
            "g_host->MemoryRead32(pause + 4) == 0xe5c03809u",
        ):
            self.assertIn(guard, body)
        # The factory below proves 2 is Gameplay; 4 is LoadingState.
        self.assertIn("const uint32_t state_type = g_host->RunFunction(state, {app});", body)
        self.assertIn("if (state_type == 2)", body)
        fallback = body.index('GuestSym("Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeHandleKey")')
        self.assertIn("return;", body[body.index("g_host->RunFunction(pause, {app});"):fallback])
        self.assertLess(body.index("g_host->RunFunction(pause, {app});"), fallback)
        self.assertIn("g_host->RunFunction(symbol, {FakeEnv(), J(obj), static_cast<uint32_t>(key)});",
                      body[fallback:])

    def test_production_native_back_routes_paused_and_nested_menu_keys_to_original(self):
        source = (ROOT / "arm64_bridge/src/jni_bridge.cpp").read_text(encoding="utf-8")
        start = source.index("static void MC4_nativeHandleKey(")
        body = source[start:source.index("GUEST_VOID_0_OBJ(MC4_nativeHideKeyboard", start)]
        memory = (ROOT / "arm64_bridge/src/thunk_types.h").read_text(encoding="utf-8")
        start = memory.index("inline bool GuestRangeValid(")
        memory = memory[start:memory.index("\n}", start) + 2]
        fixture = r"""
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
using JNIEnv = void;
using jobject = uintptr_t;
using jint = int32_t;
#define LOGI(...) do {} while (0)
constexpr uint32_t kApp = 0x100, kGameplay = 0x2000, kState = 0x3000;
constexpr uint32_t kPause = 0x3100, kHudPause = 0x4000, kHudUnpause = 0x5000;
constexpr uint32_t kOriginal = 0x6000;
const char* original = "Java_com_gameloft_android_ANMP_GloftM4HM_MC4_nativeHandleKey";
struct Call { uint32_t target; std::vector<uint32_t> args; };
struct MockHost {
    std::recursive_mutex mutex;
    std::unordered_map<std::string, uint32_t> symbols;
    std::unordered_map<uint32_t, uint32_t> words;
    std::unordered_map<uint32_t, uint8_t> bytes;
    std::vector<Call> calls;
    uint32_t state_type = 2;
    bool loaded = true;
    void reset() {
        state_type = 2; loaded = true; calls.clear(); bytes.clear();
        symbols = {{"_ZN11Application10s_instanceE", 0x80},
                   {"_ZN8Gameplay10s_instanceE", 0x84},
                   {"_ZN4iFPS19GetCurrentStateTypeEv", kState},
                   {"_ZN11Application12RequestPauseEv", kPause},
                   {"_ZN3Hud5PauseEbbb", kHudPause},
                   {"_ZN3Hud7UnPauseEb", kHudUnpause}, {original, kOriginal}};
        words = {{0x80, kApp}, {0x84, kGameplay}, {kState, 0xe5900ad4u},
                 {kPause, 0xe3a03001u}, {kPause + 4, 0xe5c03809u},
                 {kHudPause + 0x2b0, 0xe5cb104cu},
                 {kHudUnpause + 0x50, 0xe5c3604cu}};
    }
    auto& GetMutex() { return mutex; }
    size_t GetGuestMemorySize() const { return 0x8000; }
    uint32_t FindSymbol(const std::string& name) {
        const auto found = symbols.find(name);
        return found == symbols.end() ? 0 : found->second;
    }
    uint32_t MemoryRead32(uint32_t address) { return words[address]; }
    uint8_t MemoryRead8(uint32_t address) { return bytes[address]; }
    uint32_t RunFunction(uint32_t target, const std::vector<uint32_t>& args) {
        calls.push_back({target, args});
        return target == kState ? state_type : 0;
    }
} host;
MockHost* g_host = &host;
bool EnsureGameLoaded(JNIEnv*) { return host.loaded; }
uint32_t GuestSym(const char* name) { return host.FindSymbol(name); }
uint32_t FakeEnv() { return 0x20; }
uint32_t J(jobject object) { return static_cast<uint32_t>(object); }
void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "%s\n", message); std::_Exit(1); }
}
"""
        checks = r"""
void back() { MC4_nativeHandleKey(nullptr, 0x30, 4); }
void expectOriginal(int key, size_t count) {
    require(host.calls.size() == count, "unexpected calls before original key");
    const auto& call = host.calls.back();
    require(call.target == kOriginal, "paused/menu key must use original handler");
    require(call.args == std::vector<uint32_t>{0x20, 0x30, static_cast<uint32_t>(key)},
            "original JNI arguments changed");
}
int main() {
    host.reset(); back();
    require(host.calls.size() == 2 && host.calls[0].target == kState &&
            host.calls[0].args == std::vector<uint32_t>{kApp} &&
            host.calls[1].target == kPause && host.calls[1].args == std::vector<uint32_t>{kApp},
            "active gameplay must query state and request native HUD pause");
    // Hardware regression: native PAUSED and nested Options retain state2
    // and have IsInPauseMenu(+0x57)==0, but HUD sets the real pause byte.
    host.reset(); host.bytes[kGameplay + 0x4c] = 1;
    host.bytes[kGameplay + 0x57] = 0; back(); expectOriginal(4, 1);
    host.calls.clear(); back(); expectOriginal(4, 1);
    // Original UnPause clears the byte; a subsequent Back can pause again.
    host.calls.clear(); host.bytes[kGameplay + 0x4c] = 0; back();
    require(host.calls.size() == 2 && host.calls.back().target == kPause,
            "HUD UnPause must restore gameplay Back routing");
    for (uint32_t state : {3u, 4u}) {
        host.reset(); host.state_type = state; back(); expectOriginal(4, 2);
    }
    for (int key : {82, 108}) {
        host.reset(); MC4_nativeHandleKey(nullptr, 0x30, key); expectOriginal(key, 1);
    }
    for (uint32_t address : {kState, kPause, kPause + 4,
                             kHudPause + 0x2b0, kHudUnpause + 0x50}) {
        host.reset(); host.words[address] = 0; back(); expectOriginal(4, 1);
    }
    host.reset(); host.symbols.erase("_ZN3Hud7UnPauseEb"); back(); expectOriginal(4, 1);
    host.reset(); host.words[0x84] = 0; back(); expectOriginal(4, 1);
    host.reset(); host.words[0x80] = 0x7f00; back(); expectOriginal(4, 1);
    host.reset(); host.loaded = false; back();
    require(host.calls.empty(), "unloaded guest must not receive key calls");
    std::puts("native Back contract passed");
}
"""
        with tempfile.TemporaryDirectory(prefix="mc4-back-contract-") as directory:
            temporary = Path(directory)
            (temporary / "contract.cpp").write_text(fixture + memory + "\n" + body + checks,
                                                    encoding="utf-8")
            vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            installation = subprocess.check_output(
                [str(vswhere), "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"], text=True,
            ).strip()
            self.assertTrue(installation, "local MSVC C++ toolchain is required")
            vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
            command = f'call "{vcvars}" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /O2 contract.cpp /Fe:contract.exe'
            result = subprocess.run(command, shell=True, cwd=temporary,
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            result = subprocess.run([str(temporary / "contract.exe")], cwd=temporary,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("native Back contract passed", result.stdout)

    def test_original_guest_state_factory_and_hud_pause_request(self):
        guest = (ROOT / "app/assets/guest_libs/libModernCombat4.so").read_bytes()

        def word(address):
            return struct.unpack_from("<I", guest, address)[0]

        def branch_target(address):
            instruction = word(address)
            self.assertEqual((instruction >> 25) & 7, 5, hex(address))
            offset = instruction & 0xffffff
            if offset & 0x800000:
                offset -= 0x1000000
            return address + 8 + offset * 4

        # iFPS::SA_CreateState dispatches to the original state constructors.
        self.assertEqual(word(0x8a17f8), 0xe3530002)  # cmp r3, #2
        self.assertEqual(word(0x8a17fc) >> 28, 0)  # BEQ
        self.assertEqual(branch_target(0x8a17fc), 0x8a1884)
        self.assertEqual(branch_target(0x8a1898), 0x5aded0)  # Gameplay::Gameplay
        self.assertEqual(word(0x8a1800), 0xe3530004)  # cmp r3, #4
        self.assertEqual(word(0x8a1804) >> 28, 0)
        self.assertEqual(branch_target(0x8a1804), 0x8a18a4)
        self.assertEqual(branch_target(0x8a18b8), 0x5abecc)  # LoadingState::LoadingState
        self.assertEqual(word(0x8a11ac), 0xe5900ad4)  # iFPS's StateAutomat pointer
        self.assertEqual(branch_target(0x8a11b8), 0x72fbc4)  # GetCurrentStateType
        # Native HUD pause uses +0x4c; legacy IsInPauseMenu uses a different byte.
        self.assertEqual(word(0x5a5420), 0xe5d00057)
        self.assertEqual(word(0x60674c), 0xe3a01001)  # r1=true
        self.assertEqual(word(0x6064a4 + 0x2b0), 0xe5cb104c)  # Gameplay+0x4c=true
        self.assertEqual(word(0x607f84), 0xe3a06000)  # r6=false
        self.assertEqual(word(0x607f3c + 0x50), 0xe5c3604c)  # Gameplay+0x4c=false
        # RequestPause sets the existing flag; HUD clears it and calls normal Pause.
        self.assertEqual(word(0x7b577c), 0xe3a03001)
        self.assertEqual(word(0x7b5780), 0xe5c03809)  # strb r3, [app, #0x809]
        self.assertEqual(word(0x7b5784), 0xe12fff1e)
        self.assertEqual(word(0x616fe0), 0xe5d03809)  # ldrb r3, [app, #0x809]
        self.assertEqual(word(0x616fe4), 0xe3530000)
        self.assertEqual(word(0x616fe8) >> 28, 1)  # BNE
        self.assertEqual(branch_target(0x616fe8), 0x617798)
        self.assertEqual(branch_target(0x617798), 0x7b64e0)  # ClearPauseRequest
        self.assertEqual(word(0x61779c), 0xe3a01001)  # r1=true
        self.assertEqual(word(0x6177a0), 0xe1a02001)  # r2=r1
        self.assertEqual(word(0x6177a8), 0xe1a03001)  # r3=r1
        self.assertEqual(word(0x6177ac), 0xe1a00004)  # r0=HUD
        self.assertEqual(branch_target(0x6177b0), 0x6064a4)  # Hud::Pause(true,true,true)


if __name__ == "__main__":
    unittest.main(verbosity=2)
