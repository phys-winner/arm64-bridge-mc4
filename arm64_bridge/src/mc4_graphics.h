#pragma once

#include <cstdint>

class DynarmicHost;

namespace mc4 {

// Independent SharedPreferences word: version1 and five two-bit selections.
// 201: Auto/50/75/100%; 202: Auto/Low/High; 203-205: Auto/Off/On.
// 200 is the derived preset: Auto/Performance/Balanced/High/Custom.
constexpr uint32_t kGraphicsPreferenceVersion = 0x00010000u;
bool Phase3GraphicsLoad(uint32_t packed);
uint32_t Phase3GraphicsPacked();
int Phase3GraphicsOptionValue(int option);
bool Phase3GraphicsSetOption(int option, int index);

// Install before Application::Init. Preferences must already be loaded.
// The first completed Init freezes the active selections for this session;
// subsequent menu changes only update the word persisted for the next launch.
bool Phase3GraphicsInstall(DynarmicHost& host);

}  // namespace mc4
