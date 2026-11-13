#include "arm32_push.h"

// Compile-time regression: actual production helper, exact register values,
// ascending transfer order, final SP, and canaries on both sides of the frame.
constexpr bool CheckPush(uint16_t mask) {
    uint32_t stack[18]{};
    for (auto& word : stack) word = 0xfeedfaceu;
    bool outside = false;
    unsigned writes = 0;
    const uint32_t sp = arm32::PushRegisters(
        64, mask, [](unsigned reg) { return 0x12340000u + reg; },
        [&](uint32_t address, uint32_t value) {
            if (address >= 64 || address % 4) outside = true;
            else stack[1 + address / 4] = value;
            ++writes;
        });
    unsigned offset = 0;
    for (unsigned reg = 0; reg < 16; ++reg) {
        if (mask & (1u << reg)) {
            if (stack[1 + sp / 4 + offset] != 0x12340000u + reg) return false;
            ++offset;
        }
    }
    return !outside && writes == offset && sp == 64 - offset * 4 &&
           stack[sp / 4] == 0xfeedfaceu && stack[17] == 0xfeedfaceu;
}

constexpr bool CheckAllSupportedMasks() {
    for (unsigned mask = 1; mask < 0x10000; ++mask)
        if (arm32::IsProbePush(0xe92d0000u | mask) && !CheckPush(mask))
            return false;
    return true;
}

static_assert(CheckPush(0x47f0));  // onClassInitialized: no R11
static_assert(CheckPush(0x48f0));  // __cxa_throw: sparse R4-R7,R11,LR
static_assert(CheckPush(0x4ff0));  // BITrackingLaunch: LR stored only once
static_assert(CheckPush(0x4038));  // dropRef: starts at R3, not R4
static_assert(CheckPush(0x400f));  // variadic argument registers
static_assert(CheckPush(0x4000));  // LR only
static_assert(!arm32::IsProbePush(0xe92d0000u));
static_assert(!arm32::IsProbePush(0xe92da000u));
static_assert(!arm32::IsProbePush(0x192d4010u));
static_assert(CheckAllSupportedMasks());
