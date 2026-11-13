#pragma once

#include <cstdint>

namespace arm32 {

// The probe helper implements unconditional STMFD SP!,{R0-R12,LR} masks.
// SP/PC operands need additional architectural rules and are not supported.
constexpr bool IsProbePush(uint32_t instruction) {
    return (instruction & 0xffff0000u) == 0xe92d0000u &&
           (instruction & 0xa000u) == 0 && (instruction & 0xffffu) != 0;
}

template <typename ReadRegister, typename WriteWord>
constexpr uint32_t PushRegisters(uint32_t old_sp, uint16_t mask,
                                 ReadRegister read, WriteWord write) {
    uint32_t bytes = 0;
    for (unsigned reg = 0; reg < 16; ++reg)
        if (mask & (1u << reg)) bytes += 4;
    const uint32_t new_sp = old_sp - bytes;
    uint32_t address = new_sp;
    for (unsigned reg = 0; reg < 16; ++reg) {
        if (mask & (1u << reg)) {
            write(address, read(reg));
            address += 4;
        }
    }
    return new_sp;
}

}  // namespace arm32
