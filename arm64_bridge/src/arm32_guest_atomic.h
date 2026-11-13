#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace mc4 {

// The ARM kuser CAS and Dynarmic exclusive-store callback operate on the
// same guest words. Both must use a single host atomic RMW primitive: a
// separate read/check/write can report success on two competing guest cores.
template <typename T>
bool GuestAtomicCompareExchange(std::uint8_t* memory, std::size_t memory_size,
                                std::uint32_t guest_addr, T expected, T desired) {
    static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>);
    if (!memory || static_cast<std::uint64_t>(guest_addr) + sizeof(T) > memory_size)
        return false;
    auto* word = reinterpret_cast<T*>(memory + guest_addr);
    if (reinterpret_cast<std::uintptr_t>(word) % alignof(T))
        return false;
#if defined(_MSC_VER)
    std::atomic_ref<T> atom(*word);
    return atom.compare_exchange_strong(expected, desired, std::memory_order_seq_cst);
#else
    // The pinned Android NDK's libc++ does not expose std::atomic_ref even
    // in C++20 mode. Clang's integral atomic built-in emits the same single
    // hardware RMW and works on the original guest-memory address.
    return __atomic_compare_exchange_n(word, &expected, desired, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#endif
}

inline void GuestMemoryBarrier() {
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

// __kuser_cmpxchg promises C=1 exactly when r0 reports success. Preserve all
// other CPSR bits; the guest's caller may branch directly on Carry.
constexpr std::uint32_t KuserCpsrWithCarry(std::uint32_t cpsr, bool exchanged) {
    constexpr std::uint32_t kCarry = 0x20000000u;
    return (cpsr & ~kCarry) | (exchanged ? kCarry : 0u);
}

}  // namespace mc4
