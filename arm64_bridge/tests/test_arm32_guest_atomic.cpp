#include "arm32_guest_atomic.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <new>
#include <thread>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* name) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", name);
        ++failures;
    }
}

}  // namespace

int main() {
    alignas(64) std::array<std::uint8_t, 64> memory{};
    auto* word = new (memory.data() + 16) std::uint32_t(0);
#if defined(_MSC_VER)
    std::atomic_ref<std::uint32_t> atom(*word);
    auto load_word = [&] { return atom.load(std::memory_order_seq_cst); };
    auto store_word = [&](std::uint32_t value) { atom.store(value, std::memory_order_seq_cst); };
#else
    auto load_word = [&] { return __atomic_load_n(word, __ATOMIC_SEQ_CST); };
    auto store_word = [&](std::uint32_t value) { __atomic_store_n(word, value, __ATOMIC_SEQ_CST); };
#endif

    Check(mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 16u, 0u, 7u),
          "matching CAS succeeds");
    Check(!mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 16u, 0u, 9u),
          "mismatched CAS fails");
    Check(load_word() == 7u, "failed CAS does not write");
    Check(!mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 17u, 0u, 9u),
          "unaligned CAS fails closed");
    Check(!mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 62u, 0u, 9u),
          "out-of-range CAS fails closed");
    Check(!mc4::GuestAtomicCompareExchange<std::uint32_t>(nullptr, memory.size(), 16u, 0u, 9u),
          "null guest memory fails closed");

    constexpr std::uint32_t kCarry = 0x20000000u;
    constexpr std::uint32_t kOtherFlags = 0x90000020u;
    Check(mc4::KuserCpsrWithCarry(kOtherFlags, true) == (kOtherFlags | kCarry),
          "successful kuser CAS sets Carry and preserves other CPSR bits");
    Check(mc4::KuserCpsrWithCarry(kOtherFlags | kCarry, false) == kOtherFlags,
          "failed kuser CAS clears Carry and preserves other CPSR bits");

    auto* half = new (memory.data() + 24) std::uint16_t(3);
    auto* wide = new (memory.data() + 32) std::uint64_t(5);
    Check(mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 24u,
                                          std::uint16_t{3}, std::uint16_t{4}) && *half == 4,
          "16-bit exclusive store uses atomic primitive");
    Check(mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 32u,
                                          std::uint64_t{5}, std::uint64_t{6}) && *wide == 6,
          "64-bit exclusive store uses atomic primitive");

    store_word(0);
    constexpr int kThreads = 4;
    constexpr int kIterations = 50000;
    std::atomic<bool> start{false};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&] {
            while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
            for (int n = 0; n < kIterations; ++n) {
                for (;;) {
                    std::uint32_t before = load_word();
                    if (mc4::GuestAtomicCompareExchange(memory.data(), memory.size(), 16u,
                                                        before, before + 1)) break;
                }
            }
        });
    }
    start.store(true, std::memory_order_release);
    for (auto& worker : workers) worker.join();
    Check(load_word() == kThreads * kIterations,
          "four competing guest cores do not lose CAS updates");
    mc4::GuestMemoryBarrier();

    if (failures) return 1;
    std::puts("11 guest atomic checks passed");
    return 0;
}
