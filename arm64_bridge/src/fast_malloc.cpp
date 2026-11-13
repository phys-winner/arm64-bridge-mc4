// Fast guest-side allocator stub (2026-09-17 "significantly speed up the reader").
//
// The guest imports malloc/free; every C++ temporary in the zip TOC parse
// crosses the SVC->host->JIT roundtrip (~50-100 us each, ~2500 per parsed
// entry => ~190 ms/entry). This installs a tiny ARM bump allocator in guest
// code: malloc/calloc become pure guest instructions (~100x cheaper), with a
// 16-byte block header ({magic, base, capacity, payload_size}) so the real
// free/realloc thunks keep working on bump blocks. When both pools run dry
// the stub tail-calls the original malloc trampoline.
//
// Pools: two GuestAlloc windows (host pages start zeroed, so calloc stays
// correct -- pure bump never reuses memory). Thread safety: ldrex/strex on
// the pool cursor (the main run and the serialized worker allocate
// concurrently). free() is a no-op: bump memory is never reclaimed; the
// 1.5 GB of pools absorb the load phase; post-exhaustion allocations fall
// back to the original malloc thunk (which recycles through the host
// free-lists and therefore still works for the rest of the session).
#include "dynarmic_host.h"
#include <android/log.h>
#include "thunk_manager.h"
#include <cstdint>
#include <cstring>
#include <vector>

namespace mc4 {

namespace {

constexpr uint32_t kStubMagic = 0x41524D31u;  // same 'ARM1' live-block magic
constexpr uint32_t kPoolASize = 600u << 20;   // heap window 1
constexpr uint32_t kPoolBSize = 900u << 20;   // heap window 2
constexpr uint32_t kNop = 0xE1A00000u;

constexpr uint32_t R0 = 0, R1 = 1, R2 = 2, R3 = 3, R12 = 12, LR = 14;

constexpr uint32_t kCondNE = 0x10000000u;
constexpr uint32_t kCondHS = 0x20000000u;
constexpr uint32_t kCondAL = 0xE0000000u;

uint32_t movw(uint32_t rd, uint16_t imm) {
    return 0xE3000000u | ((uint32_t)(imm >> 12) << 16) | (rd << 12) | (imm & 0xFFFu);
}
uint32_t movt(uint32_t rd, uint16_t imm) {
    return 0xE3400000u | ((uint32_t)(imm >> 12) << 16) | (rd << 12) | (imm & 0xFFFu);
}
uint32_t ldrex(uint32_t rt, uint32_t rn) {
    return 0xE1900F9Fu | (rn << 16) | (rt << 12);
}
uint32_t strex(uint32_t rd, uint32_t rt, uint32_t rn) {
    return 0xE1800F90u | (rn << 16) | (rd << 12) | rt;
}
uint32_t add_imm(uint32_t rd, uint32_t rn, uint32_t imm12) {
    return 0xE2800000u | (rn << 16) | (rd << 12) | (imm12 & 0xFFFu);
}
uint32_t sub_imm(uint32_t rd, uint32_t rn, uint32_t imm12) {
    return 0xE2400000u | (rn << 16) | (rd << 12) | (imm12 & 0xFFFu);
}
uint32_t bic_imm(uint32_t rd, uint32_t rn, uint32_t imm12) {
    return 0xE3C00000u | (rn << 16) | (rd << 12) | (imm12 & 0xFFFu);
}
uint32_t cmp_imm(uint32_t rn, uint32_t imm12) {
    return 0xE3500000u | (rn << 16) | (imm12 & 0xFFFu);
}
uint32_t cmp_reg(uint32_t rn, uint32_t rm) {
    return 0xE1500000u | (rn << 16) | rm;
}
uint32_t ldr_imm(uint32_t rt, uint32_t rn, uint32_t imm12) {
    return 0xE5900000u | (rn << 16) | (rt << 12) | (imm12 & 0xFFFu);
}
uint32_t str_imm(uint32_t rt, uint32_t rn, uint32_t imm12) {
    return 0xE5800000u | (rn << 16) | (rt << 12) | (imm12 & 0xFFFu);
}
uint32_t add_reg(uint32_t rd, uint32_t rn, uint32_t rm) {
    return 0xE0800000u | (rn << 16) | (rd << 12) | rm;
}
uint32_t mov_reg(uint32_t rd, uint32_t rm) {
    return 0xE1A00000u | (rd << 12) | rm;
}
uint32_t bx(uint32_t rm) {
    return 0xE12FFF10u | rm;
}
uint32_t branch(uint32_t cond, int32_t offset_bytes) {
    return cond | 0x0A000000u | ((uint32_t)(offset_bytes >> 2) & 0x00FFFFFFu);
}

}  // namespace

// SVC probe cell for the wrapper: logs {this, result}. Registered lazily.
static uint32_t g_zip_result_cell = 0;

bool InstallZipResultProbe(DynarmicHost& host, uint32_t init_entry_guest) {
#ifndef LOGE
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "Arm32Bridge_Host", __VA_ARGS__)
#endif
    constexpr uint32_t R4 = 4, R5 = 5;
    uint32_t probe_cell = host.GetThunkManager().RegisterThunk("probe_zipresult",
        [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            static std::atomic<uint32_t> n{0};
            uint32_t k = n.fetch_add(1, std::memory_order_relaxed) + 1;
            if (k <= 24 || (k % 5000) == 0)
                LOGE("[ZIPRESULT] #%u this=%08X init_result=%08X",
                     k, jit.Regs()[0], jit.Regs()[1]);
        });
    g_zip_result_cell = probe_cell;

    // Wrapper blob:
    //   push {r4, r5, lr}; mov r4, r0; blx real_init(0x134E09C);
    //   mov r5, r0; mov r0, r4; mov r1, r5; bl probe_cell;
    //   mov r0, r5; pop {r4, r5, pc}
    const uint32_t blob_words = 64;
    uint32_t blob = host.GuestAlloc(blob_words * 4, 64);
    if (!blob) return false;
    std::vector<uint32_t> w;
    w.push_back(0xE92D4030u);                       // push {r4, r5, lr}
    w.push_back(mov_reg(R4, R0));                   // r4 = this
    w.push_back(movw(R12, 0xE09Cu));
    w.push_back(movt(R12, 0x134Eu));                // r12 = 0x134E09C (real init)
    w.push_back(0xE12FFF3Cu);                       // blx r12
    w.push_back(mov_reg(R5, R0));                   // r5 = result
    w.push_back(mov_reg(R0, R4));                   // r0 = this
    w.push_back(mov_reg(R1, R5));                   // r1 = result
    w.push_back(movw(R12, probe_cell & 0xFFFFu));
    w.push_back(movt(R12, probe_cell >> 16));
    w.push_back(0xE12FFF3Cu);                       // blx r12 (probe)
    w.push_back(mov_reg(R0, R5));                   // r0 = result
    w.push_back(0xE8BD8030u);                       // pop {r4, r5, pc}

    uint8_t* mem = host.GetGuestMemoryBase();
    if (!mem) return false;
    memset(mem + blob, 0, blob_words * 4);
    for (size_t i = 0; i < w.size(); ++i)
        memcpy(mem + blob + i * 4, &w[i], 4);
    host.AddExecutableRange(blob, blob_words * 4);
    host.InvalidateGuestCode(blob, blob_words * 4);

    // Patch the init entry: ldr r12, [pc, #0]; bx r12; <wrapper>
    host.MemoryWrite32(init_entry_guest, 0xE59FC000u);      // ldr r12, [pc, #0]
    host.MemoryWrite32(init_entry_guest + 4, 0xE12FFF1Cu);  // bx r12
    host.MemoryWrite32(init_entry_guest + 8, blob);         // literal = wrapper
    host.InvalidateGuestCode(init_entry_guest, 12);
    return true;
}

bool InstallFastGuestMalloc(DynarmicHost& host) {
    // Pools: A lands in heap window 1, B in window 2 (fresh, zeroed pages).
    uint32_t pool_a = host.GuestAlloc(kPoolASize, 0x1000);
    uint32_t pool_b = host.GuestAlloc(kPoolBSize, 0x1000);
    if (!pool_a || !pool_b) {
        return false;
    }
    uint32_t real_cell = host.GetThunkManager().GetOrCreateThunkAddress("malloc");
    if (!real_cell) return false;

    // Blob layout (word units): [0] one-instruction free no-op, [8..11]
    // allocator table (curA, endA, curB, endB), [12..] malloc stub code.
    const uint32_t blob_words = 64;
    uint32_t blob = host.GuestAlloc(blob_words * 4, 256);
    if (!blob) return false;
    const uint32_t free_stub = blob;      // `bx lr`
    const uint32_t table = blob + 32;     // words 8..11
    const uint32_t m_start = blob + 48;   // malloc code from word 12

    std::vector<uint32_t> words;
    const auto load32 = [&](uint32_t reg, uint32_t addr) {
        words.push_back(movw(reg, addr & 0xFFFFu));
        words.push_back(movt(reg, (addr >> 16) & 0xFFFFu));
    };

    // ---- size cap: a corrupt count (PerksMP ctor reads a garbage entry
    // count from a synthetic file, 2026-09-18) asks for ~4 GB; the pools
    // rightly refuse, the stub returns 0 and the guest alloc-loops forever.
    // Clamp absurd requests to a small valid block instead.
    words.push_back(0xE3500404u);                   // cmp r0, #0x04000000
    words.push_back(0xC3A00040u);                   // movgt r0, #0x40

    // ---- pool A ----
    load32(R1, table);
    const size_t retry_a = words.size();
    words.push_back(ldrex(R2, R1));                 // cur = [tableA]
    words.push_back(add_imm(R3, R0, 31));           // asize = size + 31
    words.push_back(bic_imm(R3, R3, 7));            // asize &= ~7
    words.push_back(mov_reg(R12, R2));              // r12 = cur
    words.push_back(add_reg(R12, R12, R3));         // r12 += asize
    words.push_back(ldr_imm(R0, R1, 4));            // end
    words.push_back(cmp_reg(R12, R0));
    const size_t a_full = words.size();
    words.push_back(branch(kCondHS, 0));            // -> pool B
    words.push_back(strex(R0, R12, R1));            // cur = new
    words.push_back(cmp_imm(R0, 0));
    const size_t a_retry = words.size();
    words.push_back(branch(kCondNE, 0));            // -> retry_a
    const size_t a_done = words.size();
    words.push_back(branch(kCondAL, 0));            // -> finish

    // ---- pool B ----
    const size_t pB = words.size();
    load32(R1, table + 8);
    const size_t retry_b = words.size();
    words.push_back(ldrex(R2, R1));
    words.push_back(add_imm(R3, R0, 31));
    words.push_back(bic_imm(R3, R3, 7));
    words.push_back(mov_reg(R12, R2));
    words.push_back(add_reg(R12, R12, R3));
    words.push_back(ldr_imm(R0, R1, 4));
    words.push_back(cmp_reg(R12, R0));
    const size_t b_full = words.size();
    words.push_back(branch(kCondHS, 0));            // -> real
    words.push_back(strex(R0, R12, R1));
    words.push_back(cmp_imm(R0, 0));
    const size_t b_retry = words.size();
    words.push_back(branch(kCondNE, 0));            // -> retry_b
    // fall through to finish

    // ---- finish: header {magic, ZERO, capacity, payload_size}; r0 = payload.
    // [payload-12] MUST be zero: iFPS::Init's folder-loop completion check
    // (0x8A2D20: ldr r3,[obj-12]; cmp 0; bne abort) reads exactly this slot --
    // a non-zero value (dlmalloc leaves 0 there on real hardware) sent every
    // Init call down the error path and wedged the loader in M2 forever.
    const size_t finish = words.size();
    words.push_back(movw(R1, 0x4D31u));
    words.push_back(movt(R1, 0x4152u));             // r1 = kStubMagic
    words.push_back(str_imm(R1, R2, 0));            // [base] = magic
    words.push_back(0xE3A01000u);                   // mov r1, #0
    words.push_back(str_imm(R1, R2, 4));            // [base+4] = 0
    words.push_back(str_imm(R3, R2, 8));            // [base+8] = capacity
    words.push_back(sub_imm(R1, R3, 16));           // payload size
    words.push_back(str_imm(R1, R2, 12));           // [base+12]
    words.push_back(add_imm(R0, R2, 16));           // r0 = payload
    words.push_back(bx(LR));

    // ---- real fallback: tail-call the original malloc trampoline ----
    const size_t real = words.size();
    load32(R12, real_cell);
    words.push_back(bx(R12));

    // ---- branch fixups (target = m_start + word*4; rel = tgt - (pc+8)) ----
    const auto fix = [&](size_t at_word, uint32_t cond, size_t target_word) {
        int32_t rel = int32_t(target_word * 4) - int32_t(at_word * 4 + 8);
        words[at_word] = branch(cond, rel);
    };
    fix(a_full, kCondHS, pB);
    fix(a_retry, kCondNE, retry_a);
    fix(a_done, kCondAL, finish);
    fix(b_full, kCondHS, real);
    fix(b_retry, kCondNE, retry_b);

    // ---- commit ----
    uint8_t* mem = host.GetGuestMemoryBase();
    if (!mem) return false;
    memset(mem + blob, 0, blob_words * 4);
    const auto put = [&](size_t word_index, uint32_t v) {
        memcpy(mem + blob + word_index * 4, &v, 4);
    };
    // free is intentionally a no-op for this bump allocator. It must return
    // immediately: falling through into the table below would execute data
    // as ARM instructions and then enter the malloc stub with the wrong ABI.
    put(0, bx(LR));
    put(8, pool_a);
    put(9, pool_a + kPoolASize);
    put(10, pool_b);
    put(11, pool_b + kPoolBSize);
    for (size_t i = 0; i < words.size(); ++i) {
        put(12 + i, words[i]);
    }
    host.AddExecutableRange(blob, blob_words * 4);
    host.InvalidateGuestCode(blob, blob_words * 4);

    host.SetFastPoolTable(table);
    // ---- redirect the allocator GOT slots ----
    const uint32_t slots[][2] = {
        {0x4179C07Cu, m_start},   // malloc GLOB_DAT
        {0x4179EA88u, m_start},   // malloc JUMP_SLOT
        {0x4179C09Cu, m_start},   // calloc GLOB_DAT (bump pages are zero)
        {0x4179ED2Cu, m_start},   // calloc JUMP_SLOT
        {0x4179C084u, free_stub}, // free GLOB_DAT -> no-op
        {0x4179EAA8u, free_stub}, // free JUMP_SLOT -> no-op
    };
    for (auto& slot : slots) {
        host.MemoryWrite32(slot[0], slot[1]);
    }
    return true;
}

}  // namespace mc4
