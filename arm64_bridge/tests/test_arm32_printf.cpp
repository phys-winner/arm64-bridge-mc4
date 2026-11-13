#include "arm32_printf.h"
#include <cstdlib>
#include <iostream>

static unsigned checks = 0;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    std::cerr << "FAIL line " << __LINE__ << ": " #condition << '\n'; std::exit(1); \
} } while (0)

struct Memory {
    std::array<char, 4096> bytes{};
    uint32_t Read32(uint32_t address) {
        CHECK(address + 4 <= bytes.size());
        uint32_t value;
        std::memcpy(&value, bytes.data() + address, 4);
        return value;
    }
    char* Pointer(uint32_t address) {
        CHECK(address < bytes.size());
        return address ? bytes.data() + address : nullptr;
    }
    void Word(uint32_t address, uint32_t value) { std::memcpy(Pointer(address), &value, 4); }
    void Wide(uint32_t address, uint64_t value) { std::memcpy(Pointer(address), &value, 8); }
    void Double(uint32_t address, double value) { std::memcpy(Pointer(address), &value, 8); }
    auto Va(uint32_t address = 0x100) { return arm32::PrintfArguments(*this, address); }
    auto Registers(std::array<uint32_t, 4> values, unsigned first) {
        return arm32::PrintfArguments(*this, values, first, 0x100);
    }
};

static void Expect(const arm32::PrintfResult& result, const std::string& expected) {
    CHECK(result.error == 0);
    if (result.text != expected)
        std::cerr << "expected [" << expected << "] got [" << result.text << "]\n";
    CHECK(result.text == expected);
    CHECK(result.Count() == static_cast<int>(expected.size()));
}

int main() {
    Memory m;
    std::memcpy(m.Pointer(0x500), "abcdef", 7);
    m.Word(0x100, 789);
    Expect(arm32::FormatPrintf("%s:%d:%d:%d", m.Registers({0, 0x500, 123, 456}, 1)),
           "abcdef:123:456:789");

    // Odd starting NCRN must skip r1/r3 for a 64-bit value.
    m.Word(0x100, 7);
    Expect(arm32::FormatPrintf("%llx %u", m.Registers({0, 0xDEAD, 0x89ABCDEF, 0x1234567}, 1)),
           "123456789abcdef 7");
    m.Wide(0x100, 0x123456789ABCDEFULL);
    m.Word(0x108, 9);
    Expect(arm32::FormatPrintf("%llx %u", m.Registers({0, 0, 0, 0xDEAD}, 3)),
           "123456789abcdef 9");
    m.Wide(0x108, 0xFEDCBA9876543210ULL);
    Expect(arm32::FormatPrintf("%llX", m.Va(0x104)), "FEDCBA9876543210");

    Expect(arm32::FormatPrintf("%08x/%#o/%+06d/%-5.3s", m.Registers({42, 8, uint32_t(-7), 0x500}, 0)),
           "0000002a/010/-00007/abc  ");
    Expect(arm32::FormatPrintf("%hhd %hhu %hd %hu", m.Registers({255, 511, 65535, 131071}, 0)),
           "-1 255 -1 65535");
    Expect(arm32::FormatPrintf("%ld %lu %zu %td", m.Registers({uint32_t(-2), UINT32_MAX, 5, uint32_t(-6)}, 0)),
           "-2 4294967295 5 -6");
    Expect(arm32::FormatPrintf("%*.*s!", m.Registers({uint32_t(-7), 3, 0x500, 0}, 0)), "abc    !");
    Expect(arm32::FormatPrintf("%.*s", m.Registers({uint32_t(-1), 0x500, 0, 0}, 0)), "abcdef");
    Expect(arm32::FormatPrintf("[%s]", m.Registers({0, 0, 0, 0}, 0)), "[(null)]");

    // Promoted double after a 32-bit argument aligns past the pad word.
    m.Word(0x100, 11); m.Word(0x104, 0xDEADBEEF); m.Double(0x108, 1.25); m.Word(0x110, 22);
    Expect(arm32::FormatPrintf("%d %.2f %d", m.Va()), "11 1.25 22");
    for (double value : {0.0, -0.0, -2.5, 1e-8, 1e20}) {
        m.Double(0x100, value);
        for (const char* format : {"%.3f", "%+.4e", "%.7g", "%a", "%A"}) {
            char expected[128];
            std::snprintf(expected, sizeof(expected), format, value);
            Expect(arm32::FormatPrintf(format, m.Va()), expected);
        }
    }
    m.Double(0x100, 3.5);
    Expect(arm32::FormatPrintf("%.1Lf", m.Va()), "3.5");
    m.Wide(0x100, UINT64_MAX);
    Expect(arm32::FormatPrintf("%llu", m.Va()), "18446744073709551615");
    Expect(arm32::FormatPrintf("%lld", m.Va()), "-1");

    // %n observes the full logical output count with guest-sized destinations.
    Expect(arm32::FormatPrintf("ab%hhncd%hnEF%lnG%lln", m.Registers({0x600, 0x610, 0x620, 0x630}, 0)), "abcdEFG");
    CHECK(m.bytes[0x600] == 2);
    CHECK(m.Read32(0x610) == 4);
    CHECK(m.Read32(0x620) == 6);
    CHECK(m.Read32(0x630) == 7 && m.Read32(0x634) == 0);
    auto result = arm32::FormatPrintf("%c%d", m.Registers({0, 5, 0, 0}, 0));
    CHECK(result.text.size() == 2 && result.text[0] == 0 && result.text[1] == '5');
    char output[8]; std::memset(output, 'X', sizeof(output));
    CHECK(arm32::CopyPrintfResult(output, sizeof(output), result) == 2);
    CHECK(output[0] == 0 && output[1] == '5' && output[2] == 0 && output[3] == 'X');

    result = arm32::FormatPrintf("abcdef", m.Va());
    for (size_t capacity = 0; capacity <= 8; ++capacity) {
        std::memset(output, 'X', sizeof(output));
        CHECK(arm32::CopyPrintfResult(output, capacity, result) == 6);
        const size_t written = capacity ? (capacity < 7 ? capacity - 1 : 6) : 0;
        CHECK(std::memcmp(output, "abcdef", written) == 0);
        if (capacity) CHECK(output[written] == 0);
        if (capacity < sizeof(output)) CHECK(output[capacity] == 'X');
    }
    CHECK(arm32::CopyPrintfResult(nullptr, 0, result) == 6);
    m.Word(0x700, 'A'); m.Word(0x704, 'B'); m.Word(0x708, 0);
    Expect(arm32::FormatPrintf("%ls/%lc", m.Registers({0x700, 'C', 0, 0}, 0)), "AB/C");
    Expect(arm32::FormatPrintf("%% %.0d %300s", m.Registers({0, 0x500, 0, 0}, 0)),
           "%  " + std::string(294, ' ') + "abcdef");
    CHECK(arm32::FormatPrintf("%1$s", m.Va()).error == 22);
    CHECK(arm32::FormatPrintf("%", m.Va()).error == 22);
    CHECK(arm32::FormatPrintf("%*s", m.Registers({0x80000000, 0x500, 0, 0}, 0)).error == 75);
    std::cout << "ARM32 printf PASS: " << checks << " checks\n";
}
