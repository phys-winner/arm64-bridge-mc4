#pragma once

// AAPCS32 varargs are NOT an AArch64 va_list. Decode guest words first, then
// format one explicitly typed host argument at a time. In particular, long,
// size_t and pointers are 32-bit; double/long long use aligned 64-bit slots.
// Contract: C printf conversions plus %m. POSIX positional arguments are
// explicitly rejected (EINVAL), never silently consumed using a wrong type.
#include <array>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace arm32 {

template <class Memory>
class PrintfArguments {
public:
    PrintfArguments(Memory& memory, std::array<uint32_t, 4> registers,
                    unsigned first_register, uint32_t stack)
        : memory_(memory), registers_(registers), next_(first_register),
          stack_(stack) {}
    PrintfArguments(Memory& memory, uint32_t va_list)
        : PrintfArguments(memory, {}, 4, va_list) {}

    uint32_t Word() {
        if (next_ < 4) return registers_[next_++];
        const uint32_t value = memory_.Read32(stack_);
        stack_ += 4;
        return value;
    }
    uint64_t DoubleWord() {
        next_ = (next_ + 1) & ~1u;
        if (next_ >= 4) stack_ = (stack_ + 7) & ~7u;
        const uint64_t low = Word();
        return low | (uint64_t{Word()} << 32);
    }
    const char* String(uint32_t address) { return memory_.Pointer(address); }
    std::wstring WideString(uint32_t address) {
        std::wstring result;
        if (!address) return L"(null)";
        for (uint32_t ch; (ch = memory_.Read32(address)) != 0; address += 4) {
            if constexpr (sizeof(wchar_t) == 2) {
                if (ch > 0xFFFF && ch <= 0x10FFFF) {
                    ch -= 0x10000;
                    result += static_cast<wchar_t>(0xD800 + (ch >> 10));
                    result += static_cast<wchar_t>(0xDC00 + (ch & 1023));
                    continue;
                }
            }
            result += static_cast<wchar_t>(ch);
        }
        return result;
    }
    bool StoreCount(uint32_t address, unsigned bytes, uint64_t count) {
        char* target = memory_.Pointer(address);
        if (!target) return false;
        for (unsigned i = 0; i < bytes; ++i)
            target[i] = static_cast<char>(count >> (8 * i));
        return true;
    }

private:
    Memory& memory_;
    std::array<uint32_t, 4> registers_;
    unsigned next_;
    uint32_t stack_;
};

struct PrintfResult {
    std::string text;
    int error = 0; // Android errno values: EINVAL=22, EOVERFLOW=75, EILSEQ=84.
    int Count() const { return error ? -1 : static_cast<int>(text.size()); }
};

template <class Value>
int AppendFormatted(std::string& output, const std::string& format, Value value) {
    char small[256];
    const int count = std::snprintf(small, sizeof(small), format.c_str(), value);
    if (count < 0) return 84;
    if (static_cast<size_t>(count) > INT_MAX - output.size()) return 75;
    if (static_cast<size_t>(count) < sizeof(small)) {
        output.append(small, static_cast<size_t>(count));
    } else {
        std::vector<char> large(static_cast<size_t>(count) + 1);
        if (std::snprintf(large.data(), large.size(), format.c_str(), value) != count)
            return 84;
        output.append(large.data(), static_cast<size_t>(count));
    }
    return 0;
}

template <class Arguments>
PrintfResult FormatPrintf(const char* format, Arguments arguments, int guest_errno = 0) {
    PrintfResult result;
    if (!format) { result.error = 22; return result; }
    const auto digit = [](char c) { return c >= '0' && c <= '9'; };
    for (const char* p = format; *p && !result.error;) {
        if (*p != '%') { result.text += *p++; continue; }
        ++p;
        if (*p == '%') { result.text += *p++; continue; }
        std::string spec = "%";
        while (*p && std::strchr("-+ #0'", *p)) spec += *p++;
        if (*p == '*') {
            const int32_t width = static_cast<int32_t>(arguments.Word());
            ++p;
            if (width == INT_MIN) { result.error = 75; break; }
            if (width < 0) spec += '-';
            spec += std::to_string(width < 0 ? -width : width);
        } else {
            while (digit(*p)) spec += *p++;
        }
        if (*p == '.') {
            ++p;
            if (*p == '*') {
                const int32_t precision = static_cast<int32_t>(arguments.Word());
                ++p;
                if (precision >= 0) spec += '.' + std::to_string(precision);
            } else {
                spec += '.';
                while (digit(*p)) spec += *p++;
            }
        }
        std::string length;
        if (*p && std::strchr("hljztLq", *p)) {
            length += *p++;
            if ((length == "h" && *p == 'h') || (length == "l" && *p == 'l'))
                length += *p++;
        }
        if (!*p) { result.error = 22; break; }
        const char conversion = *p++;
        const bool wide_integer = length == "ll" || length == "j" || length == "q";
        if (std::strchr("diuoxX", conversion)) {
            const uint64_t raw = wide_integer ? arguments.DoubleWord() : arguments.Word();
            spec += "ll";
            spec += conversion;
            if (conversion == 'd' || conversion == 'i') {
                int64_t value;
                if (wide_integer) std::memcpy(&value, &raw, sizeof(value));
                else if (length == "hh") value = static_cast<int8_t>(raw);
                else if (length == "h") value = static_cast<int16_t>(raw);
                else value = static_cast<int32_t>(raw);
                result.error = AppendFormatted(result.text, spec, static_cast<long long>(value));
            } else {
                uint64_t value = raw;
                if (length == "hh") value = static_cast<uint8_t>(raw);
                else if (length == "h") value = static_cast<uint16_t>(raw);
                result.error = AppendFormatted(result.text, spec, static_cast<unsigned long long>(value));
            }
        } else if (std::strchr("fFeEgGaA", conversion)) {
            const uint64_t raw = arguments.DoubleWord();
            double value;
            std::memcpy(&value, &raw, sizeof(value));
            spec += conversion; // ARM32 long double is also IEEE binary64.
            result.error = AppendFormatted(result.text, spec, value);
        } else if (conversion == 's') {
            const uint32_t address = arguments.Word();
            if (length == "l") {
                const auto value = arguments.WideString(address);
                result.error = AppendFormatted(result.text, spec + "ls", value.c_str());
            } else {
                const char* value = arguments.String(address);
                result.error = AppendFormatted(result.text, spec + 's', value ? value : "(null)");
            }
        } else if (conversion == 'c') {
            const uint32_t value = arguments.Word();
            result.error = AppendFormatted(result.text, spec + (length == "l" ? "lc" : "c"), value);
        } else if (conversion == 'p') {
            const uintptr_t value = arguments.Word(); // Print guest, never translated host address.
            result.error = AppendFormatted(result.text, spec + 'p', reinterpret_cast<void*>(value));
        } else if (conversion == 'n') {
            const unsigned bytes = wide_integer ? 8 : length == "hh" ? 1 : length == "h" ? 2 : 4;
            if (!arguments.StoreCount(arguments.Word(), bytes, result.text.size())) result.error = 22;
        } else if (conversion == 'm') {
            result.error = AppendFormatted(result.text, spec + 's', std::strerror(guest_errno));
        } else {
            // Includes positional $ syntax; do not guess how many words it used.
            result.error = 22;
        }
        if (result.text.size() > INT_MAX) result.error = 75;
    }
    return result;
}

inline int CopyPrintfResult(char* destination, size_t capacity, const PrintfResult& result) {
    if (capacity && !destination) return -1;
    if (capacity) {
        const size_t count = result.text.size() < capacity - 1 ? result.text.size() : capacity - 1;
        std::memcpy(destination, result.text.data(), count);
        destination[count] = 0;
    }
    return result.Count(); // Count includes truncated bytes, excludes the final NUL.
}

} // namespace arm32
