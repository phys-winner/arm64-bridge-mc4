#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sys/types.h>
#include <unistd.h>

namespace mc4 {

// The guest's mmap offset is relative to the virtual file, not to its
// unaligned STORED payload inside the APK. Its 32-bit Linux page ABI is 4 KiB
// even when the arm64 host uses 16-KiB pages.
struct ApkVfdView {
    size_t span;
    size_t copy_bytes;
};

inline bool PrepareApkVfdView(uint64_t member_size, uint64_t virtual_offset,
                              uint64_t length, size_t host_page,
                              ApkVfdView* out) {
    constexpr uint64_t kGuestPage = 4096;
    if (!out || !length || !host_page ||
        (host_page & (host_page - 1)) != 0 || host_page < kGuestPage ||
        virtual_offset % kGuestPage != 0 || virtual_offset >= member_size ||
        length > UINT64_MAX - (host_page - 1)) {
        errno = EINVAL;
        return false;
    }
    const uint64_t span =
        (length + host_page - 1) & ~static_cast<uint64_t>(host_page - 1);
    const uint64_t guest_span = (length + kGuestPage - 1) & ~(kGuestPage - 1);
    const uint64_t remaining = member_size - virtual_offset;
    // EOF follows the guest's 4-KiB page ABI, not the host's page size.
    // Host-page padding is inaccessible to the requested guest view; reject
    // requests that would include a wholly out-of-file guest page.
    if (!span || span > UINT32_MAX ||
        (length > remaining && length - remaining >= kGuestPage)) {
        errno = EINVAL;
        return false;
    }
    out->span = static_cast<size_t>(span);
    out->copy_bytes = static_cast<size_t>(guest_span < remaining ? guest_span : remaining);
    return true;
}

inline bool CopyApkVfdView(int apk_fd, uint64_t member_offset,
                           uint64_t virtual_offset, const ApkVfdView& view,
                           void* destination) {
    constexpr size_t kReadChunk = 1u << 20;
    const uint64_t off_max =
        static_cast<uint64_t>(std::numeric_limits<off_t>::max());
    if (apk_fd < 0 || !destination || !view.span ||
        view.copy_bytes > view.span || member_offset > off_max ||
        virtual_offset > off_max - member_offset ||
        view.copy_bytes > off_max - member_offset - virtual_offset) {
        errno = EINVAL;
        return false;
    }
    uint8_t* const dst = static_cast<uint8_t*>(destination);
    const uint64_t source = member_offset + virtual_offset;
    size_t done = 0;
    while (done < view.copy_bytes) {
        const size_t amount =
            (view.copy_bytes - done < kReadChunk) ? view.copy_bytes - done : kReadChunk;
        const ssize_t n = pread(apk_fd, dst + done, amount,
                                static_cast<off_t>(source + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (n == 0) errno = EIO;
            return false;
        }
        done += static_cast<size_t>(n);
    }
    if (view.copy_bytes < view.span)
        memset(dst + view.copy_bytes, 0, view.span - view.copy_bytes);
    return true;
}

}  // namespace mc4
