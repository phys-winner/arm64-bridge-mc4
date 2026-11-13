#include "../src/apk_vfd_map.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <unistd.h>

static void Check(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void WriteAll(int fd, const unsigned char* bytes, size_t length) {
    while (length) {
        const ssize_t n = write(fd, bytes, length);
        Check(n > 0, "fixture write");
        bytes += n;
        length -= static_cast<size_t>(n);
    }
}

int main() {
    constexpr size_t kPrefix = 1176;
    constexpr size_t kMember = 4096 + 197;
    constexpr size_t kSuffix = 2476;
    constexpr size_t kTotal = kPrefix + kMember + kSuffix;
    unsigned char* fixture = static_cast<unsigned char*>(malloc(kTotal));
    Check(fixture != nullptr, "fixture allocation");
    memset(fixture, 0xa5, kPrefix);
    for (size_t i = 0; i < kMember; ++i)
        fixture[kPrefix + i] = static_cast<unsigned char>((i * 13 + 7) & 0xff);
    memset(fixture + kPrefix + kMember, 0x5a, kSuffix);

    char path[] = "/data/local/tmp/mc4-vfd-fixture-XXXXXX";
    const int fd = mkstemp(path);
    Check(fd >= 0, "temporary fixture creation");
    Check(unlink(path) == 0, "fixture unlinked before test");
    WriteAll(fd, fixture, kTotal);

    for (size_t page : {static_cast<size_t>(4096), static_cast<size_t>(16384)}) {
        mc4::ApkVfdView view{};
        Check(mc4::PrepareApkVfdView(kMember, 0, kMember, page, &view),
              "whole-member view geometry");
        Check(view.span % page == 0 && view.copy_bytes == kMember,
              "page alignment and exact virtual length");
        unsigned char* mapped = static_cast<unsigned char*>(malloc(view.span));
        Check(mapped != nullptr, "view allocation");
        memset(mapped, 0xcc, view.span);
        Check(mc4::CopyApkVfdView(fd, kPrefix, 0, view, mapped),
              "copy unaligned APK payload into aligned virtual view");
        Check(memcmp(mapped, fixture + kPrefix, kMember) == 0,
              "member bytes match exactly");
        for (size_t i = kMember; i < view.span; ++i)
            Check(mapped[i] == 0, "tail is zero, not adjacent ZIP bytes");
        free(mapped);

        Check(mc4::PrepareApkVfdView(kMember, 0, 1, page, &view),
              "short guest view geometry");
        mapped = static_cast<unsigned char*>(malloc(view.span));
        Check(mapped != nullptr, "short view allocation");
        memset(mapped, 0xcc, view.span);
        Check(mc4::CopyApkVfdView(fd, kPrefix, 0, view, mapped),
              "copy only requested guest pages");
        Check(memcmp(mapped, fixture + kPrefix, 4096) == 0,
              "short view contains the first guest page");
        for (size_t i = 4096; i < view.span; ++i)
            Check(mapped[i] == 0, "16K host padding hides extra member bytes");
        free(mapped);

        Check(mc4::PrepareApkVfdView(kMember, 4096, 197, page, &view),
              "second guest page geometry");
        mapped = static_cast<unsigned char*>(malloc(view.span));
        Check(mapped != nullptr, "second view allocation");
        memset(mapped, 0xcc, view.span);
        Check(mc4::CopyApkVfdView(fd, kPrefix, 4096, view, mapped),
              "copy virtual offset without raw APK bias");
        Check(memcmp(mapped, fixture + kPrefix + 4096, 197) == 0,
              "second guest page content");
        for (size_t i = 197; i < view.span; ++i)
            Check(mapped[i] == 0, "second view tail is zero");
        free(mapped);
    }

    mc4::ApkVfdView bad{};
    Check(!mc4::PrepareApkVfdView(kMember, 1, 197, 4096, &bad),
          "reject unaligned guest file offset");
    Check(!mc4::PrepareApkVfdView(kMember, 0, kMember + 8192, 4096, &bad),
          "reject wholly out-of-file pages");
    Check(!mc4::PrepareApkVfdView(4096, 0, 8192, 4096, &bad),
          "reject a whole out-of-file 4K guest page");
    Check(!mc4::PrepareApkVfdView(4096, 0, 8192, 16384, &bad),
          "host 16K padding cannot permit a whole out-of-file guest page");
    Check(mc4::PrepareApkVfdView(4097, 0, 8192, 16384, &bad),
          "allow partial final guest page on a 16K host");
    close(fd);
    free(fixture);
    puts("PASS: APK virtual fd view geometry, content, zero tail, 4K/16K pages");
    return 0;
}
