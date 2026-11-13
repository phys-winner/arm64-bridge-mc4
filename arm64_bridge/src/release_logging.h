#pragma once

#include <android/log.h>

#ifndef MC4_ENABLE_NATIVE_LOGGING
#define MC4_ENABLE_NATIVE_LOGGING 0
#endif

#if !MC4_ENABLE_NATIVE_LOGGING
// Keep argument evaluation, including counters and guest printf side effects.
inline int mc4_quiet_log_print(int, const char*, const char*, ...) {
    return 0;
}

inline int mc4_quiet_log_write(int, const char*, const char*) {
    return 0;
}

#define __android_log_print mc4_quiet_log_print
#define __android_log_write mc4_quiet_log_write
#endif
