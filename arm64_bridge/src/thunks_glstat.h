// Bring-up-only GL counters/timers. Release builds leave the instrumentation
// compiled out: the guest can issue over a thousand instrumented GL calls per
// frame, and two clock reads plus atomic writes per call distort performance.
// Define MC4_GL_TIMING_ENABLED=1 for an explicitly instrumented diagnostic.
#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>

#ifndef MC4_GL_TIMING_ENABLED
#define MC4_GL_TIMING_ENABLED MC4_ENABLE_NATIVE_LOGGING
#endif

// Per-call GL trace logs are useful during bring-up but run on the guest's
// serial render thread. Keep their counters and branches out of release draws.
#ifndef MC4_GL_DRAW_TRACE_ENABLED
#define MC4_GL_DRAW_TRACE_ENABLED 0
#endif

namespace glstat {
enum Idx {
    Swap = 0, Clear, DrawArrays, DrawElements, TexImage2D, TexSubImage2D,
    CompressedTexImage2D, UseProgram, ShaderSource, CompileShader, LinkProgram,
    GetShaderiv, GetProgramiv, GetUniformLocation, GetAttribLocation,
    VertexAttribPointer, EnableVertexAttribArray, BufferData, BufferSubData,
    BindTexture, ActiveTexture, Viewport, GetError, ReadPixels, BindFramebuffer,
    CheckFramebufferStatus, COUNT
};
inline const char* const kNames[COUNT] = {
    "eglSwapBuffers", "glClear", "glDrawArrays", "glDrawElements",
    "glTexImage2D", "glTexSubImage2D", "glCompressedTexImage2D", "glUseProgram",
    "glShaderSource", "glCompileShader", "glLinkProgram", "glGetShaderiv",
    "glGetProgramiv", "glGetUniformLocation", "glGetAttribLocation",
    "glVertexAttribPointer", "glEnableVertexAttribArray", "glBufferData",
    "glBufferSubData", "glBindTexture", "glActiveTexture", "glViewport",
    "glGetError", "glReadPixels", "glBindFramebuffer",
    "glCheckFramebufferStatus" };
inline std::atomic<uint32_t> g_n[COUNT];
inline std::atomic<uint32_t> g_dump{0};
inline void Bump(int i) {
#if MC4_GL_TIMING_ENABLED
    g_n[i].fetch_add(1, std::memory_order_relaxed);
#else
    (void)i;
#endif
}

// Bounded CPU-side graphics timing for the first-person performance gate.
// Counts/times are consumed once per 128 GL2_step calls; no per-draw logging.
enum TimeIdx {
    MapTime, UnmapTime, DrawTime, SwapTime, BufferSubDataTime,
    AttribTime, BindTextureTime, UseProgramTime, UniformMatrixTime,
    TIME_COUNT
};
inline const char* const kTimeNames[TIME_COUNT] = {
    "map", "unmap", "draw", "swap", "subdata", "attrib", "bindtex",
    "program", "matrix"
};
inline std::atomic<uint64_t> g_time_ns[TIME_COUNT];
inline std::atomic<uint32_t> g_time_calls[TIME_COUNT];
class ScopedTime {
public:
#if MC4_GL_TIMING_ENABLED
    explicit ScopedTime(TimeIdx category)
        : category_(category), start_(std::chrono::steady_clock::now()) {}
    ~ScopedTime() {
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start_).count();
        g_time_ns[category_].fetch_add(static_cast<uint64_t>(elapsed),
                                       std::memory_order_relaxed);
        g_time_calls[category_].fetch_add(1, std::memory_order_relaxed);
    }
    ScopedTime(const ScopedTime&) = delete;
    ScopedTime& operator=(const ScopedTime&) = delete;
private:
    TimeIdx category_;
    std::chrono::steady_clock::time_point start_;
#else
    explicit ScopedTime(TimeIdx) {}
#endif
};
} // namespace glstat
