#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "thunks_glstat.h"
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl3.h>
#include <GLES3/gl31.h>
#include <EGL/egl.h>
#include <android/log.h>
#include <algorithm>
#include <vector>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>


// Mirror bindings per owner thread; Java can switch the current EGL context.
// Query only on a context switch, not on every draw/attribute update.
struct GLBindings {
    EGLContext context = EGL_NO_CONTEXT;
    GLint array_buffer = 0;
    GLint element_buffer = 0;
    GLint draw_framebuffer = 0;
};
static thread_local GLBindings s_bindings;

#if MC4_ENABLE_NATIVE_LOGGING
static thread_local std::unordered_map<EGLContext,
    std::unordered_map<GLuint, std::unordered_map<GLint, std::string>>> s_uniform_names;

// Look up uniforms already queried by the guest; never drain GL error state.
const char* GuestGLUniformName(uint32_t location, uint32_t* program) {
    *program = 0;
    const EGLContext context = eglGetCurrentContext();
    if (context == EGL_NO_CONTEXT) return "";
    GLint current_program = 0;
    glGetIntegerv(GL_CURRENT_PROGRAM, &current_program);
    *program = static_cast<uint32_t>(current_program);
    const auto context_names = s_uniform_names.find(context);
    if (context_names == s_uniform_names.end()) return "";
    const auto names = context_names->second.find(*program);
    if (names == context_names->second.end()) return "";
    const auto name = names->second.find(static_cast<int32_t>(location));
    return name == names->second.end() ? "" : name->second.c_str();
}
#endif

struct GLCapabilities {
    EGLContext context = EGL_NO_CONTEXT;
    int major = 0;
    const char* extensions = nullptr;
};
static thread_local GLCapabilities s_capabilities;

static const GLCapabilities& CurrentCapabilities() {
    const EGLContext context = eglGetCurrentContext();
    if (context != s_capabilities.context) {
        s_capabilities = {context, 0, nullptr};
        if (context != EGL_NO_CONTEXT) {
            const char* version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
            if (version && strncmp(version, "OpenGL ES", 9) == 0) {
                version += 9;
                while (*version && (*version < '0' || *version > '9')) ++version;
                if (*version) s_capabilities.major = *version - '0';
            }
            s_capabilities.extensions = reinterpret_cast<const char*>(glGetString(GL_EXTENSIONS));
            __android_log_print(ANDROID_LOG_INFO, "Arm32Bridge_GL",
                "[GL-CAPS] context=%p version=%d extensions=%s", context,
                s_capabilities.major, s_capabilities.extensions ? s_capabilities.extensions : "");
        }
    }
    return s_capabilities;
}

static bool HasGLExtension(const char* name) {
    const char* extensions = CurrentCapabilities().extensions;
    if (!extensions) return false;
    const size_t length = strlen(name);
    const char* match = extensions;
    while ((match = strstr(match, name))) {
        if ((match == extensions || match[-1] == ' ') &&
            (match[length] == '\0' || match[length] == ' ')) return true;
        match += length;
    }
    return false;
}

static bool GLProcSupported(const char* name) {
    const int major = CurrentCapabilities().major;
    if (major < 2) return false;
    if (strcmp(name, "glMapBufferRangeEXT") == 0 ||
        strcmp(name, "glFlushMappedBufferRangeEXT") == 0)
        return major >= 3 || HasGLExtension("GL_EXT_map_buffer_range");
    if (strcmp(name, "glMapBufferOES") == 0 || strcmp(name, "glUnmapBufferOES") == 0 ||
        strcmp(name, "glGetBufferPointervOES") == 0)
        return major >= 3 || HasGLExtension("GL_OES_mapbuffer");
    if (strcmp(name, "glRenderbufferStorageMultisample") == 0 ||
        strcmp(name, "glBlitFramebuffer") == 0) return major >= 3;
    static const struct { const char* proc; const char* extension; } extensions[] = {
        {"glRenderbufferStorageMultisampleEXT", "GL_EXT_multisampled_render_to_texture"},
        {"glFramebufferTexture2DMultisampleEXT", "GL_EXT_multisampled_render_to_texture"},
        {"glRenderbufferStorageMultisampleIMG", "GL_IMG_multisampled_render_to_texture"},
        {"glFramebufferTexture2DMultisampleIMG", "GL_IMG_multisampled_render_to_texture"},
        {"glRenderbufferStorageMultisampleANGLE", "GL_ANGLE_framebuffer_multisample"},
        {"glBlitFramebufferANGLE", "GL_ANGLE_framebuffer_blit"},
        {"glRenderbufferStorageMultisampleAPPLE", "GL_APPLE_framebuffer_multisample"},
        {"glResolveMultisampleFramebufferAPPLE", "GL_APPLE_framebuffer_multisample"},
        {"glBlitFramebufferEXT", "GL_EXT_framebuffer_blit"},
        {"glDiscardFramebufferEXT", "GL_EXT_discard_framebuffer"},
        {"glDrawBuffersEXT", "GL_EXT_draw_buffers"},
        {"glDrawBuffersNV", "GL_NV_draw_buffers"},
        {"glDrawBuffersARB", "GL_ARB_draw_buffers"},
        {"glReadBufferNV", "GL_NV_read_buffer"},
        {"glTexStorage2DEXT", "GL_EXT_texture_storage"},
        {"glTexStorage3DEXT", "GL_EXT_texture_storage"},
        {"glGenQueriesEXT", "GL_EXT_occlusion_query_boolean"},
        {"glDeleteQueriesEXT", "GL_EXT_occlusion_query_boolean"},
        {"glBeginQueryEXT", "GL_EXT_occlusion_query_boolean"},
        {"glEndQueryEXT", "GL_EXT_occlusion_query_boolean"},
        {"glGetQueryObjectuivEXT", "GL_EXT_occlusion_query_boolean"},
        {"glTexImage3DOES", "GL_OES_texture_3D"},
        {"glTexSubImage3DOES", "GL_OES_texture_3D"},
        {"glCompressedTexImage3DOES", "GL_OES_texture_3D"},
        {"glCompressedTexSubImage3DOES", "GL_OES_texture_3D"},
    };
    for (const auto& extension : extensions)
        if (strcmp(name, extension.proc) == 0) return HasGLExtension(extension.extension);
    return true;
}

static GLBindings& CurrentBindings() {
    const EGLContext context = eglGetCurrentContext();
    if (context != s_bindings.context) {
        s_bindings = {context, 0, 0, 0};
        if (context != EGL_NO_CONTEXT) {
            glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &s_bindings.array_buffer);
            glGetIntegerv(GL_ELEMENT_ARRAY_BUFFER_BINDING, &s_bindings.element_buffer);
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &s_bindings.draw_framebuffer);
        }
    }
    return s_bindings;
}

// UI scaling, the virtual-resolution way: tell the guest the screen is
// s_virtual{Width,Height} and stretch the result here. The guest sizes its viewport
// in those units while the real default framebuffer is still the surface size, so
// the window-system framebuffer -- and only that one -- gets mapped back. Offscreen
// targets are allocated in the guest's own units and must not be touched, which is
// what the draw framebuffer check is for.
// Leave s_virtualWidth/Height at 0 to disable the whole path.
static void ScaleViewportToSurface(GLint& x, GLint& y, GLsizei& w, GLsizei& h) {
    if (CurrentBindings().draw_framebuffer != 0) return;
    const uint32_t vw = ThunkManager::s_virtualWidth, vh = ThunkManager::s_virtualHeight;
    const uint32_t rw = ThunkManager::s_screenWidth, rh = ThunkManager::s_screenHeight;
    if (!vw || !vh || !rw || !rh || (vw == rw && vh == rh)) return;
    x = static_cast<GLint>((float)x * rw / vw);
    w = static_cast<GLsizei>((float)w * rw / vw);
    y = static_cast<GLint>((float)y * rh / vh);
    h = static_cast<GLsizei>((float)h * rh / vh);
}
#define LOG_TAG "Arm32Bridge_GL"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static uint32_t g_draw_calls = 0;

// A native GL mapping is a 64-bit process pointer. The ARM guest can only use
// addresses in its own 32-bit arena, so keep the driver mapping alive and hand
// it a guest allocation containing the buffer's current bytes. On unmap copy
// its edits back before releasing the driver mapping. GL calls for one context
// are serialized on its owner thread by EGL; a thread-local record also keeps
// independent contexts from aliasing one another here.
struct GuestBufferMap {
    EGLContext context;
    GLint binding;
    uint32_t guest_address;
    GLintptr offset;
    GLsizeiptr size;
    GLbitfield access;
    void* driver_address;
};
static thread_local std::vector<GuestBufferMap> s_guest_buffer_maps;
// ES2 OES mappings are write-only; preserve their unwritten bytes from uploads.
static thread_local std::unordered_map<EGLContext,
    std::unordered_map<GLint, std::vector<uint8_t>>> s_buffer_shadows;

#if MC4_ENABLE_NATIVE_LOGGING
// The verified CustomSceneManager sky-pass call brackets these observations.
// Restore texture-unit selection after querying samplers. GLES3.1-only level
// queries are version gated; never consume GL error state.
struct SkyBufferCapture {
    EGLContext context;
    GLuint buffer;
    uintptr_t offset;
    size_t total;
    uint32_t hash;
};
struct SkyPassObservation {
    bool active = false;
    uint32_t passes = 0;
    uint32_t draws = 0;
    uint32_t samples = 0;
    std::vector<std::pair<EGLContext, GLuint>> programs;
    std::vector<SkyBufferCapture> buffers;
    bool pixel_frame_requested = false;
    bool pixel_frame_pending = false;
    EGLContext pixel_context = EGL_NO_CONTEXT;
};
static thread_local SkyPassObservation s_sky_observation;

struct SkyTextureDump {
    EGLContext context;
    GLint level;
};
static thread_local std::vector<SkyTextureDump> s_sky_texture_dumps;
static thread_local uint32_t s_sky_dump_repeats = 0;
static thread_local uint32_t s_sky_pixel_clear_observations = 0;

static void LogSkyRasterState(const char* phase, GLbitfield clear_mask, uint32_t lr) {
    GLint framebuffer = 0, viewport[4] = {}, scissor[4] = {}, color_mask[4] = {};
    GLint depth_mask = 0, stencil_clear = 0, stencil[7] = {}, back[7] = {};
    GLfloat depth_clear = 0, color_clear[4] = {}, factor = 0, units = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    glGetIntegerv(GL_VIEWPORT, viewport);
    glGetIntegerv(GL_SCISSOR_BOX, scissor);
    glGetIntegerv(GL_COLOR_WRITEMASK, color_mask);
    glGetIntegerv(GL_DEPTH_WRITEMASK, &depth_mask);
    glGetIntegerv(GL_STENCIL_CLEAR_VALUE, &stencil_clear);
    glGetFloatv(GL_DEPTH_CLEAR_VALUE, &depth_clear);
    glGetFloatv(GL_COLOR_CLEAR_VALUE, color_clear);
    glGetFloatv(GL_POLYGON_OFFSET_FACTOR, &factor);
    glGetFloatv(GL_POLYGON_OFFSET_UNITS, &units);
    const GLenum front_names[] = {GL_STENCIL_FUNC, GL_STENCIL_REF, GL_STENCIL_VALUE_MASK,
        GL_STENCIL_WRITEMASK, GL_STENCIL_FAIL, GL_STENCIL_PASS_DEPTH_FAIL, GL_STENCIL_PASS_DEPTH_PASS};
    const GLenum back_names[] = {GL_STENCIL_BACK_FUNC, GL_STENCIL_BACK_REF, GL_STENCIL_BACK_VALUE_MASK,
        GL_STENCIL_BACK_WRITEMASK, GL_STENCIL_BACK_FAIL, GL_STENCIL_BACK_PASS_DEPTH_FAIL, GL_STENCIL_BACK_PASS_DEPTH_PASS};
    for (unsigned i = 0; i < 7; ++i) {
        glGetIntegerv(front_names[i], &stencil[i]);
        glGetIntegerv(back_names[i], &back[i]);
    }
    LOGI("[GLSKY-RASTER] phase=%s draw=3000 fbo=%d clear=%04X lr=%08X"
         " viewport=%d,%d,%d,%d scissor=%d/%d,%d,%d,%d color_mask=%d,%d,%d,%d depth_mask=%d"
         " clear_depth=%.9g clear_color=%.6g,%.6g,%.6g,%.6g clear_stencil=%d"
         " stencil=%d/%04X,%d,%08X,%08X,%04X,%04X,%04X"
         " back=%04X,%d,%08X,%08X,%04X,%04X,%04X poly=%d/%.9g/%.9g",
         phase, framebuffer, clear_mask, lr, viewport[0], viewport[1], viewport[2], viewport[3],
         glIsEnabled(GL_SCISSOR_TEST), scissor[0], scissor[1], scissor[2], scissor[3],
         color_mask[0], color_mask[1], color_mask[2], color_mask[3], depth_mask, depth_clear,
         color_clear[0], color_clear[1], color_clear[2], color_clear[3], stencil_clear,
         glIsEnabled(GL_STENCIL_TEST), stencil[0], stencil[1], stencil[2], stencil[3], stencil[4], stencil[5], stencil[6],
         back[0], back[1], back[2], back[3], back[4], back[5], back[6],
         glIsEnabled(GL_POLYGON_OFFSET_FILL), factor, units);
    if (framebuffer == 1) {
        for (GLenum attachment : {GL_COLOR_ATTACHMENT0, GL_DEPTH_ATTACHMENT, GL_STENCIL_ATTACHMENT}) {
            GLint type = 0, name = 0, bits = -1;
            glGetFramebufferAttachmentParameteriv(GL_FRAMEBUFFER, attachment,
                GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE, &type);
            if (type != GL_NONE) {
                glGetFramebufferAttachmentParameteriv(GL_FRAMEBUFFER, attachment,
                    GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME, &name);
                if (CurrentCapabilities().major >= 3 && attachment != GL_COLOR_ATTACHMENT0)
                    glGetFramebufferAttachmentParameteriv(GL_FRAMEBUFFER, attachment,
                        attachment == GL_DEPTH_ATTACHMENT ? GL_FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE :
                        GL_FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE, &bits);
            }
            LOGI("[GLSKY-ATTACHMENT] phase=%s draw=3000 fbo=1 attachment=%04X type=%04X name=%d bits=%d",
                 phase, attachment, type, name, bits);
        }
    }
}

static void ObserveSelectedSkyClear(GLbitfield mask, uint32_t lr) {
    const auto& observation = s_sky_observation;
    if (observation.draws != 2999 || observation.pixel_frame_requested ||
        s_sky_pixel_clear_observations >= 4) return;
    GLint framebuffer = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    if (framebuffer == 1) {
        ++s_sky_pixel_clear_observations;
        LogSkyRasterState("preceding-clear", mask, lr);
    }
}

// One frame only: two bounded RGBA bands before/after the real sky draw and at
// its swap. Validate read-FBO/packing/sample/read-format state; change none of it.
static void CaptureSkyPixels(const char* phase, GLint expected_framebuffer) {
    GLint framebuffer = 0, viewport[4] = {}, samples = 0, alignment = 0;
    GLint read_format = 0, read_type = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    glGetIntegerv(GL_VIEWPORT, viewport);
    glGetIntegerv(GL_SAMPLES, &samples);
    glGetIntegerv(GL_PACK_ALIGNMENT, &alignment);
    if (framebuffer != expected_framebuffer || viewport[0] < 0 || viewport[1] < 0 ||
        viewport[2] < 2 || viewport[3] < 2 || viewport[2] > 8192 || viewport[3] > 8192 ||
        (framebuffer != 0 && samples != 0) ||
        (alignment != 1 && alignment != 2 && alignment != 4 && alignment != 8) ||
        glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        LOGI("[GLSKY-PIXELS] skip phase=%s fbo=%d expected=%d viewport=%d,%d,%d,%d samples=%d pack=%d read=%04X/%04X",
             phase, framebuffer, expected_framebuffer, viewport[0], viewport[1], viewport[2], viewport[3],
             samples, alignment, read_format, read_type);
        return;
    }
    if (CurrentCapabilities().major >= 3) {
        GLint read_framebuffer = 0, read_buffer = GL_NONE, pack_buffer = 0;
        GLint row_length = 0, skip_rows = 0, skip_pixels = 0;
        glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &read_framebuffer);
        glGetIntegerv(GL_READ_BUFFER, &read_buffer);
        glGetIntegerv(GL_PIXEL_PACK_BUFFER_BINDING, &pack_buffer);
        glGetIntegerv(GL_PACK_ROW_LENGTH, &row_length);
        glGetIntegerv(GL_PACK_SKIP_ROWS, &skip_rows);
        glGetIntegerv(GL_PACK_SKIP_PIXELS, &skip_pixels);
        if (read_framebuffer != framebuffer || read_buffer != (framebuffer ? GL_COLOR_ATTACHMENT0 : GL_BACK) ||
            pack_buffer || row_length || skip_rows || skip_pixels) {
            LOGI("[GLSKY-PIXELS] skip phase=%s read_fbo=%d draw_fbo=%d read_buffer=%04X pbo=%d row=%d skip=%d/%d",
                 phase, read_framebuffer, framebuffer, read_buffer, pack_buffer, row_length, skip_rows, skip_pixels);
            return;
        }
    }
    glGetIntegerv(GL_IMPLEMENTATION_COLOR_READ_FORMAT, &read_format);
    glGetIntegerv(GL_IMPLEMENTATION_COLOR_READ_TYPE, &read_type);
    if ((read_format != GL_RGBA && read_format != GL_BGRA_EXT) || read_type != GL_UNSIGNED_BYTE) {
        LOGI("[GLSKY-PIXELS] skip phase=%s implementation read=%04X/%04X", phase, read_format, read_type);
        return;
    }
    const GLsizei width = std::min(viewport[2], GLint{2048}) & ~1;
    const GLsizei height = std::min(viewport[3] / 2, GLint{256});
    const GLint x = viewport[0] + (viewport[2] - width) / 2;
    const auto context_id = static_cast<unsigned long long>((uintptr_t)eglGetCurrentContext());
    for (unsigned band = 0; band < 2; ++band) {
        const GLint y = viewport[1] + viewport[3] * (band ? 3 : 1) / 4 - height / 2;
        std::vector<uint8_t> pixels(static_cast<size_t>(width) * height * 4);
        glReadPixels(x, y, width, height, static_cast<GLenum>(read_format), GL_UNSIGNED_BYTE, pixels.data());
        if (read_format == GL_BGRA_EXT)
            for (size_t i = 0; i < pixels.size(); i += 4) std::swap(pixels[i], pixels[i + 2]);
        char filename[256] = {}, metadata[256] = {};
        snprintf(filename, sizeof(filename), "/sdcard/Android/data/com.gameloft.android.ANMP.GloftM4HM/files/"
            "codex-mc4-20261015-sky-d3000-%s-b%u-c%016llx.rgba", phase, band, context_id);
        snprintf(metadata, sizeof(metadata), "/sdcard/Android/data/com.gameloft.android.ANMP.GloftM4HM/files/"
            "codex-mc4-20261015-sky-d3000-%s-b%u-c%016llx.json", phase, band, context_id);
        FILE* output = fopen(filename, "wb");
        if (!output) { LOGE("[GLSKY-PIXELS] cannot open '%s'", filename); continue; }
        const size_t written = fwrite(pixels.data(), 1, pixels.size(), output);
        const int closed = fclose(output);
        uint32_t hash = 2166136261u;
        for (uint8_t byte : pixels) hash = (hash ^ byte) * 16777619u;
        FILE* description = fopen(metadata, "wb");
        if (!description) { LOGE("[GLSKY-PIXELS] cannot open '%s'", metadata); continue; }
        fprintf(description, "{\"context\":\"0x%016llx\",\"draw\":3000,\"phase\":\"%s\",\"band\":%u,"
            "\"framebuffer\":%d,\"viewport\":[%d,%d,%d,%d],\"roi\":[%d,%d,%d,%d],"
            "\"native_format\":%d,\"bytes\":%zu,\"written\":%zu,\"close\":%d,\"fnv1a\":\"%08X\"}\n",
            context_id, phase, band, framebuffer, viewport[0], viewport[1], viewport[2], viewport[3],
            x, y, width, height, read_format, pixels.size(), written, closed, hash);
        fclose(description);
        LOGI("[GLSKY-PIXELS] phase=%s band=%u context=0x%016llx fbo=%d viewport=%dx%d roi=%d,%d,%d,%d"
             " bytes=%zu written=%zu close=%d hash=%08X file='%s'", phase, band, context_id, framebuffer,
             viewport[2], viewport[3], x, y, width, height, pixels.size(), written, closed, hash, filename);
    }
}

// Temporary selected-resource diagnostic: texture 249 is the ETC1 diffuse map
// observed on the original M6 skydome route. Capture its actual upload bytes,
// without reading driver texture storage or changing any GL state.
static void DumpSelectedSkyTexture(DynarmicHost& host, GLenum target, GLint level,
                                   GLenum format, GLsizei width, GLsizei height,
                                   GLsizei image_size, uint32_t address, uint32_t lr) {
    if (target != GL_TEXTURE_2D || format != GL_ETC1_RGB8_OES || level < 0 || level > 12 ||
        width <= 0 || height <= 0 || image_size <= 0 || image_size > 3 * 1024 * 1024) return;
    const EGLContext context = eglGetCurrentContext();
    if (context == EGL_NO_CONTEXT) return;
    GLint texture = 0;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &texture);
    if (texture != 249) return;
    auto& dumps = s_sky_texture_dumps;
    for (const auto& previous : dumps) {
        if (previous.context == context && previous.level == level) {
            if (++s_sky_dump_repeats <= 16)
                LOGI("[GLSKY-TEXDUMP] repeated upload context=%p texture=249 level=%d size=%d",
                     context, level, image_size);
            return;
        }
    }
    if (dumps.size() >= 26) return;
    const auto* bytes = static_cast<const uint8_t*>(GuestSpan(host.GetGuestMemoryBase(),
        host.GetGuestMemorySize(), address, static_cast<size_t>(image_size)));
    if (!bytes) {
        LOGE("[GLSKY-TEXDUMP] invalid guest range context=%p level=%d address=%08X bytes=%d",
             context, level, address, image_size);
        return;
    }
    dumps.push_back({context, level});
    char filename[256] = {}, metadata[256] = {};
    const auto context_id = static_cast<unsigned long long>((uintptr_t)context);
    snprintf(filename, sizeof(filename), "/sdcard/Android/data/com.gameloft.android.ANMP.GloftM4HM/files/"
        "codex-mc4-20261015-sky-t249-l%d-c%016llx.bin", level, context_id);
    snprintf(metadata, sizeof(metadata), "/sdcard/Android/data/com.gameloft.android.ANMP.GloftM4HM/files/"
        "codex-mc4-20261015-sky-t249-l%d-c%016llx.json", level, context_id);
    FILE* output = fopen(filename, "wb");
    if (!output) {
        LOGE("[GLSKY-TEXDUMP] cannot open '%s'", filename);
        return;
    }
    const size_t written = fwrite(bytes, 1, static_cast<size_t>(image_size), output);
    const int closed = fclose(output);
    if (written != static_cast<size_t>(image_size) || closed != 0) {
        LOGE("[GLSKY-TEXDUMP] incomplete '%s' written=%zu expected=%d close=%d",
             filename, written, image_size, closed);
        return;
    }
    uint32_t hash = 2166136261u;
    for (GLsizei i = 0; i < image_size; ++i) hash = (hash ^ bytes[i]) * 16777619u;
    FILE* description = fopen(metadata, "wb");
    if (!description) {
        LOGE("[GLSKY-TEXDUMP] cannot open metadata '%s'", metadata);
        return;
    }
    const int described = fprintf(description,
        "{\"context\":\"0x%016llx\",\"texture\":249,\"target\":%u,\"level\":%d,"
        "\"format\":%u,\"width\":%d,\"height\":%d,\"image_size\":%d,"
        "\"fnv1a\":\"%08X\",\"guest_address\":\"%08X\",\"guest_lr\":\"%08X\"}\n",
        context_id, target, level, format, width, height, image_size, hash, address, lr);
    const int metadata_closed = fclose(description);
    LOGI("[GLSKY-TEXDUMP] context=%p texture=249 level=%d size=%dx%d format=%04X bytes=%d"
         " hash=%08X metadata_ok=%d file='%s'", context, level, width, height, format,
         image_size, hash, described > 0 && metadata_closed == 0, filename);
}

void GuestGLSkyPass(bool enter) {
    s_sky_observation.active = enter;
    if (enter) ++s_sky_observation.passes;
}

static const uint8_t* SkyDataSpan(DynarmicHost& host, EGLContext context,
                                 GLuint buffer, uintptr_t address, size_t length) {
    if (buffer) {
        const auto shadows = s_buffer_shadows.find(context);
        if (shadows == s_buffer_shadows.end()) return nullptr;
        const auto bytes = shadows->second.find(static_cast<GLint>(buffer));
        if (bytes == shadows->second.end() || address > bytes->second.size() ||
            length > bytes->second.size() - address) return nullptr;
        return bytes->second.data() + address;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
    if (address < base || address - base > UINT32_MAX) return nullptr;
    return static_cast<const uint8_t*>(GuestSpan(host.GetGuestMemoryBase(),
        host.GetGuestMemorySize(), static_cast<uint32_t>(address - base), length));
}

static void LogSkyBuffer(uint32_t draw, const char* role, EGLContext context,
                         GLuint buffer, uintptr_t offset, const uint8_t* data, size_t total) {
    if (!data || !total) return;
    const size_t captured = std::min(total, size_t{16384});
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < captured; ++i) hash = (hash ^ data[i]) * 16777619u;
    auto& buffers = s_sky_observation.buffers;
    for (const auto& previous : buffers)
        if (previous.context == context && previous.buffer == buffer &&
            previous.offset == offset && previous.total == total && previous.hash == hash) return;
    if (buffers.size() >= 4) return;
    buffers.push_back({context, buffer, offset, total, hash});
    for (size_t chunk = 0; chunk < captured; chunk += 384) {
        const size_t length = std::min(captured - chunk, size_t{384});
        char hex[769] = {};
        static constexpr char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < length; ++i) {
            hex[i * 2] = digits[data[chunk + i] >> 4];
            hex[i * 2 + 1] = digits[data[chunk + i] & 15];
        }
        LOGI("[GLSKY-MESH] draw=%u role=%s context=%p buffer=%u base=%zu total=%zu"
             " captured=%zu hash=%08X offset=%zu hex=%s", draw, role, context, buffer,
             static_cast<size_t>(offset), total, captured, hash, chunk, hex);
    }
}

static void CompareSelectedSkyGpuBuffers() {
    if (CurrentCapabilities().major < 3) {
        LOGI("[GLSKY-GPU] skip: native core READ mapping requires GLES3");
        return;
    }
    const EGLContext context = eglGetCurrentContext();
    for (GLenum target : {GL_ELEMENT_ARRAY_BUFFER, GL_ARRAY_BUFFER}) {
        const GLuint expected = target == GL_ELEMENT_ARRAY_BUFFER ? 587 : 588;
        GLint binding = 0, size = 0, mapped = 0;
        glGetIntegerv(target == GL_ELEMENT_ARRAY_BUFFER ? GL_ELEMENT_ARRAY_BUFFER_BINDING :
            GL_ARRAY_BUFFER_BINDING, &binding);
        if (binding != static_cast<GLint>(expected)) {
            LOGI("[GLSKY-GPU] skip target=%04X actual=%d expected=%u", target, binding, expected);
            continue;
        }
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &size);
        glGetBufferParameteriv(target, GL_BUFFER_MAPPED, &mapped);
        if (mapped || size <= 0 || size > 16384) {
            LOGI("[GLSKY-GPU] skip target=%04X buffer=%d size=%d mapped=%d", target, binding, size, mapped);
            continue;
        }
        // This is a native GLES3 READ mapping, never the guest/OES write-only adapter.
        std::vector<uint8_t> copy(static_cast<size_t>(size));
        const void* source = glMapBufferRange(target, 0, size, GL_MAP_READ_BIT);
        if (!source) {
            LOGI("[GLSKY-GPU] native READ map failed target=%04X buffer=%d size=%d", target, binding, size);
            continue;
        }
        memcpy(copy.data(), source, copy.size());
        const GLboolean unmapped = glUnmapBuffer(target);
        uint32_t hash = 2166136261u;
        for (uint8_t byte : copy) hash = (hash ^ byte) * 16777619u;
        bool equal = false;
        size_t shadow_size = 0;
        const auto shadows = s_buffer_shadows.find(context);
        if (shadows != s_buffer_shadows.end()) {
            const auto shadow = shadows->second.find(binding);
            if (shadow != shadows->second.end()) {
                shadow_size = shadow->second.size();
                equal = shadow_size == copy.size() && memcmp(copy.data(), shadow->second.data(), copy.size()) == 0;
            }
        }
        LOGI("[GLSKY-GPU] draw=3000 context=%p target=%04X buffer=%d bytes=%d hash=%08X"
             " shadow_bytes=%zu equal=%d unmap=%u", context, target, binding, size, hash, shadow_size, equal, unmapped);
        if (!equal) LogSkyBuffer(3000, target == GL_ELEMENT_ARRAY_BUFFER ? "gpuindex" : "gpuvertex",
            context, expected, 0, copy.data(), copy.size());
    }
}

static void LogSkyTexture2D(uint32_t draw, GLuint program, const char* sampler, GLint unit) {
    GLint original = GL_TEXTURE0, maximum = 0;
    glGetIntegerv(GL_ACTIVE_TEXTURE, &original);
    glGetIntegerv(GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS, &maximum);
    if (unit < 0 || unit >= maximum) return;
    struct RestoreTextureUnit {
        GLint original;
        ~RestoreTextureUnit() { glActiveTexture(static_cast<GLenum>(original)); }
    } restore{original};
    glActiveTexture(GL_TEXTURE0 + static_cast<GLenum>(unit));
    GLint texture = 0;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &texture);
    if (!texture) {
        LOGI("[GLSKY-TEXTURE] draw=%u program=%u sampler='%s' unit=%d texture=0", draw, program, sampler, unit);
        return;
    }
    GLint wrap_s = 0, wrap_t = 0, minimum = 0, magnification = 0;
    glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, &wrap_s);
    glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, &wrap_t);
    glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, &minimum);
    glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, &magnification);
    GLint width = -1, height = -1, format = -1;
    // The level query is GLES3.1, not GLES3.0. A non-null proc alone is insufficient.
    const auto* version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
    if (version) while (*version && (*version < '0' || *version > '9')) ++version;
    const bool level_queries = version && (version[0] > '3' ||
        (version[0] == '3' && version[1] == '.' && version[2] >= '1' && version[2] <= '9'));
    if (level_queries) {
        using GetLevel = void (*)(GLenum, GLint, GLenum, GLint*);
        const auto get_level = reinterpret_cast<GetLevel>(eglGetProcAddress("glGetTexLevelParameteriv"));
        if (get_level) {
            get_level(GL_TEXTURE_2D, 0, GL_TEXTURE_WIDTH, &width);
            get_level(GL_TEXTURE_2D, 0, GL_TEXTURE_HEIGHT, &height);
            get_level(GL_TEXTURE_2D, 0, GL_TEXTURE_INTERNAL_FORMAT, &format);
        }
    }
    LOGI("[GLSKY-TEXTURE] draw=%u program=%u sampler='%s' unit=%d texture=%d"
         " size=%dx%d format=%04X wrap=%04X/%04X filter=%04X/%04X",
         draw, program, sampler, unit, texture, width, height, format,
         wrap_s, wrap_t, minimum, magnification);
}

static void LogSkyProgram(GLuint program) {
    const auto key = std::make_pair(eglGetCurrentContext(), program);
    auto& programs = s_sky_observation.programs;
    if (std::find(programs.begin(), programs.end(), key) != programs.end() ||
        programs.size() >= 2) return;
    programs.push_back(key);
    GLuint shaders[2] = {};
    GLsizei count = 0;
    glGetAttachedShaders(program, 2, &count, shaders);
    for (GLsizei i = 0; i < count; ++i) {
        GLint length = 0, type = 0;
        glGetShaderiv(shaders[i], GL_SHADER_SOURCE_LENGTH, &length);
        glGetShaderiv(shaders[i], GL_SHADER_TYPE, &type);
        if (length <= 1) continue;
        std::vector<GLchar> source(static_cast<size_t>(std::min(length, 32769)));
        GLsizei written = 0;
        glGetShaderSource(shaders[i], static_cast<GLsizei>(source.size()), &written, source.data());
        // Hex preserves newlines and exact source bytes in bounded logcat records.
        for (GLsizei offset = 0; offset < written; offset += 384) {
            const GLsizei bytes = std::min(written - offset, GLsizei{384});
            char hex[769] = {};
            static constexpr char digits[] = "0123456789abcdef";
            for (GLsizei n = 0; n < bytes; ++n) {
                const auto byte = static_cast<uint8_t>(source[offset + n]);
                hex[n * 2] = digits[byte >> 4];
                hex[n * 2 + 1] = digits[byte & 15];
            }
            LOGI("[GLSKY-SOURCE] context=%p program=%u shader=%u type=%04X"
                 " total=%d captured=%d offset=%d hex=%s", key.first,
                 program, shaders[i], type, length - 1, written, offset, hex);
        }
    }
}

static unsigned SkyUniformComponents(GLenum type, bool& floating) {
    floating = true;
    switch (type) {
    case GL_FLOAT: return 1;
    case GL_FLOAT_VEC2: return 2;
    case GL_FLOAT_VEC3: return 3;
    case GL_FLOAT_VEC4: return 4;
    case GL_FLOAT_MAT2: return 4;
    case GL_FLOAT_MAT3: return 9;
    case GL_FLOAT_MAT4: return 16;
    case GL_FLOAT_MAT2x3: case GL_FLOAT_MAT3x2: return 6;
    case GL_FLOAT_MAT2x4: case GL_FLOAT_MAT4x2: return 8;
    case GL_FLOAT_MAT3x4: case GL_FLOAT_MAT4x3: return 12;
    default: floating = false; break;
    }
    switch (type) {
    case GL_INT_VEC2: case GL_BOOL_VEC2: case GL_UNSIGNED_INT_VEC2: return 2;
    case GL_INT_VEC3: case GL_BOOL_VEC3: case GL_UNSIGNED_INT_VEC3: return 3;
    case GL_INT_VEC4: case GL_BOOL_VEC4: case GL_UNSIGNED_INT_VEC4: return 4;
    default: return 1;
    }
}

static void LogSkyGuestState(DynarmicHost& host, uint32_t draw, uint32_t lr,
                             uint32_t driver_address) {
    // Original drawImpl keeps its driver in r8 at BL 0x411CA364, and
    // drawPrimitives preserves r8 through glDrawElements at 0x411C9BC8.
    // redrawImpl can use r8 for an index offset instead: validate the complete
    // candidate span and its original-image vtable before observing fields.
    if (lr != 0x411C9BCCu || driver_address < 0x10000u || (driver_address & 3u)) return;
    const auto* driver = static_cast<const uint8_t*>(GuestSpan(host.GetGuestMemoryBase(),
        host.GetGuestMemorySize(), driver_address, 0x2F8));
    if (!driver) return;
    uint32_t vtable = 0;
    memcpy(&vtable, driver, sizeof(vtable));
    if (vtable < 0x40000000u || vtable >= 0x43000000u) return;
    uint32_t desired[8] = {}, cached[8] = {}, depth[2] = {};
    memcpy(desired, driver + 4, sizeof(desired));
    memcpy(cached, driver + 0x2D8, sizeof(cached));
    memcpy(depth, driver + 0x2C, sizeof(depth));
    LOGI("[GLSKY-GUEST] draw=%u r8=%08X vtable=%08X desired=%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X"
         " cached=%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X depth=%08X,%08X",
         draw, driver_address, vtable, desired[0], desired[1], desired[2], desired[3],
         desired[4], desired[5], desired[6], desired[7], cached[0], cached[1], cached[2],
         cached[3], cached[4], cached[5], cached[6], cached[7], depth[0], depth[1]);
}

static void LogSkyDraw(DynarmicHost& host, GLenum mode, GLsizei count,
                       GLenum index_type, const void* indices, GLint first, uint32_t lr,
                       uint32_t driver_address = 0) {
    auto& observation = s_sky_observation;
    if (!observation.active || observation.samples >= 32) return;
    const uint32_t draw = ++observation.draws;
    if (draw > 8 && draw % 1000 != 0) return;
    ++observation.samples;
    const EGLContext context = eglGetCurrentContext();
    GLint program = 0, linked = 0, element = 0, depth_mask = 0, depth_function = 0;
    GLint source_rgb = 0, destination_rgb = 0;
    glGetIntegerv(GL_CURRENT_PROGRAM, &program);
    if (!program) return;
    glGetProgramiv(static_cast<GLuint>(program), GL_LINK_STATUS, &linked);
    if (!linked) return;
    glGetIntegerv(GL_ELEMENT_ARRAY_BUFFER_BINDING, &element);
    glGetIntegerv(GL_DEPTH_WRITEMASK, &depth_mask);
    glGetIntegerv(GL_DEPTH_FUNC, &depth_function);
    glGetIntegerv(GL_BLEND_SRC_RGB, &source_rgb);
    glGetIntegerv(GL_BLEND_DST_RGB, &destination_rgb);
    GLint framebuffer = 0, cull_mode = 0, front_face = 0;
    GLfloat depth_range[2] = {};
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    glGetIntegerv(GL_CULL_FACE_MODE, &cull_mode);
    glGetIntegerv(GL_FRONT_FACE, &front_face);
    glGetFloatv(GL_DEPTH_RANGE, depth_range);
    LOGI("[GLSKY-DRAW] #%u sample=%u pass=%u context=%p program=%d mode=%04X"
         " count=%d first=%d index_type=%04X indices=%p ebo=%d"
         " depth=%d/%04X mask=%d blend=%d/%04X/%04X cull=%d lr=%08X",
         draw, observation.samples, observation.passes, context, program, mode,
         count, first, index_type, indices, element, glIsEnabled(GL_DEPTH_TEST),
         depth_function, depth_mask, glIsEnabled(GL_BLEND), source_rgb,
         destination_rgb, glIsEnabled(GL_CULL_FACE), lr);
    LOGI("[GLSKY-STATE] draw=%u framebuffer=%d depth_range=%.9g/%.9g cull=%04X front=%04X",
         draw, framebuffer, depth_range[0], depth_range[1], cull_mode, front_face);
    LogSkyGuestState(host, draw, lr, driver_address);
    LogSkyProgram(static_cast<GLuint>(program));
    if (index_type && count > 0) {
        const size_t index_bytes = index_type == GL_UNSIGNED_BYTE ? 1 :
            index_type == GL_UNSIGNED_SHORT ? 2 : 4;
        const size_t total = static_cast<size_t>(count) * index_bytes;
        const size_t bytes = std::min(total, size_t{16384});
        const auto* data = SkyDataSpan(host, context, static_cast<GLuint>(element),
            reinterpret_cast<uintptr_t>(indices), bytes);
        uint32_t words[8] = {};
        if (data) memcpy(words, data, std::min(bytes, sizeof(words)));
        LOGI("[GLSKY-INDICES] draw=%u available=%d bytes=%zu words=%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X",
             draw, data != nullptr, bytes, words[0], words[1], words[2], words[3],
             words[4], words[5], words[6], words[7]);
        LogSkyBuffer(draw, "index", context, static_cast<GLuint>(element),
            reinterpret_cast<uintptr_t>(indices), data, total);
    }
    GLint attributes = 0, maximum_attributes = 0;
    glGetIntegerv(GL_MAX_VERTEX_ATTRIBS, &maximum_attributes);
    glGetProgramiv(static_cast<GLuint>(program), GL_ACTIVE_ATTRIBUTES, &attributes);
    for (GLuint active = 0; active < static_cast<GLuint>(std::min(attributes, 16)); ++active) {
        GLchar name[128] = {};
        GLsizei length = 0;
        GLint array = 0;
        GLenum attribute_type = 0;
        glGetActiveAttrib(static_cast<GLuint>(program), active, sizeof(name), &length, &array, &attribute_type, name);
        if (length >= static_cast<GLsizei>(sizeof(name) - 1)) continue;
        const GLint location = glGetAttribLocation(static_cast<GLuint>(program), name);
        if (location < 0 || location >= maximum_attributes) continue;
        const GLuint attribute = static_cast<GLuint>(location);
        GLint enabled = 0, buffer = 0, size = 0, type = 0, stride = 0, normalized = 0;
        glGetVertexAttribiv(attribute, GL_VERTEX_ATTRIB_ARRAY_ENABLED, &enabled);
        LOGI("[GLSKY-ATTRIBUTE] draw=%u name='%s' index=%u type=%04X array=%d enabled=%d",
             draw, name, attribute, attribute_type, array, enabled);
        if (!enabled) {
            GLfloat values[4] = {};
            uint32_t words[4] = {};
            glGetVertexAttribfv(attribute, GL_CURRENT_VERTEX_ATTRIB, values);
            memcpy(words, values, sizeof(words));
            LOGI("[GLSKY-CONSTANT] draw=%u name='%s' index=%u words=%08X,%08X,%08X,%08X",
                 draw, name, attribute, words[0], words[1], words[2], words[3]);
            continue;
        }
        glGetVertexAttribiv(attribute, GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING, &buffer);
        glGetVertexAttribiv(attribute, GL_VERTEX_ATTRIB_ARRAY_SIZE, &size);
        glGetVertexAttribiv(attribute, GL_VERTEX_ATTRIB_ARRAY_TYPE, &type);
        glGetVertexAttribiv(attribute, GL_VERTEX_ATTRIB_ARRAY_STRIDE, &stride);
        glGetVertexAttribiv(attribute, GL_VERTEX_ATTRIB_ARRAY_NORMALIZED, &normalized);
        void* pointer = nullptr;
        glGetVertexAttribPointerv(attribute, GL_VERTEX_ATTRIB_ARRAY_POINTER, &pointer);
        const size_t component = type == GL_FLOAT || type == GL_FIXED ? 4 :
            type == GL_SHORT || type == GL_UNSIGNED_SHORT || type == GL_HALF_FLOAT ||
            type == GL_HALF_FLOAT_OES ? 2 : 1;
        const size_t vertex_bytes = static_cast<size_t>(size) * component;
        const size_t step = stride ? static_cast<size_t>(stride) : vertex_bytes;
        LOGI("[GLSKY-ATTRIB] draw=%u index=%u buffer=%d size=%d type=%04X normalized=%d stride=%d pointer=%p",
             draw, attribute, buffer, size, type, normalized, stride, pointer);
        if (buffer) {
            const auto shadows = s_buffer_shadows.find(context);
            if (shadows != s_buffer_shadows.end()) {
                const auto bytes = shadows->second.find(buffer);
                if (bytes != shadows->second.end())
                    LogSkyBuffer(draw, "vertex", context, static_cast<GLuint>(buffer),
                        0, bytes->second.data(), bytes->second.size());
            }
        }
        for (size_t vertex = 0; vertex < 4; ++vertex) {
            const uintptr_t address = reinterpret_cast<uintptr_t>(pointer) +
                (vertex + static_cast<size_t>(std::max(first, 0))) * step;
            const auto* data = SkyDataSpan(host, context, static_cast<GLuint>(buffer),
                address, vertex_bytes);
            uint32_t words[4] = {};
            if (data) memcpy(words, data, std::min(vertex_bytes, sizeof(words)));
            LOGI("[GLSKY-VERTEX] draw=%u index=%u vertex=%zu available=%d words=%08X,%08X,%08X,%08X",
                 draw, attribute, vertex, data != nullptr, words[0], words[1], words[2], words[3]);
        }
    }
    GLint uniforms = 0;
    glGetProgramiv(static_cast<GLuint>(program), GL_ACTIVE_UNIFORMS, &uniforms);
    for (GLuint uniform = 0; uniform < static_cast<GLuint>(std::min(uniforms, 64)); ++uniform) {
        GLchar name[256] = {};
        GLsizei length = 0;
        GLint size = 0;
        GLenum type = 0;
        glGetActiveUniform(static_cast<GLuint>(program), uniform, sizeof(name), &length, &size, &type, name);
        if (length >= static_cast<GLsizei>(sizeof(name) - 1)) continue;
        const GLint location = glGetUniformLocation(static_cast<GLuint>(program), name);
        if (location < 0) continue;
        bool floating = false;
        const unsigned components = SkyUniformComponents(type, floating);
        uint32_t words[16] = {};
        if (floating) {
            GLfloat values[16] = {};
            glGetUniformfv(static_cast<GLuint>(program), location, values);
            memcpy(words, values, sizeof(words));
        } else {
            GLint values[16] = {};
            glGetUniformiv(static_cast<GLuint>(program), location, values);
            memcpy(words, values, sizeof(words));
        }
        for (unsigned offset = 0; offset < components; offset += 4)
            LOGI("[GLSKY-UNIFORM] draw=%u program=%d name='%s' location=%d type=%04X"
                 " array=%d components=%u offset=%u words=%08X,%08X,%08X,%08X",
                 draw, program, name, location, type, size, components, offset,
                 words[offset], words[offset + 1], words[offset + 2], words[offset + 3]);
        if (type == GL_SAMPLER_2D)
            LogSkyTexture2D(draw, static_cast<GLuint>(program), name, static_cast<GLint>(words[0]));
    }
}

// Sample guest staging bytes without reading a write-only driver mapping.
static void LogMappedBytes(DynarmicHost& host, const char* phase, uint32_t count,
                           GLenum target, GLint binding, uint32_t address,
                           GLsizeiptr size, GLbitfield access, uint32_t lr) {
    const auto* bytes = static_cast<const uint8_t*>(GuestToHost(
        host.GetGuestMemoryBase(), address));
    uint32_t words[4] = {};
    const size_t length = static_cast<size_t>(size);
    memcpy(words, bytes, std::min(length, sizeof(words)));
    uint32_t hash = 2166136261u;
    const size_t first = std::min(length, size_t{128});
    for (size_t i = 0; i < first; ++i) hash = (hash ^ bytes[i]) * 16777619u;
    const size_t tail = std::max(first, length > 128 ? length - 128 : size_t{0});
    for (size_t i = tail; i < length; ++i) hash = (hash ^ bytes[i]) * 16777619u;
    LOGI("[GLMAP-BYTES] %s #%u target=%04X binding=%d guest=%08X size=%zd"
         " access=%04X sample=%08X words=%08X,%08X,%08X,%08X lr=%08X",
         phase, count, target, binding, address, static_cast<ssize_t>(size),
         access, hash, words[0], words[1], words[2], words[3], lr);
}
#endif

static GLenum BufferBindingEnum(GLenum target) {
    if (target == GL_ARRAY_BUFFER) return GL_ARRAY_BUFFER_BINDING;
    if (target == GL_ELEMENT_ARRAY_BUFFER) return GL_ELEMENT_ARRAY_BUFFER_BINDING;
    return 0;
}

static void* DriverMapBufferRange(GLenum target, GLintptr offset,
                                  GLsizeiptr length, GLbitfield access) {
    if (CurrentCapabilities().major >= 3)
        return glMapBufferRange(target, offset, length, access);
    if (!HasGLExtension("GL_EXT_map_buffer_range")) return nullptr;
    static const auto extension = reinterpret_cast<PFNGLMAPBUFFERRANGEEXTPROC>(
        eglGetProcAddress("glMapBufferRangeEXT"));
    return extension ? extension(target, offset, length, access) : nullptr;
}

static void* DriverMapBufferOES(GLenum target, GLsizeiptr size) {
    if (HasGLExtension("GL_OES_mapbuffer")) {
        static const auto function = reinterpret_cast<PFNGLMAPBUFFEROESPROC>(
            eglGetProcAddress("glMapBufferOES"));
        if (function) return function(target, GL_WRITE_ONLY_OES);
    }
    return CurrentCapabilities().major >= 3
        ? glMapBufferRange(target, 0, size, GL_MAP_WRITE_BIT) : nullptr;
}

static GLboolean DriverUnmapBuffer(GLenum target) {
    if (HasGLExtension("GL_OES_mapbuffer")) {
        static const auto function = reinterpret_cast<PFNGLUNMAPBUFFEROESPROC>(
            eglGetProcAddress("glUnmapBufferOES"));
        if (function) return function(target);
    }
    return CurrentCapabilities().major >= 3 ? glUnmapBuffer(target) : GL_FALSE;
}

static GLint BoundBuffer(GLenum target) {
    const auto& bindings = CurrentBindings();
    if (target == GL_ARRAY_BUFFER) return bindings.array_buffer;
    if (target == GL_ELEMENT_ARRAY_BUFFER) return bindings.element_buffer;
    return 0;
}

static void UpdateBufferShadow(GLenum target, GLintptr offset, GLsizeiptr length,
                                const void* data) {
    if (offset < 0 || length <= 0 || !data) return;
    const GLint binding = BoundBuffer(target);
    if (!binding) return;
    auto& shadow = s_buffer_shadows[eglGetCurrentContext()][binding];
    if (shadow.empty()) {
        GLint size = 0;
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &size);
        if (size <= 0 || offset > size || length > size - offset) return;
        shadow.resize(static_cast<size_t>(size));
    }
    if (static_cast<size_t>(offset) > shadow.size() ||
        static_cast<size_t>(length) > shadow.size() - static_cast<size_t>(offset)) return;
    memcpy(shadow.data() + offset, data, static_cast<size_t>(length));
}

static uint32_t MapGuestBuffer(DynarmicHost& host, GLenum target, GLintptr offset,
                               GLsizeiptr length, GLbitfield access, uint32_t lr,
                               bool whole_buffer = false) {
    const EGLContext context = eglGetCurrentContext();
    if (context == EGL_NO_CONTEXT || !BufferBindingEnum(target)) return 0;
    const auto& bindings = CurrentBindings();
    const GLint binding = target == GL_ARRAY_BUFFER ? bindings.array_buffer : bindings.element_buffer;
    if (!binding || length <= 0 || static_cast<size_t>(length) > host.GetGuestMemorySize()) {
        LOGE("[GLMAP] invalid range: target=%04X binding=%d offset=%zd length=%zd",
             target, binding, static_cast<ssize_t>(offset), static_cast<ssize_t>(length));
        return 0;
    }
    const auto existing = std::find_if(s_guest_buffer_maps.begin(),
        s_guest_buffer_maps.end(), [context, binding](const GuestBufferMap& map) {
            return map.context == context && map.binding == binding;
        });
    if (existing != s_guest_buffer_maps.end()) {
        LOGE("[GLMAP] buffer=%d is already mapped", binding);
        return 0;
    }
    const uint32_t guest_address = host.GuestAlloc(static_cast<size_t>(length), 8);
    if (!guest_address) return 0;
    GLbitfield driver_access = access;
    // Staging must preserve unwritten bytes unless the guest invalidates them.
    if (!whole_buffer && (access & GL_MAP_WRITE_BIT) && !(access & (GL_MAP_READ_BIT |
            GL_MAP_INVALIDATE_RANGE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT))) {
        driver_access = (access | GL_MAP_READ_BIT) & ~GL_MAP_UNSYNCHRONIZED_BIT;
    }
    void* driver_address = whole_buffer ? DriverMapBufferOES(target, length)
        : DriverMapBufferRange(target, offset, length, driver_access);
    if (!driver_address) {
        LOGE("[GLMAP] driver map failed: target=%04X binding=%d offset=%zd length=%zd access=%04X",
             target, binding, static_cast<ssize_t>(offset), static_cast<ssize_t>(length), access);
        host.GuestFree(guest_address);
        return 0;
    }
    if (whole_buffer) {
        const auto& shadows = s_buffer_shadows[context];
        const auto shadow = shadows.find(binding);
        if (shadow != shadows.end() && shadow->second.size() == static_cast<size_t>(length))
            memcpy(GuestToHost(host.GetGuestMemoryBase(), guest_address),
                   shadow->second.data(), static_cast<size_t>(length));
    } else if (driver_access & GL_MAP_READ_BIT)
        memcpy(GuestToHost(host.GetGuestMemoryBase(), guest_address), driver_address,
               static_cast<size_t>(length));
    s_guest_buffer_maps.push_back({context, binding, guest_address, offset, length, access,
                                   driver_address});
#if MC4_ENABLE_NATIVE_LOGGING
    static std::atomic<uint32_t> observed{0};
    const uint32_t count = observed.fetch_add(1, std::memory_order_relaxed) + 1;
    if (count <= 40 || count % 1000 == 0) {
        LOGI("[GLMAP-RANGE] map #%u target=%04X binding=%d offset=%zd length=%zd"
             " access=%04X driver_access=%04X guest=%08X driver=%p context=%p lr=%08X",
             count, target, binding, static_cast<ssize_t>(offset),
             static_cast<ssize_t>(length), access, driver_access, guest_address,
             driver_address, context, lr);
        LogMappedBytes(host, "mapped", count, target, binding, guest_address,
                       length, access, lr);
    }
#else
    (void)lr;
#endif
    return guest_address;
}

// Share lookup-only graphics resolution with dlsym; a dummy GL proc can enable
// an extension path that never produces its texture, query or mapped buffer.
uint32_t ResolveGuestGLProcAddress(DynarmicHost& host, const char* name) {
    if (!name || strncmp(name, "gl", 2) != 0 || name[2] < 'A' || name[2] > 'Z' ||
        !GLProcSupported(name) || !eglGetProcAddress(name)) return 0;
    const uint32_t address = host.GetThunkManager().FindThunkAddress(name);
    LOGI("[GLPROC] %s -> guest=%08X context=%p", name, address, eglGetCurrentContext());
    return address;
}

void RegisterGles2CoreThunks(ThunkManager& manager);

void ThunkManager::RegisterGLThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    RegisterThunk("glActiveTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::ActiveTexture);
        glActiveTexture(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glAttachShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glAttachShader(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glBindBuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLuint buffer = jit.Regs()[1];
        auto& bindings = CurrentBindings();
        glBindBuffer(target, buffer);
        if (target == GL_ARRAY_BUFFER) bindings.array_buffer = buffer;
        else if (target == GL_ELEMENT_ARRAY_BUFFER) bindings.element_buffer = buffer;
    });

    RegisterThunk("glBindFramebuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::BindFramebuffer);
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        auto& bindings = CurrentBindings();
        glBindFramebuffer(target, jit.Regs()[1]);
        if (target == GL_FRAMEBUFFER || target == GL_DRAW_FRAMEBUFFER)
            bindings.draw_framebuffer = jit.Regs()[1];
    });

    RegisterThunk("glBindRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindRenderbuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::BindTextureTime);
        glstat::Bump(glstat::BindTexture);
        glBindTexture(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBlendFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendFunc(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glBufferData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::BufferData);
        GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        GLsizeiptr size = static_cast<int32_t>(jit.Regs()[1]);
        const void* data = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]);
        GLenum usage = static_cast<GLenum>(jit.Regs()[3]);
        glBufferData(target, size, data, usage);
        const GLint binding = BoundBuffer(target);
        if (binding && size >= 0 && static_cast<size_t>(size) <= host.GetGuestMemorySize()) {
            GLint stored_size = -1;
            glGetBufferParameteriv(target, GL_BUFFER_SIZE, &stored_size);
            if (stored_size != size) return;
            auto& shadow = s_buffer_shadows[eglGetCurrentContext()][binding];
            shadow.clear();
            if (data && size > 0 && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[2],
                                                  static_cast<size_t>(size)))
                shadow.assign(static_cast<const uint8_t*>(data),
                              static_cast<const uint8_t*>(data) + size);
        }
    });

    RegisterThunk("glMapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::MapTime);
        const GLenum target = jit.Regs()[0];
        const GLenum access = jit.Regs()[1];
        const EGLContext context = eglGetCurrentContext();
        jit.Regs()[0] = 0;
        if (context == EGL_NO_CONTEXT || access != GL_WRITE_ONLY_OES ||
            !BufferBindingEnum(target)) {
            LOGE("[GLMAP] unsupported map target=%04X access=%04X context=%p",
                 target, access, context);
            return;
        }
        const auto& bindings = CurrentBindings();
        const GLint binding = target == GL_ARRAY_BUFFER ? bindings.array_buffer : bindings.element_buffer;
        GLint size = 0;
        if (binding == 0) {
            LOGE("[GLMAP] no buffer bound to target=%04X", target);
            return;
        }
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &size);
        if (size <= 0 || static_cast<size_t>(size) > host.GetGuestMemorySize()) {
            LOGE("[GLMAP] invalid buffer size=%d target=%04X binding=%d",
                 size, target, binding);
            return;
        }
        const uint32_t guest_address = MapGuestBuffer(host, target, 0, size,
            GL_MAP_WRITE_BIT, jit.Regs()[14], true);
        static uint32_t count = 0;
        if (++count <= 40 || count % 1000 == 0) {
            LOGI("[GLMAP] map #%u target=%04X binding=%d size=%d guest=%08X lr=%08X",
                 count, target, binding, size, guest_address, jit.Regs()[14]);
        }
        jit.Regs()[0] = guest_address;
    });

    RegisterThunk("glMapBufferRangeEXT", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::MapTime);
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = args.U32();
        const GLintptr offset = args.I32();
        const GLsizeiptr length = args.I32();
        const GLbitfield access = args.U32();
        jit.Regs()[0] = MapGuestBuffer(host, target, offset, length, access,
                                     jit.Regs()[14]);
    });

    RegisterThunk("glGetBufferPointervOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = jit.Regs()[0], pname = jit.Regs()[1];
        auto* output = static_cast<uint32_t*>(GuestSpan(host.GetGuestMemoryBase(),
            host.GetGuestMemorySize(), jit.Regs()[2], sizeof(uint32_t)));
        if (!output) return;
        void* driver_pointer = nullptr;
        if (HasGLExtension("GL_OES_mapbuffer")) {
            static const auto function = reinterpret_cast<PFNGLGETBUFFERPOINTERVOESPROC>(
                eglGetProcAddress("glGetBufferPointervOES"));
            if (function) function(target, pname, &driver_pointer);
        } else if (CurrentCapabilities().major >= 3)
            glGetBufferPointerv(target, pname, &driver_pointer);
        *output = 0;
        if (!BufferBindingEnum(target) || pname != GL_BUFFER_MAP_POINTER_OES) return;
        const auto& bindings = CurrentBindings();
        const GLint binding = target == GL_ARRAY_BUFFER ? bindings.array_buffer : bindings.element_buffer;
        const EGLContext context = eglGetCurrentContext();
        for (const auto& map : s_guest_buffer_maps)
            if (map.context == context && map.binding == binding &&
                map.driver_address == driver_pointer) *output = map.guest_address;
    });

    RegisterThunk("glFlushMappedBufferRangeEXT", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = jit.Regs()[0];
        const GLintptr offset = static_cast<int32_t>(jit.Regs()[1]);
        const GLsizeiptr length = static_cast<int32_t>(jit.Regs()[2]);
        if (BufferBindingEnum(target)) {
            const auto& bindings = CurrentBindings();
            const GLint binding = target == GL_ARRAY_BUFFER ? bindings.array_buffer : bindings.element_buffer;
            const EGLContext context = eglGetCurrentContext();
            for (const auto& map : s_guest_buffer_maps) {
                if (map.context == context && map.binding == binding &&
                    (map.access & GL_MAP_FLUSH_EXPLICIT_BIT) && offset >= 0 && length >= 0 &&
                    offset <= map.size && length <= map.size - offset) {
                    memcpy(static_cast<uint8_t*>(map.driver_address) + offset,
                           static_cast<uint8_t*>(GuestToHost(host.GetGuestMemoryBase(),
                               map.guest_address)) + offset, static_cast<size_t>(length));
                    UpdateBufferShadow(target, map.offset + offset, length,
                        static_cast<uint8_t*>(GuestToHost(host.GetGuestMemoryBase(),
                            map.guest_address)) + offset);
                }
            }
        }
        if (CurrentCapabilities().major >= 3) glFlushMappedBufferRange(target, offset, length);
        else if (HasGLExtension("GL_EXT_map_buffer_range")) {
            static const auto function = reinterpret_cast<PFNGLFLUSHMAPPEDBUFFERRANGEEXTPROC>(
                eglGetProcAddress("glFlushMappedBufferRangeEXT"));
            if (function) function(target, offset, length);
        }
    });

    RegisterThunk("glUnmapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::UnmapTime);
        const GLenum target = jit.Regs()[0];
        const EGLContext context = eglGetCurrentContext();
        jit.Regs()[0] = GL_FALSE;
        if (!BufferBindingEnum(target)) return;
        const auto& bindings = CurrentBindings();
        const GLint binding = target == GL_ARRAY_BUFFER ? bindings.array_buffer : bindings.element_buffer;
        const auto it = std::find_if(s_guest_buffer_maps.begin(),
            s_guest_buffer_maps.end(), [context, binding](const GuestBufferMap& map) {
                return map.context == context && map.binding == binding;
            });
        if (it == s_guest_buffer_maps.end()) {
            LOGE("[GLMAP] unmap without map: target=%04X context=%p", target, context);
            return;
        }
#if MC4_ENABLE_NATIVE_LOGGING
        static std::atomic<uint32_t> commits{0};
        const uint32_t commit = commits.fetch_add(1, std::memory_order_relaxed) + 1;
        if (commit <= 40 || commit % 1000 == 0)
            LogMappedBytes(host, "unmap", commit, target, binding, it->guest_address,
                           it->size, it->access, jit.Regs()[14]);
#endif
        if ((it->access & GL_MAP_WRITE_BIT) && !(it->access & GL_MAP_FLUSH_EXPLICIT_BIT)) {
            memcpy(it->driver_address,
                   GuestToHost(host.GetGuestMemoryBase(), it->guest_address),
                   static_cast<size_t>(it->size));
            UpdateBufferShadow(target, it->offset, it->size,
                GuestToHost(host.GetGuestMemoryBase(), it->guest_address));
        }
        const GLboolean result = DriverUnmapBuffer(target);
        static uint32_t count = 0;
        if (++count <= 40 || count % 1000 == 0) {
            LOGI("[GLMAP] unmap #%u target=%04X binding=%d size=%zd ok=%u lr=%08X",
                 count, target, it->binding, static_cast<ssize_t>(it->size),
                 result, jit.Regs()[14]);
        }
        host.GuestFree(it->guest_address);
        s_guest_buffer_maps.erase(it);
        jit.Regs()[0] = result;
    });

    RegisterThunk("glCheckFramebufferStatus", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::CheckFramebufferStatus);
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum status = glCheckFramebufferStatus(target);
        if (status != GL_FRAMEBUFFER_COMPLETE) {
            static std::atomic<uint32_t> failures{0};
            const uint32_t n = failures.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n <= 40 || n % 1000 == 0) {
                LOGE("[GLFBO] incomplete #%u target=%04X status=%04X lr=%08X",
                     n, target, status, jit.Regs()[14]);
            }
        }
        jit.Regs()[0] = status;
    });

    RegisterThunk("glClear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::Clear);
#if MC4_ENABLE_NATIVE_LOGGING
        ObserveSelectedSkyClear(static_cast<GLbitfield>(jit.Regs()[0]), jit.Regs()[14]);
#endif
        glClear(static_cast<GLbitfield>(jit.Regs()[0]));
    });

    RegisterThunk("glClearColor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float r = ReadSF(jit, 0);
        float g = ReadSF(jit, 1);
        float b = ReadSF(jit, 2);
        float a = ReadSF(jit, 3);
        glClearColor(r, g, b, a);
    });

    RegisterThunk("glColorMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glColorMask(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glCompileShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::CompileShader);
        GLuint shader = jit.Regs()[0];
        glCompileShader(shader);
        GLint compiled = 0;
        glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
        if (!compiled) {
            char log[1024];
            glGetShaderInfoLog(shader, sizeof(log), nullptr, log);
            LOGE("Shader %u compile failed: %s", shader, log);
        }
    });

    RegisterThunk("glCompressedTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::CompressedTexImage2D);
        static std::atomic<uint32_t> observed{0};
        const uint32_t n = observed.fetch_add(1, std::memory_order_relaxed) + 1;
        GLenum target = jit.Regs()[0];
        GLint level = jit.Regs()[1];
        GLenum internalformat = jit.Regs()[2];
        GLsizei width = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei height = host.MemoryRead32(sp);
        GLint border = host.MemoryRead32(sp + 4);
        GLsizei imageSize = host.MemoryRead32(sp + 8);
        const uint32_t guest_data = host.MemoryRead32(sp + 12);
        const void* data = GuestToHost(host.GetGuestMemoryBase(), guest_data);
        if (n <= 200 || n % 1000 == 0) {
            LOGI("[GLCOMP] upload #%u target=%04X level=%d internal=%04X"
                 " size=%dx%d bytes=%d source=%08X lr=%08X",
                 n, target, level, internalformat, width, height,
                 imageSize, guest_data, jit.Regs()[14]);
        }
#if MC4_ENABLE_NATIVE_LOGGING
        DumpSelectedSkyTexture(host, target, level, internalformat, width, height,
            imageSize, guest_data, jit.Regs()[14]);
#endif
        glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize, data);
    });

    RegisterThunk("glCreateProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateProgram();
    });

    RegisterThunk("glCreateShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateShader(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glCullFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glCullFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDeleteBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        const auto* buffers = count > 0 ? static_cast<const GLuint*>(GuestSpan(
            host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1],
            static_cast<size_t>(count) * sizeof(GLuint))) : nullptr;
        if (count > 0 && !buffers) {
            LOGE("glDeleteBuffers rejected guest array: address=%08X count=%d",
                 jit.Regs()[1], count);
            return;
        }
        auto& bindings = CurrentBindings();
        glDeleteBuffers(count, buffers);
        for (GLsizei i = 0; i < count; ++i) {
            s_buffer_shadows[bindings.context].erase(buffers[i]);
            if (bindings.array_buffer == buffers[i]) bindings.array_buffer = 0;
            if (bindings.element_buffer == buffers[i]) bindings.element_buffer = 0;
            // Deleting a mapped object invalidates its driver pointer immediately.
            for (auto it = s_guest_buffer_maps.begin(); it != s_guest_buffer_maps.end();) {
                if (it->context == bindings.context && it->binding == buffers[i]) {
                    host.GuestFree(it->guest_address);
                    it = s_guest_buffer_maps.erase(it);
                } else ++it;
            }
        }
    });

    RegisterThunk("glDeleteFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        const auto* buffers = count > 0 ? static_cast<const GLuint*>(GuestSpan(
            host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1],
            static_cast<size_t>(count) * sizeof(GLuint))) : nullptr;
        if (count > 0 && !buffers) {
            LOGE("glDeleteFramebuffers rejected guest array: address=%08X count=%d",
                 jit.Regs()[1], count);
            return;
        }
        auto& bindings = CurrentBindings();
        glDeleteFramebuffers(count, buffers);
        for (GLsizei i = 0; i < count; ++i)
            if (bindings.draw_framebuffer == buffers[i]) bindings.draw_framebuffer = 0;
    });

    RegisterThunk("glDeleteProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
#if MC4_ENABLE_NATIVE_LOGGING
        s_uniform_names[eglGetCurrentContext()].erase(jit.Regs()[0]);
#endif
        glDeleteProgram(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteRenderbuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteShader(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteTextures(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDepthFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthFunc(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDepthMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthMask(static_cast<GLboolean>(jit.Regs()[0]));
    });

    RegisterThunk("glDisable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDisableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glDrawArrays", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::DrawTime);
        glstat::Bump(glstat::DrawArrays);
#if MC4_GL_DRAW_TRACE_ENABLED
        static std::atomic<uint32_t> observed{0};
        const uint32_t n = observed.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n <= 16 || n % 4096 == 0) {
            LOGI("[GLTEXT] draw_arrays #%u mode=%04X first=%u count=%u lr=%08X",
                 n, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[14]);
        }
#endif
        const GLenum mode = static_cast<GLenum>(jit.Regs()[0]);
        const GLint first = static_cast<GLint>(jit.Regs()[1]);
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[2]);
#if MC4_ENABLE_NATIVE_LOGGING
        LogSkyDraw(host, mode, count, 0, nullptr, first, jit.Regs()[14], jit.Regs()[8]);
#endif
        glDrawArrays(mode, first, count);
    });

    RegisterThunk("glDrawElements", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::DrawTime);
        glstat::Bump(glstat::DrawElements);
#if MC4_GL_DRAW_TRACE_ENABLED
        static std::atomic<uint32_t> observed{0};
        const uint32_t n = observed.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n <= 16 || n % 4096 == 0) {
            LOGI("[GLTEXT] draw_elements #%u mode=%04X count=%u type=%04X"
                 " indices=%08X ebo=%u lr=%08X",
                 n, jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                 jit.Regs()[3], CurrentBindings().element_buffer, jit.Regs()[14]);
        }
#endif
        const GLenum mode = static_cast<GLenum>(jit.Regs()[0]);
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[1]);
        const GLenum type = static_cast<GLenum>(jit.Regs()[2]);
        const uint32_t indices_gaddr = jit.Regs()[3];
        const GLuint element_buffer = CurrentBindings().element_buffer;
        const void* indices = (element_buffer != 0) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(indices_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), indices_gaddr);
#if MC4_ENABLE_NATIVE_LOGGING
        LogSkyDraw(host, mode, count, type, indices, 0, jit.Regs()[14], jit.Regs()[8]);
        bool capture_pixels = false;
        auto& observation = s_sky_observation;
        if (observation.active && observation.draws == 3000 && !observation.pixel_frame_requested) {
            observation.pixel_frame_requested = true;
            GLint program = 0, framebuffer = 0;
            glGetIntegerv(GL_CURRENT_PROGRAM, &program);
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            capture_pixels = program == 219 && framebuffer == 1;
            observation.pixel_frame_pending = capture_pixels;
            observation.pixel_context = eglGetCurrentContext();
            if (capture_pixels) {
                LogSkyRasterState("before", 0, jit.Regs()[14]);
                CompareSelectedSkyGpuBuffers();
                CaptureSkyPixels("before", 1);
            }
        }
#endif
        glDrawElements(mode, count, type, indices);
#if MC4_ENABLE_NATIVE_LOGGING
        if (capture_pixels) CaptureSkyPixels("after", 1);
#endif
    });

    RegisterThunk("glEnable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glEnableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::EnableVertexAttribArray);
        glEnableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glFlush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFlush();
    });

    RegisterThunk("glFramebufferRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferRenderbuffer(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glFramebufferTexture2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferTexture2D(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], host.MemoryRead32(jit.Regs()[13]));
    });

    RegisterThunk("glFrontFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFrontFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGenBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenBuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenFramebuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenRenderbuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenTextures(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenerateMipmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenerateMipmap(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGetActiveAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei* length = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        GLint* size = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        GLenum* type = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 4)));
        GLchar* name = reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8)));
        glGetActiveAttrib(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], length, size, type, name);
    });

    RegisterThunk("glGetActiveUniform", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei* length = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        GLint* size = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        GLenum* type = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 4)));
        GLchar* name = reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8)));
        glGetActiveUniform(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], length, size, type, name);
    });

    RegisterThunk("glGetAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::GetAttribLocation);
        jit.Regs()[0] = glGetAttribLocation(jit.Regs()[0], reinterpret_cast<const GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::GetError);
        const GLenum result = glGetError();
        if (result != GL_NO_ERROR) {
            static std::atomic<uint32_t> errors{0};
            const uint32_t n = errors.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n <= 40 || n % 1000 == 0) {
                LOGE("[GLERR] guest-observed #%u result=%04X lr=%08X",
                     n, result, jit.Regs()[14]);
            }
        }
        jit.Regs()[0] = result;
    });

    RegisterThunk("glGetIntegerv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetIntegerv(static_cast<GLenum>(jit.Regs()[0]),
                      reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGetProgramInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* length = jit.Regs()[2] ?
            reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])) : nullptr;
        glGetProgramInfoLog(jit.Regs()[0], jit.Regs()[1], length,
                           reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glGetProgramiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::GetProgramiv);
        glGetProgramiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]),
                       reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetRenderbufferParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetRenderbufferParameteriv(jit.Regs()[0], jit.Regs()[1],
                                     reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetShaderInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* length = jit.Regs()[2] ?
            reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])) : nullptr;
        glGetShaderInfoLog(jit.Regs()[0], jit.Regs()[1], length,
                          reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glGetShaderiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::GetShaderiv);
        glGetShaderiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]),
                      reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    // GL promises a pointer valid for the life of the context, and callers keep
    // it. One block per enum, so a capability check inside a frame loop costs
    // nothing after the first frame - GL_EXTENSIONS alone is a couple of KiB.
    RegisterThunk("glGetString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::mutex m;
        static std::unordered_map<EGLContext, std::unordered_map<GLenum, uint32_t>> caches;
        GLenum name = static_cast<GLenum>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(m);
        auto& cache = caches[eglGetCurrentContext()];
        auto it = cache.find(name);
        if (it == cache.end()) {
            const GLubyte* str = glGetString(name);
            if (!str) {
                // An invalid enum must reach GL again on subsequent calls.
                jit.Regs()[0] = 0;
                return;
            }
            uint32_t guest_addr = 0;
            if (str) {
                size_t len = strlen(reinterpret_cast<const char*>(str)) + 1;
                guest_addr = host.GuestAlloc(len);
                if (guest_addr) memcpy(host.GetGuestMemoryBase() + guest_addr, str, len);
            }
            // Bring-up probe: what the guest sees for version/extension strings.
            // Remove with the rest of the phase-7 bring-up diagnostics.
            LOGI("[GL-PROBE] glGetString(0x%04X) -> guest 0x%08X '%s'",
                 name, guest_addr, str ? reinterpret_cast<const char*>(str) : "(null)");
            if (!guest_addr) { jit.Regs()[0] = 0; return; }
            it = cache.emplace(name, guest_addr).first;
        }
        jit.Regs()[0] = it->second;
    });

    RegisterThunk("glGetUniformLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::GetUniformLocation);
        const GLuint program = jit.Regs()[0];
        const auto* name = reinterpret_cast<const GLchar*>(GuestToHost(
            host.GetGuestMemoryBase(), jit.Regs()[1]));
        const GLint location = glGetUniformLocation(program, name);
#if MC4_ENABLE_NATIVE_LOGGING
        if (name && location >= 0)
            s_uniform_names[eglGetCurrentContext()][program][location] = name;
#endif
        jit.Regs()[0] = location;
    });

    RegisterThunk("glHint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glHint(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glLineWidth", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glLineWidth(ReadSF(jit, 0));
    });

    RegisterThunk("glLinkProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::LinkProgram);
        GLuint prog = jit.Regs()[0];
        glLinkProgram(prog);
        GLint linked = 0;
        glGetProgramiv(prog, GL_LINK_STATUS, &linked);
        if (!linked) {
            char log[1024];
            glGetProgramInfoLog(prog, sizeof(log), nullptr, log);
            LOGE("Program %u link failed: %s", prog, log);
        }
    });

    RegisterThunk("glPixelStorei", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPixelStorei(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glPolygonOffset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPolygonOffset(ReadSF(jit, 0), ReadSF(jit, 1));
    });

    RegisterThunk("glReadPixels", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::ReadPixels);
        uint32_t sp = jit.Regs()[13];
        GLenum format = host.MemoryRead32(sp);
        GLenum type = host.MemoryRead32(sp + 4);
        void* pixels = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8));
        glReadPixels(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], format, type, pixels);
    });

    RegisterThunk("glRenderbufferStorage", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glRenderbufferStorage(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glScissor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint x = jit.Regs()[0], y = jit.Regs()[1];
        GLsizei w = jit.Regs()[2], h = jit.Regs()[3];
        ScaleViewportToSurface(x, y, w, h);
        glScissor(x, y, w, h);
    });

    RegisterThunk("glShaderSource", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::ShaderSource);
        GLuint shader = jit.Regs()[0];
        GLsizei count = jit.Regs()[1];
        uint32_t str_array_gaddr = jit.Regs()[2];
        uint32_t len_array_gaddr = jit.Regs()[3];

        std::vector<const char*> strings(count);
        for (GLsizei i = 0; i < count; ++i) {
            uint32_t str_gaddr = host.MemoryRead32(str_array_gaddr + i * 4);
            strings[i] = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), str_gaddr));
        }

        const GLint* lengths = len_array_gaddr ?
            reinterpret_cast<const GLint*>(GuestToHost(host.GetGuestMemoryBase(), len_array_gaddr)) : nullptr;

        glShaderSource(shader, count, strings.data(), lengths);
    });

    RegisterThunk("glTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::TexImage2D);
        static std::atomic<uint32_t> observed{0};
        const uint32_t n = observed.fetch_add(1, std::memory_order_relaxed) + 1;
        GLenum target = jit.Regs()[0];
        GLint level = jit.Regs()[1];
        GLint internalformat = jit.Regs()[2];
        GLsizei width = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei height = host.MemoryRead32(sp);
        GLint border = host.MemoryRead32(sp + 4);
        GLenum format = host.MemoryRead32(sp + 8);
        GLenum type = host.MemoryRead32(sp + 12);
        uint32_t pixels_gaddr = host.MemoryRead32(sp + 16);
        if (n <= 40 || n % 4096 == 0) {
            LOGI("[GLTEXT] tex_image #%u target=%04X level=%d internal=%04X"
                 " size=%ux%u format=%04X type=%04X pixels=%08X lr=%08X",
                 n, target, level, internalformat, width, height, format,
                 type, pixels_gaddr, jit.Regs()[14]);
        }
        const void* pixels = (pixels_gaddr < 0x10000) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(pixels_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), pixels_gaddr);
        if (format == GL_LUMINANCE && type == GL_UNSIGNED_BYTE &&
            pixels_gaddr >= 0x10000u && width > 0 && height > 0 &&
            width <= 4096 && height <= 4096) {
            const uint32_t total = static_cast<uint32_t>(width * height);
            const auto* bytes = static_cast<const uint8_t*>(pixels);
            uint32_t nonzero = 0;
            uint8_t maximum = 0;
            for (uint32_t i = 0; i < total; ++i) {
                if (bytes[i]) ++nonzero;
                if (bytes[i] > maximum) maximum = bytes[i];
            }
            LOGI("[GLTEXT] luminance_pixels tex#%u nonzero=%u/%u max=%u",
                 n, nonzero, total, maximum);
        }
        glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
    });

    RegisterThunk("glTexParameterf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameterf(jit.Regs()[0], jit.Regs()[1], ReadSF(jit, 2));
    });

    RegisterThunk("glTexParameteri", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameteri(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
    });

    RegisterThunk("glUniform1f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1f(jit.Regs()[0], ReadSF(jit, 1));
    });

    RegisterThunk("glUniform1i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1i(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glUniform2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform2f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2));
    });

    RegisterThunk("glUniform3f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2), ReadSF(jit, 3));
    });

    RegisterThunk("glUniform3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glUniform4f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform4f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2), ReadSF(jit, 3),
                    ReadStackF(jit, host.GetGuestMemoryBase(), 0));
    });

    RegisterThunk("glUniform4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform4fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glUniformMatrix3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::UniformMatrixTime);
        glUniformMatrix3fv(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                           reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glUniformMatrix4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::UniformMatrixTime);
        glUniformMatrix4fv(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                           reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glUseProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::UseProgramTime);
        glstat::Bump(glstat::UseProgram);
        glUseProgram(jit.Regs()[0]);
    });

    RegisterThunk("glVertexAttribPointer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::AttribTime);
        glstat::Bump(glstat::VertexAttribPointer);
        GLuint index = jit.Regs()[0];
        GLint size = jit.Regs()[1];
        GLenum type = jit.Regs()[2];
        GLboolean normalized = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei stride = host.MemoryRead32(sp);
        uint32_t ptr_gaddr = host.MemoryRead32(sp + 4);
        
        const void* ptr = (CurrentBindings().array_buffer != 0) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(ptr_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), ptr_gaddr);
        
        glVertexAttribPointer(index, size, type, normalized, stride, ptr);
    });

    RegisterThunk("glViewport", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::Viewport);
        GLint x = jit.Regs()[0], y = jit.Regs()[1];
        GLsizei w = jit.Regs()[2], h = jit.Regs()[3];
        ScaleViewportToSurface(x, y, w, h);
        glViewport(x, y, w, h);
    });

    RegisterThunk("glBufferSubData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::BufferSubDataTime);
        glstat::Bump(glstat::BufferSubData);
        GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        GLintptr offset = static_cast<int32_t>(jit.Regs()[1]);
        GLsizeiptr size = static_cast<int32_t>(jit.Regs()[2]);
        uint32_t data_gaddr = jit.Regs()[3];
        const void* data = data_gaddr ? GuestToHost(host.GetGuestMemoryBase(), data_gaddr) : nullptr;
        glBufferSubData(target, offset, size, data);
        if (size > 0 && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3],
                                       static_cast<size_t>(size)))
            UpdateBufferShadow(target, offset, size, data);
    });

    RegisterThunk("glDepthRangef", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float n = ReadSF(jit, 0);
        float f = ReadSF(jit, 1);
        glDepthRangef(n, f);
    });

    RegisterThunk("glTexSubImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::Bump(glstat::TexSubImage2D);
        static std::atomic<uint32_t> observed{0};
        const uint32_t n = observed.fetch_add(1, std::memory_order_relaxed) + 1;
        GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        GLint level = static_cast<GLint>(jit.Regs()[1]);
        GLint xoffset = static_cast<GLint>(jit.Regs()[2]);
        GLint yoffset = static_cast<GLint>(jit.Regs()[3]);
        uint32_t sp = jit.Regs()[13];
        GLsizei width = static_cast<GLsizei>(host.MemoryRead32(sp));
        GLsizei height = static_cast<GLsizei>(host.MemoryRead32(sp + 4));
        GLenum format = static_cast<GLenum>(host.MemoryRead32(sp + 8));
        GLenum type = static_cast<GLenum>(host.MemoryRead32(sp + 12));
        uint32_t pixels_gaddr = host.MemoryRead32(sp + 16);
        if (n <= 40 || n % 4096 == 0) {
            LOGI("[GLTEXT] tex_sub #%u target=%04X level=%d offset=%d,%d"
                 " size=%ux%u format=%04X type=%04X pixels=%08X lr=%08X",
                 n, target, level, xoffset, yoffset, width, height, format,
                 type, pixels_gaddr, jit.Regs()[14]);
        }
        const void* pixels = (pixels_gaddr < 0x10000) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(pixels_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), pixels_gaddr);
        glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels);
    });

    // EGL thunks
    RegisterThunk("eglGetCurrentDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0xDE700001; // Non-null dummy display handle
    });

    RegisterThunk("eglGetCurrentSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0x50F00001; // Non-null dummy surface handle
    });

    RegisterThunk("eglSwapBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glstat::ScopedTime timer(glstat::SwapTime);
        glstat::Bump(glstat::Swap);
        EGLDisplay dpy = eglGetCurrentDisplay();
        EGLSurface surf = eglGetCurrentSurface(EGL_DRAW);
        if (dpy != EGL_NO_DISPLAY && surf != EGL_NO_SURFACE) {
#if MC4_ENABLE_NATIVE_LOGGING
            auto& observation = s_sky_observation;
            if (observation.pixel_frame_pending) {
                observation.pixel_frame_pending = false;
                if (observation.pixel_context == eglGetCurrentContext()) CaptureSkyPixels("present", 0);
                else LOGI("[GLSKY-PIXELS] skip present: selected sky context changed");
            }
#endif
            eglSwapBuffers(dpy, surf);
        }
        jit.Regs()[0] = EGL_TRUE;
    });

    RegisterThunk("eglGetProcAddress", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* procname = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = ResolveGuestGLProcAddress(host, procname);
    });

    RegisterGles2CoreThunks(*this);
}
