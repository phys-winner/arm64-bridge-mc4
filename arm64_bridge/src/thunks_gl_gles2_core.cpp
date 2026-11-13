#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl3.h>
#include <EGL/egl.h>
#include <android/log.h>

#include <cstdint>
#include <limits>
#include <unordered_map>

#define LOG_TAG "Arm32Bridge_GLES2Core"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

bool CheckedArrayBytes(size_t count, size_t components, size_t element_size,
                       size_t* bytes) {
    const uint64_t total = static_cast<uint64_t>(count) *
                           static_cast<uint64_t>(components) *
                           static_cast<uint64_t>(element_size);
    if (total > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return false;
    }
    *bytes = static_cast<size_t>(total);
    return true;
}

template <typename T>
const T* GuestInputArray(DynarmicHost& host, uint32_t address, size_t count,
                         size_t components, const char* function_name) {
    size_t bytes = 0;
    if (!CheckedArrayBytes(count, components, sizeof(T), &bytes) ||
        bytes == 0 ||
        !GuestRangeValid(host.GetGuestMemorySize(), address, bytes)) {
        LOGE("%s rejected guest input: address=0x%08X count=%zu components=%zu",
             function_name, address, count, components);
        return nullptr;
    }
    return reinterpret_cast<const T*>(
        GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, bytes));
}

template <typename T>
T* GuestOutputArray(DynarmicHost& host, uint32_t address, size_t count,
                    size_t components, const char* function_name) {
    size_t bytes = 0;
    if (!CheckedArrayBytes(count, components, sizeof(T), &bytes) ||
        bytes == 0 ||
        !GuestRangeValid(host.GetGuestMemorySize(), address, bytes)) {
        LOGE("%s rejected guest output: address=0x%08X count=%zu components=%zu",
             function_name, address, count, components);
        return nullptr;
    }
    return reinterpret_cast<T*>(
        GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, bytes));
}

template <typename T>
T* OptionalGuestOutput(DynarmicHost& host, uint32_t address, size_t count,
                       const char* function_name, bool* valid) {
    if (address == 0) {
        *valid = true;
        return nullptr;
    }
    T* output = GuestOutputArray<T>(host, address, count, 1, function_name);
    *valid = output != nullptr;
    return output;
}

const void* CountedGuestBytes(DynarmicHost& host, uint32_t address,
                              GLsizei byte_count, const char* function_name,
                              bool* valid) {
    if (byte_count <= 0) {
        *valid = true;
        return nullptr;
    }
    const void* input = GuestInputArray<uint8_t>(
        host, address, static_cast<size_t>(byte_count), 1, function_name);
    *valid = input != nullptr;
    return input;
}

template <typename T>
const T* CountedGuestValues(DynarmicHost& host, uint32_t address,
                            GLsizei count, size_t components,
                            const char* function_name, bool* valid) {
    if (count <= 0) {
        *valid = true;
        return nullptr;
    }
    const T* input = GuestInputArray<T>(
        host, address, static_cast<size_t>(count), components, function_name);
    *valid = input != nullptr;
    return input;
}

const void* GuestImage3D(DynarmicHost& host, uint32_t address, GLsizei width,
                        GLsizei height, GLsizei depth, GLenum format, GLenum type,
                        const char* name, bool* valid) {
    if (!address || width <= 0 || height <= 0 || depth <= 0) {
        *valid = true;
        return nullptr;
    }
    size_t components = 1, element_size = 1;
    switch (format) {
        case GL_LUMINANCE_ALPHA: case GL_RG: case GL_RG_INTEGER: components = 2; break;
        case GL_RGB: case GL_RGB_INTEGER: components = 3; break;
        case GL_RGBA: case GL_RGBA_INTEGER: case GL_BGRA_EXT: components = 4; break;
    }
    switch (type) {
        case GL_UNSIGNED_SHORT: case GL_SHORT: case GL_HALF_FLOAT: case GL_HALF_FLOAT_OES:
            element_size = 2; break;
        case GL_UNSIGNED_INT: case GL_INT: case GL_FLOAT: element_size = 4; break;
        case GL_UNSIGNED_SHORT_5_6_5: case GL_UNSIGNED_SHORT_4_4_4_4:
        case GL_UNSIGNED_SHORT_5_5_5_1: components = 1; element_size = 2; break;
        case GL_UNSIGNED_INT_2_10_10_10_REV: case GL_UNSIGNED_INT_10F_11F_11F_REV:
        case GL_UNSIGNED_INT_5_9_9_9_REV: case GL_UNSIGNED_INT_24_8:
            components = 1; element_size = 4; break;
        case GL_FLOAT_32_UNSIGNED_INT_24_8_REV: components = 1; element_size = 8; break;
    }
    GLint alignment = 4;
    glGetIntegerv(GL_UNPACK_ALIGNMENT, &alignment);
    const uint64_t row = static_cast<uint64_t>(width) * components * element_size;
    const uint64_t stride = ((row + alignment - 1) / alignment) * alignment;
    const uint64_t rows = static_cast<uint64_t>(height) * depth;
    const uint64_t available = host.GetGuestMemorySize();
    if (row > available || rows - 1 > (available - row) / stride) {
        LOGE("%s rejected image span: address=%08X size=%dx%dx%d", name, address, width, height, depth);
        *valid = false;
        return nullptr;
    }
    const void* pixels = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(),
                                   address, static_cast<size_t>((rows - 1) * stride + row));
    *valid = pixels != nullptr;
    return pixels;
}

template <typename Function, typename Handler>
void NativeExtensionThunk(ThunkManager& manager, const char* name, Handler handler) {
    manager.RegisterThunk(name, [name, handler](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        // Registration precedes EGL context creation; resolve on first use.
        static thread_local std::unordered_map<const char*, Function> functions;
        auto it = functions.find(name);
        if (it == functions.end()) {
            const auto function = reinterpret_cast<Function>(eglGetProcAddress(name));
            if (!function) return;
            it = functions.emplace(name, function).first;
        }
        handler(it->second, jit, host);
    });
}

size_t GetFloatStateValueCount(GLenum pname) {
    switch (pname) {
        case GL_ALIASED_LINE_WIDTH_RANGE:
        case GL_ALIASED_POINT_SIZE_RANGE:
        case GL_DEPTH_RANGE:
        case GL_MAX_VIEWPORT_DIMS:
            return 2;
        case GL_BLEND_COLOR:
        case GL_COLOR_CLEAR_VALUE:
        case GL_COLOR_WRITEMASK:
        case GL_SCISSOR_BOX:
        case GL_VIEWPORT:
            return 4;
        case GL_COMPRESSED_TEXTURE_FORMATS: {
            GLint count = 0;
            glGetIntegerv(GL_NUM_COMPRESSED_TEXTURE_FORMATS, &count);
            return count > 0 ? static_cast<size_t>(count) : 1;
        }
        case GL_SHADER_BINARY_FORMATS: {
            GLint count = 0;
            glGetIntegerv(GL_NUM_SHADER_BINARY_FORMATS, &count);
            return count > 0 ? static_cast<size_t>(count) : 1;
        }
        default:
            return 1;
    }
}

size_t GetVertexAttribValueCount(GLenum pname) {
    return pname == GL_CURRENT_VERTEX_ATTRIB ? 4 : 1;
}

uint32_t HostVertexPointerToGuest(DynarmicHost& host, const void* pointer,
                                  GLint array_buffer_binding) {
    if (!pointer) return 0;

    const uintptr_t value = reinterpret_cast<uintptr_t>(pointer);
    if (array_buffer_binding != 0) {
        return value <= std::numeric_limits<uint32_t>::max()
            ? static_cast<uint32_t>(value)
            : 0;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
    const uintptr_t end = base + host.GetGuestMemorySize();
    if (value < base || value >= end) return 0;
    const uintptr_t offset = value - base;
    return offset <= std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(offset)
        : 0;
}

}  // namespace

void RegisterGles2CoreThunks(ThunkManager& manager) {
    manager.RegisterThunk("glBlendColor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLfloat red = args.F32();
        const GLfloat green = args.F32();
        const GLfloat blue = args.F32();
        const GLfloat alpha = args.F32();
        glBlendColor(red, green, blue, alpha);
    });
    manager.RegisterThunk("glBlendEquation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glBlendEquation(static_cast<GLenum>(args.U32()));
    });
    manager.RegisterThunk("glBlendEquationSeparate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum rgb = static_cast<GLenum>(args.U32());
        const GLenum alpha = static_cast<GLenum>(args.U32());
        glBlendEquationSeparate(rgb, alpha);
    });
    manager.RegisterThunk("glClearDepthf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glClearDepthf(args.F32());
    });
    manager.RegisterThunk("glClearStencil", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glClearStencil(static_cast<GLint>(args.I32()));
    });
    manager.RegisterThunk("glCompressedTexSubImage2D", [](Dynarmic::A32::Jit& jit,
                                                     DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLint level = static_cast<GLint>(args.I32());
        const GLint xoffset = static_cast<GLint>(args.I32());
        const GLint yoffset = static_cast<GLint>(args.I32());
        const GLsizei width = static_cast<GLsizei>(args.I32());
        const GLsizei height = static_cast<GLsizei>(args.I32());
        const GLenum format = static_cast<GLenum>(args.U32());
        const GLsizei image_size = static_cast<GLsizei>(args.I32());
        const uint32_t data_address = args.Ptr();
        bool valid = false;
        const void* data = CountedGuestBytes(
            host, data_address, image_size, "glCompressedTexSubImage2D", &valid);
        if (!valid) return;
        glCompressedTexSubImage2D(target, level, xoffset, yoffset, width, height,
                                  format, image_size, data);
    });
    manager.RegisterThunk("glCopyTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLint level = static_cast<GLint>(args.I32());
        const GLenum internal_format = static_cast<GLenum>(args.U32());
        const GLint x = static_cast<GLint>(args.I32());
        const GLint y = static_cast<GLint>(args.I32());
        const GLsizei width = static_cast<GLsizei>(args.I32());
        const GLsizei height = static_cast<GLsizei>(args.I32());
        const GLint border = static_cast<GLint>(args.I32());
        glCopyTexImage2D(target, level, internal_format, x, y, width, height, border);
    });
    manager.RegisterThunk("glCopyTexSubImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLint level = static_cast<GLint>(args.I32());
        const GLint xoffset = static_cast<GLint>(args.I32());
        const GLint yoffset = static_cast<GLint>(args.I32());
        const GLint x = static_cast<GLint>(args.I32());
        const GLint y = static_cast<GLint>(args.I32());
        const GLsizei width = static_cast<GLsizei>(args.I32());
        const GLsizei height = static_cast<GLsizei>(args.I32());
        glCopyTexSubImage2D(target, level, xoffset, yoffset, x, y, width, height);
    });
    manager.RegisterThunk("glDetachShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint program = static_cast<GLuint>(args.U32());
        const GLuint shader = static_cast<GLuint>(args.U32());
        glDetachShader(program, shader);
    });

    manager.RegisterThunk("glGetAttachedShaders", [](Dynarmic::A32::Jit& jit,
                                                DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint program = static_cast<GLuint>(args.U32());
        const GLsizei max_count = static_cast<GLsizei>(args.I32());
        const uint32_t count_address = args.Ptr();
        const uint32_t shaders_address = args.Ptr();
        bool count_valid = false;
        GLsizei* count = OptionalGuestOutput<GLsizei>(
            host, count_address, 1, "glGetAttachedShaders", &count_valid);
        if (!count_valid) return;
        GLuint* shaders = nullptr;
        if (max_count > 0) {
            shaders = GuestOutputArray<GLuint>(
                host, shaders_address, static_cast<size_t>(max_count), 1,
                "glGetAttachedShaders");
            if (!shaders) return;
        }
        glGetAttachedShaders(program, max_count, count, shaders);
    });
    manager.RegisterThunk("glGetBufferParameteriv", [](Dynarmic::A32::Jit& jit,
                                                  DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        GLint* params = GuestOutputArray<GLint>(
            host, args.Ptr(), 1, 1, "glGetBufferParameteriv");
        if (!params) return;
        glGetBufferParameteriv(target, pname, params);
    });
    manager.RegisterThunk("glGetFloatv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum pname = static_cast<GLenum>(args.U32());
        const size_t count = GetFloatStateValueCount(pname);
        GLfloat* data = GuestOutputArray<GLfloat>(
            host, args.Ptr(), count, 1, "glGetFloatv");
        if (!data) return;
        glGetFloatv(pname, data);
    });
    manager.RegisterThunk("glGetShaderPrecisionFormat", [](Dynarmic::A32::Jit& jit,
                                                      DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum shader_type = static_cast<GLenum>(args.U32());
        const GLenum precision_type = static_cast<GLenum>(args.U32());
        GLint* range = GuestOutputArray<GLint>(
            host, args.Ptr(), 2, 1, "glGetShaderPrecisionFormat");
        GLint* precision = GuestOutputArray<GLint>(
            host, args.Ptr(), 1, 1, "glGetShaderPrecisionFormat");
        if (!range || !precision) return;
        glGetShaderPrecisionFormat(shader_type, precision_type, range, precision);
    });
    manager.RegisterThunk("glGetShaderSource", [](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint shader = static_cast<GLuint>(args.U32());
        const GLsizei buffer_size = static_cast<GLsizei>(args.I32());
        const uint32_t length_address = args.Ptr();
        const uint32_t source_address = args.Ptr();
        bool length_valid = false;
        GLsizei* length = OptionalGuestOutput<GLsizei>(
            host, length_address, 1, "glGetShaderSource", &length_valid);
        if (!length_valid) return;
        GLchar* source = nullptr;
        if (buffer_size > 0) {
            source = GuestOutputArray<GLchar>(
                host, source_address, static_cast<size_t>(buffer_size), 1,
                "glGetShaderSource");
            if (!source) return;
        }
        glGetShaderSource(shader, buffer_size, length, source);
    });
    manager.RegisterThunk("glGetTexParameterfv", [](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        GLfloat* params = GuestOutputArray<GLfloat>(
            host, args.Ptr(), 1, 1, "glGetTexParameterfv");
        if (!params) return;
        glGetTexParameterfv(target, pname, params);
    });
    manager.RegisterThunk("glGetTexParameteriv", [](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        GLint* params = GuestOutputArray<GLint>(
            host, args.Ptr(), 1, 1, "glGetTexParameteriv");
        if (!params) return;
        glGetTexParameteriv(target, pname, params);
    });
    manager.RegisterThunk("glGetUniformfv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint program = static_cast<GLuint>(args.U32());
        const GLint location = static_cast<GLint>(args.I32());
        // A single GLES2 uniform location contains at most one mat4 (16 scalars).
        GLfloat* params = GuestOutputArray<GLfloat>(
            host, args.Ptr(), 16, 1, "glGetUniformfv");
        if (!params) return;
        glGetUniformfv(program, location, params);
    });
    manager.RegisterThunk("glGetUniformiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint program = static_cast<GLuint>(args.U32());
        const GLint location = static_cast<GLint>(args.I32());
        GLint* params = GuestOutputArray<GLint>(
            host, args.Ptr(), 16, 1, "glGetUniformiv");
        if (!params) return;
        glGetUniformiv(program, location, params);
    });
    manager.RegisterThunk("glGetVertexAttribfv", [](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        GLfloat* params = GuestOutputArray<GLfloat>(
            host, args.Ptr(), GetVertexAttribValueCount(pname), 1,
            "glGetVertexAttribfv");
        if (!params) return;
        glGetVertexAttribfv(index, pname, params);
    });
    manager.RegisterThunk("glGetVertexAttribiv", [](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        GLint* params = GuestOutputArray<GLint>(
            host, args.Ptr(), GetVertexAttribValueCount(pname), 1,
            "glGetVertexAttribiv");
        if (!params) return;
        glGetVertexAttribiv(index, pname, params);
    });
    manager.RegisterThunk("glGetVertexAttribPointerv", [](Dynarmic::A32::Jit& jit,
                                                     DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        uint32_t* guest_pointer = GuestOutputArray<uint32_t>(
            host, args.Ptr(), 1, 1, "glGetVertexAttribPointerv");
        if (!guest_pointer) return;
        void* host_pointer = nullptr;
        GLint array_buffer_binding = 0;
        glGetVertexAttribPointerv(index, pname, &host_pointer);
        glGetVertexAttribiv(index, GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING,
                            &array_buffer_binding);
        *guest_pointer = HostVertexPointerToGuest(
            host, host_pointer, array_buffer_binding);
    });

    manager.RegisterThunk("glIsBuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(glIsBuffer(static_cast<GLuint>(args.U32())));
    });
    manager.RegisterThunk("glIsEnabled", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(glIsEnabled(static_cast<GLenum>(args.U32())));
    });
    manager.RegisterThunk("glIsFramebuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(
            glIsFramebuffer(static_cast<GLuint>(args.U32())));
    });
    manager.RegisterThunk("glIsProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(glIsProgram(static_cast<GLuint>(args.U32())));
    });
    manager.RegisterThunk("glIsRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(
            glIsRenderbuffer(static_cast<GLuint>(args.U32())));
    });
    manager.RegisterThunk("glIsShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(glIsShader(static_cast<GLuint>(args.U32())));
    });
    manager.RegisterThunk("glIsTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        jit.Regs()[0] = static_cast<uint32_t>(glIsTexture(static_cast<GLuint>(args.U32())));
    });
    manager.RegisterThunk("glReleaseShaderCompiler", [](Dynarmic::A32::Jit&, DynarmicHost&) {
        glReleaseShaderCompiler();
    });
    manager.RegisterThunk("glSampleCoverage", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLfloat value = args.F32();
        const GLboolean invert = static_cast<GLboolean>(args.U32());
        glSampleCoverage(value, invert);
    });

    manager.RegisterThunk("glStencilFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum function = static_cast<GLenum>(args.U32());
        const GLint reference = static_cast<GLint>(args.I32());
        const GLuint mask = static_cast<GLuint>(args.U32());
        glStencilFunc(function, reference, mask);
    });
    manager.RegisterThunk("glStencilFuncSeparate", [](Dynarmic::A32::Jit& jit,
                                                 DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum face = static_cast<GLenum>(args.U32());
        const GLenum function = static_cast<GLenum>(args.U32());
        const GLint reference = static_cast<GLint>(args.I32());
        const GLuint mask = static_cast<GLuint>(args.U32());
        glStencilFuncSeparate(face, function, reference, mask);
    });
    manager.RegisterThunk("glStencilMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glStencilMask(static_cast<GLuint>(args.U32()));
    });
    manager.RegisterThunk("glStencilMaskSeparate", [](Dynarmic::A32::Jit& jit,
                                                 DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum face = static_cast<GLenum>(args.U32());
        const GLuint mask = static_cast<GLuint>(args.U32());
        glStencilMaskSeparate(face, mask);
    });
    manager.RegisterThunk("glStencilOp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum fail = static_cast<GLenum>(args.U32());
        const GLenum depth_fail = static_cast<GLenum>(args.U32());
        const GLenum depth_pass = static_cast<GLenum>(args.U32());
        glStencilOp(fail, depth_fail, depth_pass);
    });
    manager.RegisterThunk("glStencilOpSeparate", [](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum face = static_cast<GLenum>(args.U32());
        const GLenum stencil_fail = static_cast<GLenum>(args.U32());
        const GLenum depth_fail = static_cast<GLenum>(args.U32());
        const GLenum depth_pass = static_cast<GLenum>(args.U32());
        glStencilOpSeparate(face, stencil_fail, depth_fail, depth_pass);
    });
    manager.RegisterThunk("glTexParameterfv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLenum pname = static_cast<GLenum>(args.U32());
        const GLfloat* params = GuestInputArray<GLfloat>(
            host, args.Ptr(), 1, 1, "glTexParameterfv");
        if (!params) return;
        glTexParameterfv(target, pname, params);
    });

    manager.RegisterThunk("glUniform1fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLfloat* value = CountedGuestValues<GLfloat>(
            host, value_address, count, 1, "glUniform1fv", &valid);
        if (!valid) return;
        glUniform1fv(location, count, value);
    });
    manager.RegisterThunk("glUniform1iv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLint* value = CountedGuestValues<GLint>(
            host, value_address, count, 1, "glUniform1iv", &valid);
        if (!valid) return;
        glUniform1iv(location, count, value);
    });
    manager.RegisterThunk("glUniform2fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLfloat* value = CountedGuestValues<GLfloat>(
            host, value_address, count, 2, "glUniform2fv", &valid);
        if (!valid) return;
        glUniform2fv(location, count, value);
    });
    manager.RegisterThunk("glUniform2i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLint x = static_cast<GLint>(args.I32());
        const GLint y = static_cast<GLint>(args.I32());
        glUniform2i(location, x, y);
    });
    manager.RegisterThunk("glUniform2iv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLint* value = CountedGuestValues<GLint>(
            host, value_address, count, 2, "glUniform2iv", &valid);
        if (!valid) return;
        glUniform2iv(location, count, value);
    });
    manager.RegisterThunk("glUniform3i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLint x = static_cast<GLint>(args.I32());
        const GLint y = static_cast<GLint>(args.I32());
        const GLint z = static_cast<GLint>(args.I32());
        glUniform3i(location, x, y, z);
    });
    manager.RegisterThunk("glUniform3iv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLint* value = CountedGuestValues<GLint>(
            host, value_address, count, 3, "glUniform3iv", &valid);
        if (!valid) return;
        glUniform3iv(location, count, value);
    });
    manager.RegisterThunk("glUniform4i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLint x = static_cast<GLint>(args.I32());
        const GLint y = static_cast<GLint>(args.I32());
        const GLint z = static_cast<GLint>(args.I32());
        const GLint w = static_cast<GLint>(args.I32());
        glUniform4i(location, x, y, z, w);
    });
    manager.RegisterThunk("glUniform4iv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLint* value = CountedGuestValues<GLint>(
            host, value_address, count, 4, "glUniform4iv", &valid);
        if (!valid) return;
        glUniform4iv(location, count, value);
    });
    manager.RegisterThunk("glUniformMatrix2fv", [](Dynarmic::A32::Jit& jit,
                                              DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint location = static_cast<GLint>(args.I32());
        const GLsizei count = static_cast<GLsizei>(args.I32());
        const GLboolean transpose = static_cast<GLboolean>(args.U32());
        const uint32_t value_address = args.Ptr();
        bool valid = false;
        const GLfloat* value = CountedGuestValues<GLfloat>(
            host, value_address, count, 4, "glUniformMatrix2fv", &valid);
        if (!valid) return;
        glUniformMatrix2fv(location, count, transpose, value);
    });
    manager.RegisterThunk("glValidateProgram", [](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glValidateProgram(static_cast<GLuint>(args.U32()));
    });

    manager.RegisterThunk("glVertexAttrib1f", [](Dynarmic::A32::Jit& jit,
                                           DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat x = args.F32();
        glVertexAttrib1f(index, x);
    });
    manager.RegisterThunk("glVertexAttrib1fv", [](Dynarmic::A32::Jit& jit,
                                            DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat* values = GuestInputArray<GLfloat>(
            host, args.Ptr(), 1, 1, "glVertexAttrib1fv");
        if (!values) return;
        glVertexAttrib1fv(index, values);
    });
    manager.RegisterThunk("glVertexAttrib2f", [](Dynarmic::A32::Jit& jit,
                                           DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat x = args.F32();
        const GLfloat y = args.F32();
        glVertexAttrib2f(index, x, y);
    });
    manager.RegisterThunk("glVertexAttrib2fv", [](Dynarmic::A32::Jit& jit,
                                            DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat* values = GuestInputArray<GLfloat>(
            host, args.Ptr(), 1, 2, "glVertexAttrib2fv");
        if (!values) return;
        glVertexAttrib2fv(index, values);
    });
    manager.RegisterThunk("glVertexAttrib3f", [](Dynarmic::A32::Jit& jit,
                                           DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat x = args.F32();
        const GLfloat y = args.F32();
        const GLfloat z = args.F32();
        glVertexAttrib3f(index, x, y, z);
    });
    manager.RegisterThunk("glVertexAttrib3fv", [](Dynarmic::A32::Jit& jit,
                                            DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat* values = GuestInputArray<GLfloat>(
            host, args.Ptr(), 1, 3, "glVertexAttrib3fv");
        if (!values) return;
        glVertexAttrib3fv(index, values);
    });
    manager.RegisterThunk("glVertexAttrib4f", [](Dynarmic::A32::Jit& jit,
                                           DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat x = args.F32();
        const GLfloat y = args.F32();
        const GLfloat z = args.F32();
        const GLfloat w = args.F32();
        glVertexAttrib4f(index, x, y, z, w);
    });
    manager.RegisterThunk("glVertexAttrib4fv", [](Dynarmic::A32::Jit& jit,
                                            DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLuint index = static_cast<GLuint>(args.U32());
        const GLfloat* values = GuestInputArray<GLfloat>(
            host, args.Ptr(), 1, 4, "glVertexAttrib4fv");
        if (!values) return;
        glVertexAttrib4fv(index, values);
    });

    // These are the entry points resolved by MC4's GL function-pointer set.
    // Keep native signatures and optional availability; never mint dummy GL procs.
    for (const char* name : {"glRenderbufferStorageMultisample", "glRenderbufferStorageMultisampleEXT",
                            "glRenderbufferStorageMultisampleIMG", "glRenderbufferStorageMultisampleANGLE",
                            "glRenderbufferStorageMultisampleAPPLE"}) {
        NativeExtensionThunk<PFNGLRENDERBUFFERSTORAGEMULTISAMPLEEXTPROC>(manager, name,
            [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                Arm32CallArgs args(jit, host.GetGuestMemoryBase());
                const GLenum target = args.U32();
                const GLsizei samples = args.I32();
                const GLenum format = args.U32();
                const GLsizei width = args.I32(), height = args.I32();
                function(target, samples, format, width, height);
            });
    }
    for (const char* name : {"glFramebufferTexture2DMultisampleEXT", "glFramebufferTexture2DMultisampleIMG"}) {
        NativeExtensionThunk<PFNGLFRAMEBUFFERTEXTURE2DMULTISAMPLEEXTPROC>(manager, name,
            [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                Arm32CallArgs args(jit, host.GetGuestMemoryBase());
                const GLenum target = args.U32(), attachment = args.U32(), textarget = args.U32();
                const GLuint texture = args.U32();
                const GLint level = args.I32();
                const GLsizei samples = args.I32();
                function(target, attachment, textarget, texture, level, samples);
            });
    }
    for (const char* name : {"glBlitFramebuffer", "glBlitFramebufferANGLE", "glBlitFramebufferEXT"}) {
        NativeExtensionThunk<PFNGLBLITFRAMEBUFFERANGLEPROC>(manager, name,
            [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                Arm32CallArgs args(jit, host.GetGuestMemoryBase());
                const GLint sx0 = args.I32(), sy0 = args.I32(), sx1 = args.I32(), sy1 = args.I32();
                const GLint dx0 = args.I32(), dy0 = args.I32(), dx1 = args.I32(), dy1 = args.I32();
                const GLbitfield mask = args.U32();
                const GLenum filter = args.U32();
                function(sx0, sy0, sx1, sy1, dx0, dy0, dx1, dy1, mask, filter);
            });
    }
    NativeExtensionThunk<PFNGLRESOLVEMULTISAMPLEFRAMEBUFFERAPPLEPROC>(manager,
        "glResolveMultisampleFramebufferAPPLE", [](auto function, Dynarmic::A32::Jit&, DynarmicHost&) {
            function();
        });
    NativeExtensionThunk<PFNGLDISCARDFRAMEBUFFEREXTPROC>(manager, "glDiscardFramebufferEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLsizei count = args.I32();
            bool valid = false;
            const auto* attachments = CountedGuestValues<GLenum>(
                host, args.Ptr(), count, 1, "glDiscardFramebufferEXT", &valid);
            if (valid) function(target, count, attachments);
        });
    for (const char* name : {"glDrawBuffersNV", "glDrawBuffersARB", "glDrawBuffersEXT"}) {
        NativeExtensionThunk<PFNGLDRAWBUFFERSEXTPROC>(manager, name,
            [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                Arm32CallArgs args(jit, host.GetGuestMemoryBase());
                const GLsizei count = args.I32();
                bool valid = false;
                const auto* buffers = CountedGuestValues<GLenum>(
                    host, args.Ptr(), count, 1, "glDrawBuffers", &valid);
                if (valid) function(count, buffers);
            });
    }
    NativeExtensionThunk<PFNGLREADBUFFERNVPROC>(manager, "glReadBufferNV",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost&) { function(jit.Regs()[0]); });
    NativeExtensionThunk<PFNGLTEXSTORAGE2DEXTPROC>(manager, "glTexStorage2DEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLsizei levels = args.I32();
            const GLenum format = args.U32();
            const GLsizei width = args.I32(), height = args.I32();
            function(target, levels, format, width, height);
        });
    NativeExtensionThunk<PFNGLTEXSTORAGE3DEXTPROC>(manager, "glTexStorage3DEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLsizei levels = args.I32();
            const GLenum format = args.U32();
            const GLsizei width = args.I32(), height = args.I32(), depth = args.I32();
            function(target, levels, format, width, height, depth);
        });
    NativeExtensionThunk<PFNGLGENQUERIESEXTPROC>(manager, "glGenQueriesEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLsizei count = args.I32();
            GLuint* ids = nullptr;
            const uint32_t address = args.Ptr();
            if (count > 0) {
                ids = GuestOutputArray<GLuint>(host, address, static_cast<size_t>(count), 1, "glGenQueriesEXT");
                if (!ids) return;
            }
            function(count, ids);
        });
    NativeExtensionThunk<PFNGLDELETEQUERIESEXTPROC>(manager, "glDeleteQueriesEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLsizei count = args.I32();
            bool valid = false;
            const auto* ids = CountedGuestValues<GLuint>(host, args.Ptr(), count, 1, "glDeleteQueriesEXT", &valid);
            if (valid) function(count, ids);
        });
    NativeExtensionThunk<PFNGLBEGINQUERYEXTPROC>(manager, "glBeginQueryEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost&) { function(jit.Regs()[0], jit.Regs()[1]); });
    NativeExtensionThunk<PFNGLENDQUERYEXTPROC>(manager, "glEndQueryEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost&) { function(jit.Regs()[0]); });
    NativeExtensionThunk<PFNGLGETQUERYOBJECTUIVEXTPROC>(manager, "glGetQueryObjectuivEXT",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            auto* params = GuestOutputArray<GLuint>(host, jit.Regs()[2], 1, 1, "glGetQueryObjectuivEXT");
            if (params) function(jit.Regs()[0], jit.Regs()[1], params);
        });
    NativeExtensionThunk<PFNGLTEXIMAGE3DOESPROC>(manager, "glTexImage3DOES",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLint level = args.I32();
            const GLenum internal = args.U32();
            const GLsizei width = args.I32(), height = args.I32(), depth = args.I32();
            const GLint border = args.I32();
            const GLenum format = args.U32(), type = args.U32();
            bool valid = false;
            const void* pixels = GuestImage3D(host, args.Ptr(), width, height, depth,
                format, type, "glTexImage3DOES", &valid);
            if (valid) function(target, level, internal, width, height, depth, border, format, type, pixels);
        });
    NativeExtensionThunk<PFNGLTEXSUBIMAGE3DOESPROC>(manager, "glTexSubImage3DOES",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLint level = args.I32(), x = args.I32(), y = args.I32(), z = args.I32();
            const GLsizei width = args.I32(), height = args.I32(), depth = args.I32();
            const GLenum format = args.U32(), type = args.U32();
            bool valid = false;
            const void* pixels = GuestImage3D(host, args.Ptr(), width, height, depth,
                format, type, "glTexSubImage3DOES", &valid);
            if (valid) function(target, level, x, y, z, width, height, depth, format, type, pixels);
        });
    NativeExtensionThunk<PFNGLCOMPRESSEDTEXIMAGE3DOESPROC>(manager, "glCompressedTexImage3DOES",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLint level = args.I32();
            const GLenum internal = args.U32();
            const GLsizei width = args.I32(), height = args.I32(), depth = args.I32();
            const GLint border = args.I32();
            const GLsizei bytes = args.I32();
            bool valid = false;
            const void* data = CountedGuestBytes(host, args.Ptr(), bytes, "glCompressedTexImage3DOES", &valid);
            if (valid) function(target, level, internal, width, height, depth, border, bytes, data);
        });
    NativeExtensionThunk<PFNGLCOMPRESSEDTEXSUBIMAGE3DOESPROC>(manager, "glCompressedTexSubImage3DOES",
        [](auto function, Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            Arm32CallArgs args(jit, host.GetGuestMemoryBase());
            const GLenum target = args.U32();
            const GLint level = args.I32(), x = args.I32(), y = args.I32(), z = args.I32();
            const GLsizei width = args.I32(), height = args.I32(), depth = args.I32();
            const GLenum format = args.U32();
            const GLsizei bytes = args.I32();
            bool valid = false;
            const void* data = CountedGuestBytes(host, args.Ptr(), bytes, "glCompressedTexSubImage3DOES", &valid);
            if (valid) function(target, level, x, y, z, width, height, depth, format, bytes, data);
        });
}
