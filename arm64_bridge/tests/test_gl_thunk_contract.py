"""Run the production GL thunk bodies against a deterministic host driver.

This checks guest pointers, context/deletion state and ARM32 scalar ABI. A real
GPU and same-camera captures remain required for visual acceptance.
"""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "thunks_gl.cpp").read_text(encoding="utf-8")
CORE = (ROOT / "src" / "thunks_gl_gles2_core.cpp").read_text(encoding="utf-8")
HOST = (ROOT / "src" / "dynarmic_host.cpp").read_text(encoding="utf-8")


def thunk(name: str) -> str:
    start = SOURCE.index(f'RegisterThunk("{name}",')
    end = SOURCE.index("\n    });", start) + len("\n    });")
    return SOURCE[start:end]


def observer_probe(name: str) -> str:
    start = HOST.index(f'm_thunk_manager->RegisterThunk("{name}",')
    end_marker = "\n                    });"
    end = HOST.index(end_marker, start) + len(end_marker)
    return HOST[start:end].replace("m_thunk_manager->RegisterThunk", "manager.RegisterThunk")


PRELUDE = r"""
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "thunk_types.h"
#include "thunks_glstat.h"
#define KHRONOS_STATIC 1
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl3.h>
#include <GLES3/gl31.h>
using EGLContext = uintptr_t;
using ssize_t = intptr_t;
constexpr EGLContext EGL_NO_CONTEXT = 0;
constexpr int ANDROID_LOG_INFO = 4, ANDROID_LOG_ERROR = 6;
int __android_log_print(int, const char*, const char*, ...) { return 0; }
struct DriverState {
    GLuint array = 0, element = 0, framebuffer = 0, program = 0;
    GLenum active_texture = GL_TEXTURE0;
};
std::unordered_map<EGLContext, DriverState> driver;
EGLContext current_context = 1;
unsigned binding_queries = 0;
const void* seen_pointer = nullptr;
std::array<GLint, 4> seen_viewport{};
GLsizeiptr seen_size = 0; GLintptr seen_offset = 0;
std::array<float, 4> seen_uniform{};
std::array<uint8_t, 64> driver_bytes{};
std::array<uint8_t, 64> oes_write_view{};
unsigned string_calls = 0;
unsigned range_calls = 0, oes_calls = 0;
unsigned sky_source_queries = 0, sky_uniform_queries = 0;
unsigned sky_constant_queries = 0, sky_level_queries = 0;
bool sky_texture_unbound = false;
GLint sky_bound_texture_override = -1;
GLint sky_read_samples = 0, sky_read_pack_buffer = 0, sky_read_row_length = 0;
GLint sky_read_skip_rows = 0, sky_read_skip_pixels = 0, sky_read_framebuffer = -1;
GLint sky_read_buffer = -1;
GLint sky_read_format = GL_RGBA, sky_read_type = GL_UNSIGNED_BYTE;
unsigned sky_read_calls = 0, sky_read_gl3_pack_queries = 0;
bool sky_read_complete = true;
uintptr_t sky_attribute_pointer = 0;
GLint native_buffer_size = 64;
bool fail_next_buffer_data = false;
GLbitfield seen_access = 0;
void* last_mapping_pointer = nullptr;
EGLContext eglGetCurrentContext() { return current_context; }
const GLubyte* glGetString(GLenum name) {
    ++string_calls;
    if (name == GL_EXTENSIONS)
        return reinterpret_cast<const GLubyte*>(current_context == 4
            ? "GL_OES_mapbuffer GL_EXT_map_buffer_range"
            : current_context == 3 ? "GL_OES_mapbuffer" : "");
    if (name != GL_VERSION) return nullptr;
    return reinterpret_cast<const GLubyte*>(current_context == 1 ? "OpenGL ES 3.2" :
        current_context == 5 ? "OpenGL ES 3.0" : "OpenGL ES 2.0");
}
void glGetIntegerv(GLenum pname, GLint* value) {
    ++binding_queries;
    const auto& state = driver[current_context];
    if (pname == GL_ARRAY_BUFFER_BINDING) *value = state.array;
    else if (pname == GL_ELEMENT_ARRAY_BUFFER_BINDING) *value = state.element;
    else if (pname == GL_FRAMEBUFFER_BINDING) *value = state.framebuffer;
    else if (pname == GL_CURRENT_PROGRAM) *value = state.program;
    else if (pname == GL_UNPACK_ALIGNMENT) *value = 4;
    else if (pname == GL_MAX_VERTEX_ATTRIBS) *value = 8;
    else if (pname == GL_DEPTH_WRITEMASK) *value = GL_FALSE;
    else if (pname == GL_DEPTH_FUNC) *value = GL_LEQUAL;
    else if (pname == GL_BLEND_SRC_RGB) *value = GL_SRC_ALPHA;
    else if (pname == GL_BLEND_DST_RGB) *value = GL_ONE_MINUS_SRC_ALPHA;
    else if (pname == GL_ACTIVE_TEXTURE) *value = static_cast<GLint>(state.active_texture);
    else if (pname == GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS) *value = 8;
    else if (pname == GL_TEXTURE_BINDING_2D) *value = sky_bound_texture_override >= 0 ?
        sky_bound_texture_override : sky_texture_unbound ? 0 :
        100 + static_cast<GLint>(state.active_texture - GL_TEXTURE0);
    else if (pname == GL_CULL_FACE_MODE) *value = GL_BACK;
    else if (pname == GL_FRONT_FACE) *value = GL_CW;
    else if (pname == GL_VIEWPORT || pname == GL_SCISSOR_BOX) {
        value[0]=value[1]=0;value[2]=value[3]=16;
    }
    else if (pname == GL_COLOR_WRITEMASK) std::fill(value,value+4,GL_TRUE);
    else if (pname == GL_STENCIL_CLEAR_VALUE) *value=0;
    else if (pname == GL_STENCIL_FUNC || pname == GL_STENCIL_BACK_FUNC) *value=GL_ALWAYS;
    else if (pname == GL_STENCIL_REF || pname == GL_STENCIL_BACK_REF) *value=0;
    else if (pname == GL_STENCIL_VALUE_MASK || pname == GL_STENCIL_WRITEMASK ||
             pname == GL_STENCIL_BACK_VALUE_MASK || pname == GL_STENCIL_BACK_WRITEMASK) *value=255;
    else if (pname == GL_STENCIL_FAIL || pname == GL_STENCIL_PASS_DEPTH_FAIL || pname == GL_STENCIL_PASS_DEPTH_PASS ||
             pname == GL_STENCIL_BACK_FAIL || pname == GL_STENCIL_BACK_PASS_DEPTH_FAIL || pname == GL_STENCIL_BACK_PASS_DEPTH_PASS) *value=GL_KEEP;
    else if (pname == GL_SAMPLES) *value=sky_read_samples;
    else if (pname == GL_PACK_ALIGNMENT) *value=8;
    else if (pname == GL_IMPLEMENTATION_COLOR_READ_FORMAT) *value=sky_read_format;
    else if (pname == GL_IMPLEMENTATION_COLOR_READ_TYPE) *value=sky_read_type;
    else if (pname == GL_READ_FRAMEBUFFER_BINDING || pname == GL_READ_BUFFER || pname == GL_PIXEL_PACK_BUFFER_BINDING ||
             pname == GL_PACK_ROW_LENGTH || pname == GL_PACK_SKIP_ROWS || pname == GL_PACK_SKIP_PIXELS) {
        if (current_context==3 || current_context==4) std::abort();
        ++sky_read_gl3_pack_queries;
        *value=pname==GL_READ_FRAMEBUFFER_BINDING ? (sky_read_framebuffer<0 ? state.framebuffer : sky_read_framebuffer) :
            pname==GL_READ_BUFFER ? (sky_read_buffer<0 ? (state.framebuffer ? GL_COLOR_ATTACHMENT0 : GL_BACK) : sky_read_buffer) :
            pname==GL_PIXEL_PACK_BUFFER_BINDING ? sky_read_pack_buffer : pname==GL_PACK_ROW_LENGTH ? sky_read_row_length :
            pname==GL_PACK_SKIP_ROWS ? sky_read_skip_rows : sky_read_skip_pixels;
    }
    else std::abort();
}
void glGetFloatv(GLenum pname, GLfloat* value) {
    if (pname == GL_DEPTH_RANGE) { value[0] = .97f; value[1] = .99f; }
    else if (pname == GL_DEPTH_CLEAR_VALUE) *value=1;
    else if (pname == GL_COLOR_CLEAR_VALUE) std::fill(value,value+4,0.f);
    else if (pname == GL_POLYGON_OFFSET_FACTOR || pname == GL_POLYGON_OFFSET_UNITS) *value=0;
    else std::abort();
}
GLenum glCheckFramebufferStatus(GLenum target) {
    if(target!=GL_FRAMEBUFFER) std::abort();
    return sky_read_complete ? GL_FRAMEBUFFER_COMPLETE : GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT;
}
void glGetFramebufferAttachmentParameteriv(GLenum target, GLenum attachment, GLenum name, GLint* value) {
    if(target!=GL_FRAMEBUFFER) std::abort();
    if(name==GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE) *value=attachment==GL_COLOR_ATTACHMENT0 ? GL_TEXTURE : GL_RENDERBUFFER;
    else if(name==GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME) *value=31;
    else if(name==GL_FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE) *value=24;
    else if(name==GL_FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE) *value=8;
    else std::abort();
}
void glReadPixels(GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, void* raw) {
    if((format!=GL_RGBA && format!=GL_BGRA_EXT) || type!=GL_UNSIGNED_BYTE) std::abort();
    ++sky_read_calls;
    auto* data=static_cast<uint8_t*>(raw);
    for(GLsizei row=0;row<height;++row) for(GLsizei column=0;column<width;++column) {
        uint8_t* pixel=data+(static_cast<size_t>(row)*width+column)*4;
        pixel[format==GL_RGBA ? 0 : 2]=static_cast<uint8_t>(x+column);
        pixel[1]=static_cast<uint8_t>(y+row);
        pixel[format==GL_RGBA ? 2 : 0]=128;pixel[3]=255;
    }
}
void glBindBuffer(GLenum target, GLuint buffer) {
    if (target == GL_ARRAY_BUFFER) driver[current_context].array = buffer;
    if (target == GL_ELEMENT_ARRAY_BUFFER) driver[current_context].element = buffer;
}
void glBindFramebuffer(GLenum target, GLuint buffer) {
    if (target == GL_FRAMEBUFFER || target == GL_DRAW_FRAMEBUFFER)
        driver[current_context].framebuffer = buffer;
}
void glDeleteBuffers(GLsizei count, const GLuint* buffers) {
    for (GLsizei i = 0; i < count; ++i) {
        auto& state = driver[current_context];
        if (state.array == buffers[i]) state.array = 0;
        if (state.element == buffers[i]) state.element = 0;
    }
}
void glDeleteFramebuffers(GLsizei count, const GLuint* buffers) {
    for (GLsizei i = 0; i < count; ++i)
        if (driver[current_context].framebuffer == buffers[i])
            driver[current_context].framebuffer = 0;
}
void glDrawElements(GLenum, GLsizei, GLenum, const void* pointer) { seen_pointer = pointer; }
void glVertexAttribPointer(GLuint, GLint, GLenum, GLboolean, GLsizei, const void* pointer) {
    seen_pointer = pointer;
}
void glViewport(GLint x, GLint y, GLsizei width, GLsizei height) {
    seen_viewport = {x, y, width, height};
}
void glBufferData(GLenum, GLsizeiptr size, const void* data, GLenum) {
    seen_size = size;
    if (fail_next_buffer_data) { fail_next_buffer_data = false; return; }
    if (size < 0 || size > static_cast<GLsizeiptr>(driver_bytes.size())) return;
    native_buffer_size = static_cast<GLint>(size);
    if (data) std::memcpy(driver_bytes.data(), data, static_cast<size_t>(size));
}
void glBufferSubData(GLenum, GLintptr offset, GLsizeiptr size, const void* data) {
    seen_offset = offset; seen_size = size;
    if (data && offset >= 0 && size >= 0 && offset <= native_buffer_size &&
        size <= native_buffer_size - offset)
        std::memcpy(driver_bytes.data() + offset, data, static_cast<size_t>(size));
}
void glUniform4f(GLint, float x, float y, float z, float w) { seen_uniform = {x, y, z, w}; }
GLint glGetUniformLocation(GLuint, const GLchar*) { return 17; }
GLboolean glIsEnabled(GLenum name) { return name == GL_DEPTH_TEST ? GL_TRUE : GL_FALSE; }
void glGetProgramiv(GLuint, GLenum name, GLint* value) {
    if (name == GL_LINK_STATUS) *value = GL_TRUE;
    else if (name == GL_ACTIVE_UNIFORMS) *value = 2;
    else if (name == GL_ACTIVE_ATTRIBUTES) *value = 3;
    else std::abort();
}
void glGetAttachedShaders(GLuint program, GLsizei size, GLsizei* count, GLuint* shaders) {
    if (size < 2) std::abort();
    *count = 2; shaders[0] = program * 2; shaders[1] = program * 2 + 1;
}
void glGetShaderiv(GLuint shader, GLenum name, GLint* value) {
    if (name == GL_SHADER_SOURCE_LENGTH) *value = 1025;
    else if (name == GL_SHADER_TYPE) *value = shader & 1 ? GL_FRAGMENT_SHADER : GL_VERTEX_SHADER;
    else std::abort();
}
void glGetShaderSource(GLuint, GLsizei size, GLsizei* length, GLchar* source) {
    ++sky_source_queries;
    *length = std::min(size - 1, GLsizei{1024});
    std::memset(source, 'x', static_cast<size_t>(*length)); source[*length] = 0;
}
void glGetActiveUniform(GLuint, GLuint index, GLsizei size, GLsizei* length,
                        GLint* count, GLenum* type, GLchar* name) {
    const char* text = index ? "SkySampler" : "cameraMatrix";
    *length = static_cast<GLsizei>(std::strlen(text));
    if (size <= *length) std::abort();
    std::memcpy(name, text, static_cast<size_t>(*length) + 1);
    *count = 1; *type = index ? GL_SAMPLER_2D : GL_FLOAT_MAT4;
}
void glGetUniformfv(GLuint, GLint, GLfloat* value) {
    ++sky_uniform_queries;
    for (int i=0;i<16;++i) value[i]=i%5==0 ? 1.0f : 0.0f;
}
void glGetUniformiv(GLuint, GLint, GLint* value) { ++sky_uniform_queries; *value=2; }
void glGetActiveAttrib(GLuint, GLuint index, GLsizei size, GLsizei* length,
                       GLint* count, GLenum* type, GLchar* name) {
    const char* text = index == 0 ? "Vertex" : index == 1 ? "TexCoord0" : "Color";
    *length = static_cast<GLsizei>(std::strlen(text));
    if (size <= *length) std::abort();
    std::memcpy(name, text, static_cast<size_t>(*length) + 1);
    *count = 1; *type = index == 1 ? GL_FLOAT_VEC2 : GL_FLOAT_VEC4;
}
GLint glGetAttribLocation(GLuint, const GLchar* name) {
    return std::strcmp(name,"Vertex")==0 ? 0 : std::strcmp(name,"Color")==0 ? 2 : 1;
}
void glGetVertexAttribiv(GLuint index, GLenum name, GLint* value) {
    if (name == GL_VERTEX_ATTRIB_ARRAY_ENABLED) *value = index == 0;
    else if (name == GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING) *value = 0;
    else if (name == GL_VERTEX_ATTRIB_ARRAY_SIZE) *value = 3;
    else if (name == GL_VERTEX_ATTRIB_ARRAY_TYPE) *value = GL_FLOAT;
    else if (name == GL_VERTEX_ATTRIB_ARRAY_STRIDE) *value = 16;
    else if (name == GL_VERTEX_ATTRIB_ARRAY_NORMALIZED) *value = GL_FALSE;
    else std::abort();
}
void glGetVertexAttribPointerv(GLuint, GLenum, void** pointer) {
    *pointer = reinterpret_cast<void*>(sky_attribute_pointer);
}
void glGetVertexAttribfv(GLuint, GLenum name, GLfloat* values) {
    if (name != GL_CURRENT_VERTEX_ATTRIB) std::abort();
    ++sky_constant_queries;
    std::fill_n(values,4,1.0f);
}
void glActiveTexture(GLenum unit) { driver[current_context].active_texture = unit; }
void glGetTexParameteriv(GLenum, GLenum name, GLint* value) {
    *value = name == GL_TEXTURE_WRAP_S || name == GL_TEXTURE_WRAP_T ? GL_REPEAT : GL_LINEAR;
}
void NativeTextureLevel(GLenum, GLint, GLenum name, GLint* value) {
    if (current_context != 1) std::abort();
    ++sky_level_queries;
    *value = name == GL_TEXTURE_INTERNAL_FORMAT ? GL_ETC1_RGB8_OES : 512;
}
void glGetBufferParameteriv(GLenum, GLenum name, GLint* size) {
    *size = name==GL_BUFFER_MAPPED ? (last_mapping_pointer ? GL_TRUE : GL_FALSE) : native_buffer_size;
}
void* glMapBufferRange(GLenum, GLintptr offset, GLsizeiptr length, GLbitfield access) {
    ++range_calls;
    if (current_context == 3) std::abort(); // Non-null proc address, unsupported ES2 range API.
    seen_offset = offset; seen_size = length; seen_access = access;
    if (offset < 0 || length <= 0 || offset + length > static_cast<GLintptr>(driver_bytes.size())) return nullptr;
    return last_mapping_pointer = driver_bytes.data() + offset;
}
void* glMapBufferOES(GLenum, GLenum access) {
    if (current_context != 3 && current_context != 4) std::abort();
    if (access != GL_WRITE_ONLY_OES) std::abort();
    ++oes_calls;
    oes_write_view.fill(0xef); // Reads from a write-only mapping cannot supply old GPU bytes.
    return last_mapping_pointer = oes_write_view.data();
}
GLboolean glUnmapBuffer(GLenum) {
    if (last_mapping_pointer == oes_write_view.data()) driver_bytes = oes_write_view;
    last_mapping_pointer = nullptr;
    return GL_TRUE;
}
void glGetBufferPointerv(GLenum, GLenum, void** pointer) { *pointer = last_mapping_pointer; }
void glFlushMappedBufferRange(GLenum, GLintptr offset, GLsizeiptr length) {
    seen_offset = offset; seen_size = length;
}
using NativeProc = void(*)();
unsigned native_calls = 0;
std::vector<int64_t> native_args;
void NativeStorage(GLenum target, GLsizei count, GLenum format, GLsizei width, GLsizei height) {
    ++native_calls; native_args = {target, count, format, width, height};
}
void NativeStorage3D(GLenum target, GLsizei count, GLenum format, GLsizei width, GLsizei height, GLsizei depth) {
    ++native_calls; native_args = {target, count, format, width, height, depth};
}
void NativeAttachment(GLenum target, GLenum attachment, GLenum textarget, GLuint texture, GLint level, GLsizei samples) {
    ++native_calls; native_args = {target, attachment, textarget, texture, level, samples};
}
void NativeBlit(GLint a, GLint b, GLint c, GLint d, GLint e, GLint f, GLint g, GLint h, GLbitfield mask, GLenum filter) {
    ++native_calls; native_args = {a,b,c,d,e,f,g,h,mask,filter};
}
void NativeDiscard(GLenum target, GLsizei count, const GLenum* ptr) {
    ++native_calls; native_args = {target,count}; seen_pointer = ptr;
}
void NativeDrawBuffers(GLsizei count, const GLenum* ptr) {
    ++native_calls; native_args = {count}; seen_pointer = ptr;
}
void NativeGenQueries(GLsizei count, GLuint* ptr) {
    ++native_calls; for (GLsizei i=0; i<count; ++i) ptr[i]=101+i;
}
void NativeDeleteQueries(GLsizei count, const GLuint* ptr) {
    ++native_calls; native_args={count}; seen_pointer=ptr;
}
void NativeGetQuery(GLuint id, GLenum pname, GLuint* ptr) {
    ++native_calls; native_args={id,pname}; *ptr=1;
}
void NativeBeginQuery(GLenum target, GLuint id) { ++native_calls; native_args={target,id}; }
void NativeEndQuery(GLenum target) { ++native_calls; native_args={target}; }
void NativeImage3D(GLenum a, GLint b, GLenum c, GLsizei d, GLsizei e, GLsizei f, GLint g, GLenum h, GLenum i, const void* ptr) {
    ++native_calls; native_args={a,b,c,d,e,f,g,h,i}; seen_pointer=ptr;
}
void NativeSubImage3D(GLenum a, GLint b, GLint c, GLint d, GLint e, GLsizei f, GLsizei g, GLsizei h, GLenum i, GLenum j, const void* ptr) {
    ++native_calls; native_args={a,b,c,d,e,f,g,h,i,j}; seen_pointer=ptr;
}
void NativeCompressed3D(GLenum a, GLint b, GLenum c, GLsizei d, GLsizei e, GLsizei f, GLint g, GLsizei h, const void* ptr) {
    ++native_calls; native_args={a,b,c,d,e,f,g,h}; seen_pointer=ptr;
}
void NativeCompressedSub3D(GLenum a, GLint b, GLint c, GLint d, GLint e, GLsizei f, GLsizei g, GLsizei h, GLenum i, GLsizei j, const void* ptr) {
    ++native_calls; native_args={a,b,c,d,e,f,g,h,i,j}; seen_pointer=ptr;
}
void NativeNoArgs() { ++native_calls; }
NativeProc eglGetProcAddress(const char* raw) {
    const std::string name(raw);
    if (name=="glMapBufferOES") return reinterpret_cast<NativeProc>(glMapBufferOES);
    if (name=="glGetTexLevelParameteriv") return reinterpret_cast<NativeProc>(NativeTextureLevel);
    if (name=="glMapBufferRangeEXT") return reinterpret_cast<NativeProc>(glMapBufferRange);
    if (name=="glUnmapBufferOES") return reinterpret_cast<NativeProc>(glUnmapBuffer);
    if (name=="glGetBufferPointervOES") return reinterpret_cast<NativeProc>(glGetBufferPointerv);
    if (name=="glFlushMappedBufferRangeEXT") return reinterpret_cast<NativeProc>(glFlushMappedBufferRange);
    if (name.find("glRenderbufferStorageMultisample")==0 || name=="glTexStorage2DEXT") return reinterpret_cast<NativeProc>(NativeStorage);
    if (name=="glTexStorage3DEXT") return reinterpret_cast<NativeProc>(NativeStorage3D);
    if (name.find("glFramebufferTexture2DMultisample")==0) return reinterpret_cast<NativeProc>(NativeAttachment);
    if (name.find("glBlitFramebuffer")==0) return reinterpret_cast<NativeProc>(NativeBlit);
    if (name=="glDiscardFramebufferEXT") return reinterpret_cast<NativeProc>(NativeDiscard);
    if (name=="glDrawBuffersEXT") return reinterpret_cast<NativeProc>(NativeDrawBuffers);
    if (name=="glGenQueriesEXT") return reinterpret_cast<NativeProc>(NativeGenQueries);
    if (name=="glDeleteQueriesEXT") return reinterpret_cast<NativeProc>(NativeDeleteQueries);
    if (name=="glBeginQueryEXT") return reinterpret_cast<NativeProc>(NativeBeginQuery);
    if (name=="glEndQueryEXT") return reinterpret_cast<NativeProc>(NativeEndQuery);
    if (name=="glGetQueryObjectuivEXT") return reinterpret_cast<NativeProc>(NativeGetQuery);
    if (name=="glTexImage3DOES") return reinterpret_cast<NativeProc>(NativeImage3D);
    if (name=="glTexSubImage3DOES") return reinterpret_cast<NativeProc>(NativeSubImage3D);
    if (name=="glCompressedTexImage3DOES") return reinterpret_cast<NativeProc>(NativeCompressed3D);
    if (name=="glCompressedTexSubImage3DOES") return reinterpret_cast<NativeProc>(NativeCompressedSub3D);
    if (name=="glResolveMultisampleFramebufferAPPLE" || name=="glNativeButUnbridged") return NativeNoArgs;
    return nullptr;
}
struct ThunkManager;
struct DynarmicHost {
    std::array<uint8_t, 1 << 20> memory{};
    uint32_t allocation = 0x4000;
    unsigned active_maps = 0;
    ThunkManager* manager = nullptr;
    ThunkManager& GetThunkManager() { return *manager; }
    uint8_t* GetGuestMemoryBase() { return memory.data(); }
    size_t GetGuestMemorySize() { return memory.size(); }
    uint32_t MemoryRead32(uint32_t address) {
        uint32_t value; std::memcpy(&value, memory.data() + address, 4); return value;
    }
    uint32_t GuestAlloc(size_t size, size_t = 8) {
        const uint32_t result = allocation; allocation += static_cast<uint32_t>(size);
        ++active_maps; return result;
    }
    void GuestFree(uint32_t) { --active_maps; }
};
struct ThunkManager {
    using Handler = std::function<void(Dynarmic::A32::Jit&, DynarmicHost&)>;
    std::unordered_map<std::string, Handler> handlers;
    static inline uint32_t s_virtualWidth = 100, s_virtualHeight = 50;
    static inline uint32_t s_screenWidth = 200, s_screenHeight = 100;
    void RegisterThunk(const char* name, Handler handler) { handlers[name] = handler; }
    uint32_t FindThunkAddress(const char* name) { return handlers.count(name) ? 0x9000 : 0; }
    void RegisterGLThunks();
};
uint32_t Invoke(ThunkManager& manager, DynarmicHost& host, const char* name,
                std::initializer_list<uint32_t> values) {
    Dynarmic::A32::Jit jit;
    jit.Regs()[13] = 0x100;
    unsigned index = 0;
    for (uint32_t value : values) {
        if (index < 4) jit.Regs()[index] = value;
        else std::memcpy(host.memory.data() + 0x100 + (index - 4) * 4, &value, 4);
        ++index;
    }
    manager.handlers.at(name)(jit, host);
    return jit.Regs()[0];
}
uint32_t FloatBits(float value) { uint32_t result; std::memcpy(&result, &value, 4); return result; }
#if MC4_ENABLE_NATIVE_LOGGING
std::unordered_map<FILE*,std::string> sky_dump_files;
std::vector<std::pair<std::string,std::vector<uint8_t>>> sky_dump_results;
bool sky_dump_open_fails = false;
FILE* SkyTestFopen(const char* filename, const char* mode) {
    static constexpr char directory[] = "/sdcard/Android/data/com.gameloft.android.ANMP.GloftM4HM/files/";
    if (std::strncmp(filename,directory,sizeof(directory)-1) ||
        std::strcmp(mode,"wb")) std::abort();
    if (sky_dump_open_fails) return nullptr;
    FILE* result = std::tmpfile();
    if (!result) std::abort();
    sky_dump_files[result] = filename;
    return result;
}
int SkyTestFclose(FILE* file) {
    std::fflush(file);
    const long length = std::ftell(file);
    if (length < 0) std::abort();
    std::rewind(file);
    std::vector<uint8_t> data(static_cast<size_t>(length));
    if (std::fread(data.data(),1,data.size(),file) != data.size()) std::abort();
    sky_dump_results.push_back({sky_dump_files.at(file),std::move(data)});
    sky_dump_files.erase(file);
    return std::fclose(file);
}
#define fopen SkyTestFopen
#define fclose SkyTestFclose
#endif
#define CHECK(condition, message) do { if (!(condition)) { std::fprintf(stderr, "%s\n", message); return 1; } } while (false)
"""

CHECKS = r"""
int main() {
    ThunkManager manager; manager.RegisterGLThunks();
    static DynarmicHost host;
    host.manager = &manager;
    const auto client_pointer = host.memory.data() + 0x800;
    const auto offset_pointer = reinterpret_cast<const void*>(uintptr_t{0x800});
    auto draw = [&] { Invoke(manager, host, "glDrawElements", {4, 3, 0x1403, 0x800}); };
    auto attrib = [&] { Invoke(manager, host, "glVertexAttribPointer", {0, 3, 0x1406, 0, 12, 0x800}); };
    auto viewport = [&] { Invoke(manager, host, "glViewport", {1, 2, 50, 25}); };
    GLuint names[2] = {11, 12}; std::memcpy(client_pointer, names, sizeof(names));
    Invoke(manager, host, "glBindBuffer", {GL_ARRAY_BUFFER, 11});
    Invoke(manager, host, "glBindBuffer", {GL_ELEMENT_ARRAY_BUFFER, 12});
    draw(); CHECK(seen_pointer == offset_pointer, "bound EBO must receive an offset");
    attrib(); CHECK(seen_pointer == offset_pointer, "bound VBO must receive an offset");
    Invoke(manager, host, "glDeleteBuffers", {2, 0x800});
    draw(); CHECK(seen_pointer == client_pointer, "deleting current EBO must restore a guest pointer");
    attrib(); CHECK(seen_pointer == client_pointer, "deleting current VBO must restore a guest pointer");
    Invoke(manager, host, "glBindFramebuffer", {GL_FRAMEBUFFER, 11});
    viewport(); CHECK((seen_viewport == std::array<GLint, 4>{1, 2, 50, 25}), "offscreen viewport must remain in guest units");
    Invoke(manager, host, "glDeleteFramebuffers", {1, 0x800});
    viewport(); CHECK((seen_viewport == std::array<GLint, 4>{2, 4, 100, 50}), "deleted FBO must restore surface scaling");
    Invoke(manager, host, "glBindFramebuffer", {GL_READ_FRAMEBUFFER, 12});
    viewport(); CHECK(seen_viewport[2] == 100, "read framebuffer must not change draw viewport scaling");
    Invoke(manager, host, "glBindFramebuffer", {0xffff, 12});
    viewport(); CHECK(seen_viewport[2] == 100, "invalid framebuffer target must not change draw scaling");
    Invoke(manager, host, "glBindBuffer", {GL_ELEMENT_ARRAY_BUFFER, 12});
    current_context = 2;
    draw(); CHECK(seen_pointer == client_pointer, "another context must not inherit EBO binding");
    current_context = 1;
    draw(); CHECK(seen_pointer == offset_pointer, "returning to a context must restore its EBO binding");
    const auto queries = binding_queries;
    draw(); draw(); attrib(); viewport();
    CHECK(queries == binding_queries, "ordinary draws must not re-query driver bindings");
    Invoke(manager, host, "glBufferData", {GL_ARRAY_BUFFER, 0xffffffff, 0, 0x88e4});
    CHECK(seen_size == -1, "ARM32 GLsizeiptr must sign-extend into host intptr_t");
    Invoke(manager, host, "glBufferSubData", {GL_ARRAY_BUFFER, 0xfffffff0, 0xffffffff, 0});
    CHECK(seen_offset == -16 && seen_size == -1, "ARM32 offset and size must sign-extend");
    Invoke(manager, host, "glUniform4f", {7, FloatBits(0.25f), FloatBits(-1.5f), FloatBits(2.25f), FloatBits(37.f)});
    CHECK((seen_uniform == std::array<float, 4>{0.25f, -1.5f, 2.25f, 37.f}), "softfp fourth uniform component must come from the stack");
    Invoke(manager, host, "glBindBuffer", {GL_ARRAY_BUFFER, 11});
    const auto first_map = Invoke(manager, host, "glMapBufferOES", {GL_ARRAY_BUFFER, GL_WRITE_ONLY_OES});
    CHECK(first_map && host.active_maps == 1, "mapping must expose a guest allocation");
    Invoke(manager, host, "glDeleteBuffers", {1, 0x800});
    CHECK(host.active_maps == 0, "deleting a mapped buffer must release its guest allocation");
    Invoke(manager, host, "glBindBuffer", {GL_ARRAY_BUFFER, 21});
    const auto map21 = Invoke(manager, host, "glMapBufferOES", {GL_ARRAY_BUFFER, GL_WRITE_ONLY_OES});
    Invoke(manager, host, "glBindBuffer", {GL_ARRAY_BUFFER, 22});
    const auto map22 = Invoke(manager, host, "glMapBufferOES", {GL_ARRAY_BUFFER, GL_WRITE_ONLY_OES});
    CHECK(map21 && map22 && map21 != map22, "maps belong to buffers, so rebinding must allow another map");
    CHECK(Invoke(manager, host, "glUnmapBufferOES", {GL_ARRAY_BUFFER}) == GL_TRUE, "unmap must select currently bound buffer");
    Invoke(manager, host, "glBindBuffer", {GL_ARRAY_BUFFER, 21});
    CHECK(Invoke(manager, host, "glUnmapBufferOES", {GL_ARRAY_BUFFER}) == GL_TRUE && host.active_maps == 0, "both mapped buffers must retire separately");
    driver_bytes.fill(0x5a);
    const auto range = Invoke(manager, host, "glMapBufferRangeEXT", {GL_ARRAY_BUFFER, 8, 16,
        GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_RANGE_BIT | GL_MAP_UNSYNCHRONIZED_BIT});
    CHECK(range && seen_offset == 8 && seen_size == 16 &&
        seen_access == (GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_RANGE_BIT | GL_MAP_UNSYNCHRONIZED_BIT),
        "range mapping must preserve the guest range and fast write flags");
    CHECK(host.memory[range] == 0, "invalidated write-only mapping must not read back driver bytes");
    host.memory[range] = 0xaa;
    uint32_t canaries[3] = {0x11111111, 0, 0x22222222};
    std::memcpy(host.memory.data()+0x900, canaries, sizeof(canaries));
    Invoke(manager, host, "glGetBufferPointervOES", {GL_ARRAY_BUFFER, GL_BUFFER_MAP_POINTER_OES, 0x904});
    CHECK(host.MemoryRead32(0x904)==range && host.MemoryRead32(0x900)==canaries[0] &&
          host.MemoryRead32(0x908)==canaries[2], "pointer query must return a guest address in four bytes");
    Invoke(manager, host, "glUnmapBufferOES", {GL_ARRAY_BUFFER});
    CHECK(driver_bytes[8]==0xaa && driver_bytes[7]==0x5a && driver_bytes[24]==0x5a,
          "range unmap must write only the mapped bytes");
    const auto read_map=Invoke(manager, host, "glMapBufferRangeEXT", {GL_ARRAY_BUFFER, 0, 8, GL_MAP_READ_BIT});
    CHECK(read_map && host.memory[read_map]==0x5a, "read mapping must copy driver contents");
    host.memory[read_map]=0xff;
    Invoke(manager, host, "glUnmapBufferOES", {GL_ARRAY_BUFFER});
    CHECK(driver_bytes[0]==0x5a, "read-only mapping must never write back");
    const auto explicit_map=Invoke(manager, host, "glMapBufferRangeEXT", {GL_ARRAY_BUFFER, 0, 8,
        GL_MAP_WRITE_BIT | GL_MAP_FLUSH_EXPLICIT_BIT});
    host.memory[explicit_map+2]=0x44; host.memory[explicit_map+3]=0x33;
    Invoke(manager, host, "glFlushMappedBufferRangeEXT", {GL_ARRAY_BUFFER, 2, 1});
    Invoke(manager, host, "glUnmapBufferOES", {GL_ARRAY_BUFFER});
    CHECK(driver_bytes[2]==0x44 && driver_bytes[3]==0x5a, "explicit flush must commit only selected subranges");
    CHECK(ResolveGuestGLProcAddress(host, "glNativeButUnbridged")==0 &&
          ResolveGuestGLProcAddress(host, "glDrawBuffersNV")==0 &&
          ResolveGuestGLProcAddress(host, "glMapBufferRangeEXT")!=0,
          "proc lookup must require a real native function and a bridge handler");
    Invoke(manager, host, "glFramebufferTexture2DMultisampleEXT", {1,2,3,4,5,6});
    CHECK((native_args==std::vector<int64_t>{1,2,3,4,5,6}), "MSAA attachment must read both stack arguments");
    Invoke(manager, host, "glBlitFramebufferEXT", {1,2,3,4,5,6,7,8,9,10});
    CHECK((native_args==std::vector<int64_t>{1,2,3,4,5,6,7,8,9,10}), "blit must preserve all ten arguments");
    Invoke(manager, host, "glTexStorage2DEXT", {GL_TEXTURE_2D,4,GL_RGBA8,32,64});
    CHECK(native_args[4]==64, "texture storage height must come from the stack");
    Invoke(manager, host, "glGenQueriesEXT", {2,0x904});
    CHECK(host.MemoryRead32(0x904)==101 && host.MemoryRead32(0x908)==102 && host.MemoryRead32(0x900)==canaries[0],
          "query generation must write guest GLuints without widening");
    Invoke(manager, host, "glGetQueryObjectuivEXT", {101,GL_QUERY_RESULT_EXT,0x904});
    CHECK(host.MemoryRead32(0x904)==1, "occlusion query must write the native result");
    Invoke(manager, host, "glDrawBuffersEXT", {2,0x800});
    CHECK(seen_pointer==client_pointer, "draw-buffer array must use guest RAM");
    const auto before_invalid=native_calls;
    Invoke(manager, host, "glDrawBuffersEXT", {2,static_cast<uint32_t>(host.memory.size()-4)});
    CHECK(native_calls==before_invalid, "truncated guest arrays must not reach the driver");
    Invoke(manager, host, "glTexImage3DOES", {GL_TEXTURE_3D,1,GL_RGB,1,2,3,0,GL_RGB,GL_UNSIGNED_BYTE,0x800});
    CHECK(seen_pointer==client_pointer && native_args[4]==2 && native_args[5]==3,
          "3D upload must translate data and stack dimensions");
    bool span_valid=false;
    const auto edge=static_cast<uint32_t>(host.memory.size()-23);
    CHECK(GuestImage3D(host,edge,1,2,3,GL_RGB,GL_UNSIGNED_BYTE,"test",&span_valid) && span_valid,
          "3D span must account for unpack alignment and the unpadded final row");
    CHECK(!GuestImage3D(host,edge+1,1,2,3,GL_RGB,GL_UNSIGNED_BYTE,"test",&span_valid) && !span_valid,
          "3D image span must reject one byte past the guest arena");
    const auto before_strings=string_calls;
    const auto version1=Invoke(manager,host,"glGetString",{GL_VERSION});
    current_context=2;
    const auto version2=Invoke(manager,host,"glGetString",{GL_VERSION});
    CHECK(version1!=version2 && std::strcmp(reinterpret_cast<const char*>(host.memory.data()+version2),"OpenGL ES 2.0")==0,
          "cached GL strings must belong to their actual context");
    Invoke(manager,host,"glGetString",{0xffff});
    Invoke(manager,host,"glGetString",{0xffff});
    CHECK(string_calls==before_strings+4,"failed GL string queries must not be cached");
    const auto cached_string_allocations=host.active_maps;
    current_context=3;
    Invoke(manager,host,"glBindBuffer",{GL_ARRAY_BUFFER,74});
    std::memset(host.memory.data()+0x1800,0x5a,64);
    Invoke(manager,host,"glBufferData",{GL_ARRAY_BUFFER,64,0x1800,GL_STATIC_DRAW});
    const auto before_range=range_calls;
    const auto oes_map=Invoke(manager,host,"glMapBufferOES",{GL_ARRAY_BUFFER,GL_WRITE_ONLY_OES});
    CHECK(oes_map && oes_calls==1 && range_calls==before_range,
          "ES2 OES mapping must never call an unsupported non-null range proc");
    CHECK(host.memory[oes_map+1]==0x5a && host.memory[oes_map+63]==0x5a,
          "write-only OES staging must preserve bytes from the original upload");
    host.memory[oes_map]=0xaa; host.memory[oes_map+2]=0;
    Invoke(manager,host,"glGetBufferPointervOES",{GL_ARRAY_BUFFER,GL_BUFFER_MAP_POINTER_OES,0x904});
    CHECK(host.MemoryRead32(0x904)==oes_map,"ES2 OES pointer query must expose the guest staging address");
    CHECK(Invoke(manager,host,"glUnmapBufferOES",{GL_ARRAY_BUFFER})==GL_TRUE &&
          driver_bytes[0]==0xaa && driver_bytes[1]==0x5a && driver_bytes[2]==0 && driver_bytes[63]==0x5a,
          "ES2 OES partial writes must preserve all untouched bytes, including zero-valued edits");
    std::memset(host.memory.data()+0x1900,0x33,4);
    Invoke(manager,host,"glBufferSubData",{GL_ARRAY_BUFFER,8,4,0x1900});
    const auto after_subdata=Invoke(manager,host,"glMapBufferOES",{GL_ARRAY_BUFFER,GL_WRITE_ONLY_OES});
    CHECK(host.memory[after_subdata]==0xaa && host.memory[after_subdata+2]==0 &&
          host.memory[after_subdata+8]==0x33 && host.memory[after_subdata+11]==0x33 &&
          host.memory[after_subdata+12]==0x5a,"OES remap must include prior commits and subdata uploads");
    Invoke(manager,host,"glUnmapBufferOES",{GL_ARRAY_BUFFER});
    fail_next_buffer_data=true;
    Invoke(manager,host,"glBufferData",{GL_ARRAY_BUFFER,32,0x1800,GL_STATIC_DRAW});
    const auto after_failed=Invoke(manager,host,"glMapBufferOES",{GL_ARRAY_BUFFER,GL_WRITE_ONLY_OES});
    CHECK(host.memory[after_failed]==0xaa && host.memory[after_failed+8]==0x33,
          "failed replacement with a mismatching driver size must retain the old shadow");
    Invoke(manager,host,"glUnmapBufferOES",{GL_ARRAY_BUFFER});
    std::memset(host.memory.data()+0x1800,0x77,64);
    Invoke(manager,host,"glBufferData",{GL_ARRAY_BUFFER,64,0x1800,GL_STATIC_DRAW});
    const auto after_replace=Invoke(manager,host,"glMapBufferOES",{GL_ARRAY_BUFFER,GL_WRITE_ONLY_OES});
    CHECK(host.memory[after_replace]==0x77 && host.memory[after_replace+8]==0x77,
          "replacement storage must replace prior OES shadow bytes");
    Invoke(manager,host,"glUnmapBufferOES",{GL_ARRAY_BUFFER});
    CHECK(ResolveGuestGLProcAddress(host,"glMapBufferRangeEXT")==0 &&
          ResolveGuestGLProcAddress(host,"glFlushMappedBufferRangeEXT")==0 &&
          ResolveGuestGLProcAddress(host,"glRenderbufferStorageMultisampleANGLE")==0 &&
          ResolveGuestGLProcAddress(host,"glMapBufferOES")!=0,
          "proc lookup must check current ES2 extensions even when native pointers are non-null");
    GLuint deleted=74; std::memcpy(host.memory.data()+0x800,&deleted,4);
    Invoke(manager,host,"glDeleteBuffers",{1,0x800});
    CHECK(s_buffer_shadows[current_context].count(74)==0,"deletion must retire CPU buffer shadows");
    Invoke(manager,host,"glBindBuffer",{GL_ARRAY_BUFFER,74});
    Invoke(manager,host,"glBufferData",{GL_ARRAY_BUFFER,64,0,GL_STATIC_DRAW});
    const auto after_null=Invoke(manager,host,"glMapBufferOES",{GL_ARRAY_BUFFER,GL_WRITE_ONLY_OES});
    CHECK(host.memory[after_null]==0,"new undefined storage must not reuse a deleted object's shadow");
    Invoke(manager,host,"glUnmapBufferOES",{GL_ARRAY_BUFFER});
    current_context=4;
    Invoke(manager,host,"glBindBuffer",{GL_ARRAY_BUFFER,74});
    driver_bytes.fill(0x66);
    const auto es2_range=Invoke(manager,host,"glMapBufferRangeEXT",{GL_ARRAY_BUFFER,4,8,GL_MAP_READ_BIT});
    CHECK(es2_range && range_calls==before_range+1 && host.memory[es2_range]==0x66 &&
          ResolveGuestGLProcAddress(host,"glMapBufferRangeEXT")!=0,
          "ES2 with advertised EXT_map_buffer_range must retain its legal read mapping path");
    Invoke(manager,host,"glUnmapBufferOES",{GL_ARRAY_BUFFER});
    CHECK(host.active_maps==cached_string_allocations,"all mapping branches must release their guest allocations");
#if MC4_ENABLE_NATIVE_LOGGING
    std::memcpy(host.memory.data()+0x2000,"SkyOpacity",11);
    driver[current_context].program=555;
    const auto uniform_location=Invoke(manager,host,"glGetUniformLocation",{555,0x2000});
    uint32_t probe_binding[4]={0,uniform_location,0x03020601,1};
    uint32_t probe_parameter[4]={0,0xffffffff,0x00ffffff,0xffffffff};
    std::memcpy(host.memory.data()+0x2100,probe_binding,sizeof(probe_binding));
    std::memcpy(host.memory.data()+0x2140,probe_parameter,sizeof(probe_parameter));
    Dynarmic::A32::Jit probe;
    for (size_t i=0;i<probe.registers.size();++i) probe.registers[i]=0x12345000+static_cast<uint32_t>(i);
    probe.registers[4]=0x2100; probe.registers[5]=0x2140; probe.registers[6]=0x2180;
    probe.fpuregisters.fill(0x87654321); probe.cpsr=0xf00001d0;
    const auto original_registers=probe.registers;
    const auto original_fpu=probe.fpuregisters;
    const auto original_cpsr=probe.cpsr;
    manager.handlers.at("probe_missing_global_shader_parameter")(probe,host);
    CHECK(std::equal(probe.registers.begin(),probe.registers.begin()+15,original_registers.begin()) &&
          probe.registers[15]==0x411be870 && probe.fpuregisters==original_fpu && probe.cpsr==original_cpsr,
          "missing-parameter observation must preserve all registers, FPU and CPSR except displaced branch PC");
    uint32_t observed_program=0;
    CHECK(std::strcmp(GuestGLUniformName(uniform_location,&observed_program),"SkyOpacity")==0 &&
          observed_program==555,"missing-parameter observation must identify the actual native uniform name");
    probe.registers[4]=static_cast<uint32_t>(host.memory.size()-8);
    probe.registers[5]=0; probe.registers[6]=static_cast<uint32_t>(host.memory.size()-2);
    manager.handlers.at("probe_missing_global_shader_parameter")(probe,host);
    CHECK(probe.registers[15]==0x411be870 && probe.fpuregisters==original_fpu && probe.cpsr==original_cpsr,
          "truncated diagnostic records must preserve the existing fallback without host overreads");

    const unsigned before_sky_queries=binding_queries;
    LogSkyDraw(host,GL_TRIANGLES,3,0,nullptr,0,0x1234);
    CHECK(binding_queries==before_sky_queries,"sky observation must not query outside the selected pass");
    probe.registers=original_registers;
    manager.handlers.at("probe_sky_pass_begin")(probe,host);
    CHECK(std::equal(probe.registers.begin(),probe.registers.begin()+14,original_registers.begin()) &&
          probe.registers[14]==0x4053e198 && probe.registers[15]==0x40550984 &&
          probe.fpuregisters==original_fpu && probe.cpsr==original_cpsr && s_sky_observation.active,
          "sky-entry probe must emulate BL exactly and preserve FPU/CPSR");
    sky_attribute_pointer=reinterpret_cast<uintptr_t>(host.memory.data()+0x800);
    driver[current_context].element=0;
    driver[current_context].active_texture=GL_TEXTURE0+7;
    for (GLuint program=601;program<=603;++program) {
        driver[current_context].program=program;
        LogSkyDraw(host,GL_TRIANGLES,3,0,nullptr,0,0x1234);
    }
    CHECK(sky_source_queries==4 && s_sky_observation.programs.size()==2,
          "sky source capture must include at most two actual selected programs");
    CHECK(sky_uniform_queries==6,"sky snapshots must distinguish matrix and sampler query types");
    CHECK(sky_constant_queries==6,"sky snapshots must capture disabled active Color/UV constants");
    CHECK(driver[current_context].active_texture==GL_TEXTURE0+7 && sky_level_queries==0,
          "ES2 sky sampler observations must restore texture unit and avoid GLES3.1 queries");
    s_buffer_shadows[current_context][77]=std::vector<uint8_t>(32,0x4a);
    CHECK(SkyDataSpan(host,current_context,77,16,16) &&
          !SkyDataSpan(host,current_context,77,17,16) &&
          !SkyDataSpan(host,current_context,999,0,16) &&
          SkyDataSpan(host,current_context,0,sky_attribute_pointer,16)==host.memory.data()+0x800 &&
          !SkyDataSpan(host,current_context,0,1,16),
          "observational vertex/index spans must respect shadow and guest bounds");
    bool floating=false;
    CHECK(SkyUniformComponents(GL_FLOAT_MAT4,floating)==16 && floating &&
          SkyUniformComponents(GL_FLOAT_MAT3,floating)==9 && floating &&
          SkyUniformComponents(GL_SAMPLER_2D,floating)==1 && !floating,
          "observational query buffers must fit exact active uniform component counts");
    probe.registers=original_registers; probe.registers[5]=0x2200;
    uint32_t loaded_word=0x87654321;
    std::memcpy(host.memory.data()+0x2274,&loaded_word,4);
    manager.handlers.at("probe_sky_pass_end")(probe,host);
    auto expected_registers=original_registers;
    expected_registers[2]=loaded_word; expected_registers[5]=0x2200; expected_registers[15]=0x4053e19c;
    CHECK(probe.registers==expected_registers && probe.fpuregisters==original_fpu &&
          probe.cpsr==original_cpsr && !s_sky_observation.active,
          "sky-return probe must emulate displaced LDR and fallthrough exactly");
    const unsigned after_sky_queries=binding_queries;
    LogSkyDraw(host,GL_TRIANGLES,3,0,nullptr,0,0x1234);
    CHECK(binding_queries==after_sky_queries,"sky-return observation must close its scope");
    GuestGLSkyPass(true);
    s_sky_observation.samples=32;
    LogSkyDraw(host,GL_TRIANGLES,3,0,nullptr,0,0x1234);
    CHECK(binding_queries==after_sky_queries,"sky diagnostics must stop querying after 32 samples");
    GuestGLSkyPass(false);
    current_context=1;
    driver[current_context].active_texture=GL_TEXTURE0+6;
    LogSkyTexture2D(99,777,"DiffuseSampler",2);
    CHECK(driver[current_context].active_texture==GL_TEXTURE0+6 && sky_level_queries==3,
          "GLES3.2 sky sampler observations must query dimensions/format then restore active unit");
    LogSkyTexture2D(99,777,"InvalidSampler",8);
    CHECK(driver[current_context].active_texture==GL_TEXTURE0+6 && sky_level_queries==3,
          "invalid sampler units must not alter GL selection or query unsupported texture state");
    sky_texture_unbound=true;
    LogSkyTexture2D(99,777,"UnboundSampler",2);
    CHECK(driver[current_context].active_texture==GL_TEXTURE0+6 && sky_level_queries==3,
          "unbound sampler early return must restore active unit without invalid texture queries");
    sky_texture_unbound=false;
    current_context=5;
    driver[current_context].active_texture=GL_TEXTURE0+5;
    LogSkyTexture2D(99,777,"DiffuseSampler",2);
    CHECK(driver[current_context].active_texture==GL_TEXTURE0+5 && sky_level_queries==3,
          "GLES3.0 must not call a non-null GLES3.1 level-query entry point");
    std::vector<uint8_t> mesh_bytes(32768,0x4a);
    s_sky_observation.buffers.clear();
    LogSkyBuffer(99,"index",current_context,77,0,mesh_bytes.data(),360);
    LogSkyBuffer(100,"index",current_context,77,0,mesh_bytes.data(),360);
    CHECK(s_sky_observation.buffers.size()==1,"unchanged actual sky buffer snapshots must be deduplicated");
    LogSkyBuffer(100,"vertex",current_context,77,0,mesh_bytes.data(),mesh_bytes.size());
    std::fill(mesh_bytes.begin()+16384,mesh_bytes.end(),0x5b);
    LogSkyBuffer(101,"vertex",current_context,77,0,mesh_bytes.data(),mesh_bytes.size());
    CHECK(s_sky_observation.buffers.size()==2,
          "sky capture must neither read nor hash bytes beyond the 16KiB observational bound");
    for (unsigned name=78;name<84;++name)
        LogSkyBuffer(100,"vertex",current_context,name,0,mesh_bytes.data(),mesh_bytes.size());
    CHECK(s_sky_observation.buffers.size()==4,"full sky buffer capture must stop at four bounded snapshots");
    // Selected ETC1 capture writes exact validated guest bytes and valid metadata;
    // temporary host files stand in for the app-owned external-files directory.
    sky_bound_texture_override=249;
    const unsigned before_dump_queries=binding_queries;
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,13,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,0,GL_ETC1_RGB8_OES,4,4,3*1024*1024+1,0x800,0x1234);
    DumpSelectedSkyTexture(host,GL_TEXTURE_CUBE_MAP_POSITIVE_X,0,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    CHECK(binding_queries==before_dump_queries && sky_dump_results.empty(),
          "texture diagnostic must reject oversized levels/ranges and other targets before GL queries");
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,0,GL_ETC1_RGB8_OES,4,4,8,
        static_cast<uint32_t>(host.memory.size()-4),0x1234);
    CHECK(s_sky_texture_dumps.empty() && sky_dump_results.empty(),
          "texture diagnostic must validate the whole guest upload range before touching files");
    const std::vector<uint8_t> original_upload(host.memory.begin()+0x800,host.memory.begin()+0x808);
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,0,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    CHECK(sky_dump_results.size()==2 && sky_dump_results[0].second==original_upload,
          "selected compressed texture dump must preserve every upload byte");
    const auto& metadata_bytes=sky_dump_results[1].second;
    const std::string metadata_text(metadata_bytes.begin(),metadata_bytes.end());
    CHECK(metadata_text.find("\"texture\":249")!=std::string::npos &&
          metadata_text.find("\"image_size\":8")!=std::string::npos &&
          metadata_text.find("\"context\":\"0x0000000000000005\"")!=std::string::npos &&
          sky_dump_results[0].first.find("t249-l0-c0000000000000005.bin")!=std::string::npos,
          "selected texture metadata and filenames must identify exact context/texture/level");
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,0,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    CHECK(sky_dump_results.size()==2,"one context/level must be dumped at most once");
    sky_bound_texture_override=248;
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,1,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    CHECK(s_sky_texture_dumps.size()==1,"other native texture objects must not enter the diagnostic capture");
    sky_bound_texture_override=249;
    current_context=6;
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,0,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    CHECK(sky_dump_results.size()==4 && s_sky_texture_dumps.size()==2,
          "distinct EGL contexts must receive separate texture capture files");
    current_context=7;sky_dump_open_fails=true;
    DumpSelectedSkyTexture(host,GL_TEXTURE_2D,0,GL_ETC1_RGB8_OES,4,4,8,0x800,0x1234);
    CHECK(sky_dump_results.size()==4 && sky_dump_files.empty(),
          "a failed diagnostic file open must leave no active files or change upload data");
    sky_dump_open_fails=false;
    CHECK(driver[5].active_texture==GL_TEXTURE0+5,
          "texture upload capture must never change the active texture unit");
    current_context=1;
    driver[current_context].framebuffer=1;
    driver[current_context].array=588;driver[current_context].element=587;
    native_buffer_size=64;
    s_buffer_shadows[current_context][587]=std::vector<uint8_t>(driver_bytes.begin(),driver_bytes.end());
    s_buffer_shadows[current_context][588]=s_buffer_shadows[current_context][587];
    const auto before_gpu_bytes=driver_bytes;
    const unsigned before_gpu_maps=range_calls;
    CompareSelectedSkyGpuBuffers();
    CHECK(range_calls==before_gpu_maps+2 && seen_access==GL_MAP_READ_BIT &&
          last_mapping_pointer==nullptr && driver_bytes==before_gpu_bytes &&
          driver[current_context].array==588 && driver[current_context].element==587,
          "GPU verification must read native core buffers and unmap without changing bindings or bytes");
    const unsigned before_pixels=sky_read_calls;
    const size_t before_pixel_files=sky_dump_results.size();
    LogSkyRasterState("before",0,0x411C9BCC);
    CaptureSkyPixels("before",1);
    CHECK(sky_read_calls==before_pixels+2 && sky_dump_results.size()==before_pixel_files+4 &&
          sky_dump_results[before_pixel_files].second.size()==16*8*4 &&
          sky_dump_results[before_pixel_files].second[0]==0 &&
          sky_dump_results[before_pixel_files].second[2]==128 &&
          driver[current_context].framebuffer==1 && driver[current_context].array==588,
          "one-shot readback must save exact bounded RGBA bands without changing framebuffer/buffer state");
    sky_read_pack_buffer=77;
    CaptureSkyPixels("after",1);
    sky_read_pack_buffer=0;sky_read_row_length=32;
    CaptureSkyPixels("after",1);
    sky_read_row_length=0;sky_read_skip_rows=1;
    CaptureSkyPixels("after",1);
    sky_read_skip_rows=0;sky_read_skip_pixels=1;
    CaptureSkyPixels("after",1);
    sky_read_skip_pixels=0;sky_read_framebuffer=0;
    CaptureSkyPixels("after",1);
    sky_read_framebuffer=-1;sky_read_buffer=GL_NONE;
    CaptureSkyPixels("after",1);
    sky_read_buffer=GL_COLOR_ATTACHMENT1;
    CaptureSkyPixels("after",1);
    sky_read_buffer=-1;sky_read_samples=4;
    CaptureSkyPixels("after",1);
    sky_read_samples=0;sky_read_complete=false;
    CaptureSkyPixels("after",1);
    sky_read_complete=true;sky_read_type=GL_FLOAT;
    CaptureSkyPixels("after",1);
    sky_read_type=GL_UNSIGNED_BYTE;
    CHECK(sky_read_calls==before_pixels+2 && sky_dump_results.size()==before_pixel_files+4,
          "readback must skip unsafe PBO/packing/read-FBO/read-buffer/multisample/incomplete/format states");
    sky_read_format=GL_BGRA_EXT;
    CaptureSkyPixels("after",1);
    CHECK(sky_read_calls==before_pixels+4 && sky_dump_results[before_pixel_files+4].second==
          sky_dump_results[before_pixel_files].second,
          "native preferred BGRA readback must be stored as the same canonical RGBA bytes");
    sky_read_format=GL_RGBA;sky_read_samples=4;driver[current_context].framebuffer=0;
    CaptureSkyPixels("present",0);
    CHECK(sky_read_calls==before_pixels+6 && driver[current_context].framebuffer==0,
          "default framebuffer readback may resolve window multisampling without changing bindings");
    sky_read_samples=0;current_context=3;driver[current_context].framebuffer=1;
    const unsigned before_es2_pack_queries=sky_read_gl3_pack_queries;
    CaptureSkyPixels("after",1);
    CompareSelectedSkyGpuBuffers();
    CHECK(sky_read_calls==before_pixels+8 && sky_read_gl3_pack_queries==before_es2_pack_queries &&
          range_calls==before_gpu_maps+2,
          "ES2 observation must avoid GLES3 packing queries and native READ mapping");
#endif
    std::puts("GL thunk pointer/context/lifecycle/softfp contract passed");
}
"""


class GlThunkContract(unittest.TestCase):
    def test_production_thunks(self) -> None:
        names = (
            "glBindBuffer", "glBindFramebuffer", "glDeleteBuffers",
            "glDeleteFramebuffers", "glDrawElements", "glVertexAttribPointer",
            "glViewport", "glBufferData", "glBufferSubData", "glUniform4f",
            "glMapBufferOES", "glUnmapBufferOES",
            "glMapBufferRangeEXT", "glGetBufferPointervOES", "glFlushMappedBufferRangeEXT",
            "glGetString",
            "glGetUniformLocation",
        )
        prefix = SOURCE[SOURCE.index("// Mirror"):SOURCE.index("void RegisterGles2CoreThunks")]
        helpers = CORE[CORE.index("bool CheckedArrayBytes"):CORE.index("size_t GetFloatStateValueCount")]
        native = CORE[CORE.index("    // These are the entry points resolved"):CORE.rindex("\n}")]
        cpp = PRELUDE + prefix + helpers + "\nvoid ThunkManager::RegisterGLThunks() {\nauto& manager = *this;\n"
        cpp += "\n".join(thunk(name) for name in names) + native
        cpp += "\n#if MC4_ENABLE_NATIVE_LOGGING\n"
        cpp += "\n".join(observer_probe(name) for name in (
            "probe_missing_global_shader_parameter", "probe_sky_pass_begin", "probe_sky_pass_end",
        ))
        cpp += "\n#endif\n}\n" + CHECKS
        with tempfile.TemporaryDirectory(prefix="mc4-gl-contract-") as directory:
            temporary = Path(directory)
            stub = temporary / "dynarmic" / "interface" / "A32" / "a32.h"
            stub.parent.mkdir(parents=True)
            stub.write_text(
                "#pragma once\n#include <array>\n#include <cstdint>\n"
                "namespace Dynarmic::A32 { struct Jit {\n"
                "std::array<uint32_t,16> registers{};\n"
                "std::array<uint32_t,64> fpuregisters{}; uint32_t cpsr=0;\n"
                "auto& Regs() { return registers; } }; }\n",
                encoding="utf-8",
            )
            (temporary / "contract.cpp").write_text(cpp, encoding="utf-8")
            vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            installation = subprocess.check_output(
                [str(vswhere), "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"], text=True,
            ).strip()
            self.assertTrue(installation, "local MSVC C++ toolchain is required")
            vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
            sdk = Path(os.environ.get("ANDROID_SDK_ROOT", str(Path(os.environ["LOCALAPPDATA"]) / "Android/Sdk")))
            ndk_headers = sdk / "ndk/27.2.12479018/toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include"
            for header_directory in ("GLES2", "GLES3", "KHR"):
                shutil.copytree(ndk_headers / header_directory, temporary / header_directory)
            command = (
                f'call "{vcvars}" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /O2 '
                f'/I"{temporary}" /I"{ROOT / "src"}" contract.cpp /Fe:contract.exe '
                '&& contract.exe'
            )
            result = subprocess.run(
                command, shell=True, cwd=temporary, capture_output=True, text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("contract passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
