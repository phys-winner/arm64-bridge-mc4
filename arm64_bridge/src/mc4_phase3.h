// MC4 phase3 VFS + offline-cheat host port, see mc4_phase3.cpp / mc4_cheats.cpp.
#pragma once

#include <cstdio>
#include <jni.h>
#include <sys/stat.h>
#include <sys/types.h>

class DynarmicHost;

namespace mc4 {

// --- VFS install & queries (jni_bridge calls these) ---
void Phase3VfsInstall(DynarmicHost& host, const char* apk_path, const char* obb_dir);
bool Phase3Installed();
// Runs after the guest frame; queued native shop/settings calls finish here.
void Phase3PumpLocalUi(DynarmicHost& host);
uint32_t Phase3SettingsStringOverride(DynarmicHost& host, uint32_t manager,
                                     uint32_t id, uint32_t caller);
// Duplicated source FD and bounded member window; caller owns the returned FD.
int Phase3OpenMedia(const char* name, off64_t* offset, off64_t* length);
bool Phase3ForceMaxQuality(DynarmicHost& host);
bool Phase3GateReady();
void Phase3SetJavaVM(JavaVM* vm);
void Phase3RegisterThunks(DynarmicHost& host);

// Entitlement gate shared with the offline cheats port.
bool Phase3AllowCheatOption(int option);
void Phase3SetCheatEntitlement(int option);

// --- hook entry points called from thunks_libc before the native fallback ---
// handled distinguishes an unrecognized path from a recognized virtual path
// whose handle allocation failed. Never fall back to a host file for the latter.
FILE* Phase3VfsHookFopen(const char* path, const char* mode, bool* handled);
// open: sets *handled for a recognized virtual path even when it returns -1.
int Phase3VfsHookOpen(const char* path, int flags, bool* handled);
// fdopen on a virtual fd; 0 on success with *out set.
int Phase3VfsHookFdopen(int fd, FILE** out);
// Returns 0 when the fd belonged to the VFS, -1 when the caller falls back.
int Phase3VfsHookClose(int fd);
ssize_t Phase3VfsHookRead(int fd, void* buffer, size_t count);
ssize_t Phase3VfsHookPread(int fd, void* buffer, size_t count, off64_t offset);
off64_t Phase3VfsHookLseek(int fd, off64_t offset, int whence);
// Returns 0 when answered, -1 when the caller falls back to real stat.
int Phase3VfsHookStat(const char* path, struct stat* st);
int Phase3VfsHookFstat(int fd, struct stat* st);
// mmap into the guest arena; 0 on success with *out_va set.
int Phase3VfsHookMmap(DynarmicHost& host, int fd, size_t length, off64_t offset,
                      uint32_t* out_va);

}  // namespace mc4
