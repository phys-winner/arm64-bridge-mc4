#!/usr/bin/env bash

TOOL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
JAVA_EXE="${JAVA_EXE:-${JAVA_HOME:?Set JAVA_HOME}/bin/java.exe}"
BUILD_TOOLS="${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT}/build-tools/37.0.0"
export TOOL_ROOT JAVA_EXE BUILD_TOOLS

tool_apktool()  { "$JAVA_EXE" -jar "$TOOL_ROOT/apktool.jar" "$@"; }
tool_smali()    { "$JAVA_EXE" -jar "$TOOL_ROOT/smali.jar" "$@"; }
tool_baksmali() { "$JAVA_EXE" -jar "$TOOL_ROOT/baksmali.jar" "$@"; }
tool_aapt2()    { "$BUILD_TOOLS/aapt2.exe" "$@"; }
tool_zipalign() { "$BUILD_TOOLS/zipalign.exe" "$@"; }
tool_apksigner() { "$JAVA_EXE" -jar "$BUILD_TOOLS/lib/apksigner.jar" "$@"; }
