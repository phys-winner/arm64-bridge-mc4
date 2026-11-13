#!/usr/bin/env bash
set -euo pipefail

GAME_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOL_ROOT="${MC4_TOOL_ROOT:-$GAME_ROOT/tools/android}"
test -f "$TOOL_ROOT/toolchain.sh" || { echo "Missing project-local toolchain" >&2; exit 1; }
source "$TOOL_ROOT/toolchain.sh"

# Apktool's incremental staging tree can retain deleted resources of any type.
# Fail closed on orphaned entries; never silently delete an unknown cache file.
check_staged_resource_sources() {
  local staged_res_dir="$GAME_ROOT/app/build/apk/res"
  local source_res_dir="$GAME_ROOT/app/res"
  if [ -d "$staged_res_dir" ]; then
    while IFS= read -r -d '' staged_resource; do
      local relative_resource="${staged_resource#"$staged_res_dir"/}"
      if [ ! -f "$source_res_dir/$relative_resource" ]; then
        echo "Stale Apktool resource cache entry (not deleted): $staged_resource" >&2
        return 1
      fi
    done < <(find "$staged_res_dir" -type f -print0)
  fi
}
check_staged_resource_sources

ASSET_SCRIPT="$GAME_ROOT/work/obb/verify_obb_apk.py"
# Canonical guest copy (phase 7): assets/guest_libs. The arm32 lib tree is
# gone from the APK; this file is the measured original, kept verbatim.
MODERN_COMBAT="$GAME_ROOT/app/assets/guest_libs/libModernCombat4.so"
EXPECTED_MODERN_COMBAT_SHA256='f5bcb8e6071cc1b0e09d200922dd2914e971ccbf5002981e8416481fe5b45ba1'
# phase 7: the arm32 game library ships as a STORED asset for the Dynarmic
# bridge; libphase3vfs/libofflinecheats were ported into the bridge host
# (arm64_bridge/src/mc4_phase3.cpp, mc4_cheats.cpp) and no longer ship as
# separate arm32 .so files.
GUEST_LIBS_DIR="$GAME_ROOT/app/assets/guest_libs"
BRIDGE_LIB="${MC4_BRIDGE_LIB:-$GAME_ROOT/arm64_bridge/dist/libModernCombat4.so}"
BRIDGE_PROVENANCE="${MC4_BRIDGE_PROVENANCE:-$BRIDGE_LIB.provenance.json}"
test -f "$ASSET_SCRIPT" || { echo "Missing OBB asset verifier: $ASSET_SCRIPT" >&2; exit 1; }
test -f "$MODERN_COMBAT" || { echo "Missing measured ModernCombat4 library: $MODERN_COMBAT" >&2; exit 1; }
test "$(sha256sum "$MODERN_COMBAT" | awk '{print $1}')" = "$EXPECTED_MODERN_COMBAT_SHA256"
test -f "$BRIDGE_LIB" || { echo "Missing arm64 bridge (run arm64_bridge/build_arm64.ps1 -BridgeTarget ModernCombat4): $BRIDGE_LIB" >&2; exit 1; }
test -f "$BRIDGE_PROVENANCE" || { echo "Missing bridge provenance (rebuild arm64_bridge before packaging): $BRIDGE_PROVENANCE" >&2; exit 1; }
python -B "$GAME_ROOT/arm64_bridge/verify_bridge_provenance.py" verify --root "$GAME_ROOT/arm64_bridge" --bridge "$BRIDGE_LIB" --manifest "$BRIDGE_PROVENANCE" --target ModernCombat4
python -X utf8 "$ASSET_SCRIPT" "$GAME_ROOT" --verify

NDK_ROOT="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT}/ndk/27.2.12479018}}"
LLVM_BIN="$NDK_ROOT/toolchains/llvm/prebuilt/windows-x86_64/bin"
test -f "$LLVM_BIN/llvm-readelf.exe" || { echo "Missing recorded llvm-readelf" >&2; exit 1; }

# The clean source tree may not have an output directory yet; the ELF report
# below is written before the APK-output block creates its paths.
mkdir -p "$GAME_ROOT/out"

# Guest library stays at assets/guest_libs/libModernCombat4.so (ZIP_STORED via
# apktool.yml doNotCompress so the bridge can mmap it straight from the APK);
# only the arm64 bridge ships under lib/.
mkdir -p "$GAME_ROOT/app/lib/arm64-v8a"
for unwanted_abi in armeabi armeabi-v7a x86 x86_64; do
  test ! -e "$GAME_ROOT/app/lib/$unwanted_abi" || {
    echo "Unexpected native ABI input: app/lib/$unwanted_abi (not deleted)" >&2
    exit 1
  }
done
cp "$BRIDGE_LIB" "$GAME_ROOT/app/lib/arm64-v8a/libModernCombat4.so"

"$LLVM_BIN/llvm-readelf.exe" -h -A "$BRIDGE_LIB" | tee "$GAME_ROOT/out/bridge_elf.txt"
grep -q 'Class:.*ELF64' "$GAME_ROOT/out/bridge_elf.txt"
grep -q 'Machine:.*AArch64' "$GAME_ROOT/out/bridge_elf.txt"
"$LLVM_BIN/llvm-readelf.exe" -lW "$BRIDGE_LIB" | awk '/LOAD/ { for (i = 1; i <= NF; ++i) if ($i ~ /^0x/) last = $i; if (strtonum(last) < 16384) { print "PT_LOAD alignment below 16 KiB: " $0; exit 1 } }' >/dev/null

SIGNER="${MC4_APKSIGNER:-$BUILD_TOOLS/lib/apksigner.jar}"
SIGN_KEY="${MC4_SIGN_KEY:?Set MC4_SIGN_KEY to your own PKCS8 APK signing key}"
SIGN_CERT="${MC4_SIGN_CERT:?Set MC4_SIGN_CERT to your own X.509 APK signing certificate}"
EXPECTED_CERT_SHA256="${MC4_SIGN_CERT_SHA256:?Set MC4_SIGN_CERT_SHA256 to your certificate SHA-256 fingerprint}"
EXPECTED_CERT_SHA256="$(printf '%s' "$EXPECTED_CERT_SHA256" | tr -d ':' | tr 'A-F' 'a-f')"
[[ "$EXPECTED_CERT_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid certificate SHA-256 fingerprint' >&2; exit 1; }
for f in "$SIGNER" "$SIGN_KEY" "$SIGN_CERT"; do
  test -f "$f" || { echo "Missing required test signer file: $f" >&2; exit 1; }
done

APK_NAME="${MC4_APK_NAME:-MC4_1.2.3e.apk}"
OUT_DIR="$GAME_ROOT/out"
UNSIGNED="$OUT_DIR/${APK_NAME%.apk}.unsigned.apk"
ALIGNED="$OUT_DIR/${APK_NAME%.apk}.aligned.apk"
OUT_APK="$OUT_DIR/$APK_NAME"
VERIFY_LOG="$OUT_DIR/${APK_NAME%.apk}.verify.txt"
BADGING_LOG="$OUT_DIR/${APK_NAME%.apk}.badging.txt"
mkdir -p "$OUT_DIR"

# Build the canonical input directly, preserving Apktool's incremental cache.
# Analysis databases belong outside app/assets. Refuse accidental packaging
# rather than copying thousands of hard links or deleting an unknown file.
while IFS= read -r -d '' analysis_file; do
  echo "Unexpected analysis file in APK assets: $analysis_file (not deleted)" >&2
  exit 1
done < <(find "$GAME_ROOT/app/assets" -type f \( \
  -name '*.i64' -o -name '*.id[0-9]' -o -name '*.idb' -o -name '*.idb64' -o \
  -name '*.idc' -o -name '*.ids' -o -name '*.idt' -o -name '*.nam' -o -name '*.til' \
  \) -print0)

rm -f "$UNSIGNED" "$ALIGNED" "$OUT_APK" "$OUT_APK.idsig" "$VERIFY_LOG" "$BADGING_LOG"
APPDATA_ARGS=()
if [ "${MC4_DEVICECHECK:-0}" = 1 ]; then APPDATA_ARGS+=(-IncludeDeviceCheck); fi
MSYS2_ARG_CONV_EXCL='*' powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(cygpath -w "$GAME_ROOT/work/build-app-data.ps1")" "${APPDATA_ARGS[@]}"
tool_apktool b "$GAME_ROOT/app" -o "$UNSIGNED"
check_staged_resource_sources
tool_zipalign -P 16 -f 4 "$UNSIGNED" "$ALIGNED"
SIGN_ARGS=(sign --key "$SIGN_KEY" --cert "$SIGN_CERT" --out "$OUT_APK")
"$JAVA_EXE" -jar "$SIGNER" "${SIGN_ARGS[@]}" "$ALIGNED"
"$JAVA_EXE" -jar "$SIGNER" verify --verbose --print-certs "$OUT_APK" | tee "$VERIFY_LOG"
grep -F "$EXPECTED_CERT_SHA256" "$VERIFY_LOG" >/dev/null

tool_zipalign -c -P 16 4 "$OUT_APK"
tool_aapt2 dump badging "$OUT_APK" | tee "$BADGING_LOG"
# arm64-v8a is the only native ABI left.
! grep -q 'native-code:.*armeabi-v7a' "$BADGING_LOG"
grep -q 'native-code:.*arm64-v8a' "$BADGING_LOG"
# The guest library must be ZIP_STORED inside the APK. Inspect the central
# directory without reading the 2.1-GB APK into RAM, and enforce the legacy
# 32-bit ZIP/VFS size budget before publishing a candidate.
python - "$OUT_APK" <<'PY'
import os, sys, zipfile
apk = sys.argv[1]
if os.path.getsize(apk) >= 0x80000000:
    raise SystemExit('signed APK exceeds 32-bit ZIP/VFS budget')
with zipfile.ZipFile(apk) as archive:
    info = archive.getinfo('assets/guest_libs/libModernCombat4.so')
    if info.compress_type != zipfile.ZIP_STORED:
        raise SystemExit('guest lib is compressed')
    if not all(
        item.file_size < 0xFFFFFFFF and item.header_offset < 0xFFFFFFFF
        for item in archive.infolist()
    ):
        raise SystemExit('ZIP64 entry is unsupported by the native VFS')
print('guest_libs STORED check: OK')
PY
python -X utf8 "$ASSET_SCRIPT" "$GAME_ROOT" --verify-apk "$OUT_APK"
test -s "$OUT_APK"
sha256sum "$OUT_APK" | tee "$OUT_APK.sha256"
printf 'BUILD_APK=%s\n' "$OUT_APK"
printf 'BUILD_CERT_SHA256=%s\n' "$EXPECTED_CERT_SHA256"

# Apktool and zipalign each create a full-size copy of this >2 GB APK. Once
# every packaging/signature/OBB check above has passed, retain only the signed
# candidate and its compact reports; the intermediate APKs and v4 sidecar are
# reproducible and otherwise multiply project storage on every build.
rm -f "$UNSIGNED" "$ALIGNED" "$OUT_APK.idsig"
