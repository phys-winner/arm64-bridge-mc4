# arm64-bridge-mc4

An experimental ARM64 compatibility bridge for **Modern Combat 4: Zero Hour**
on Android, with source code and recipes for recreating the port locally.

**Unreleased and unfinished. There is no supported release or downloadable APK.**
The current sources include incomplete work and unresolved rendering defects.
They are published for development and research, not as a finished playable port.

Project URL: <https://github.com/phys-winner/arm64-bridge-mc4>

Suggested GitHub description:
> Unreleased ARM64 compatibility bridge and reproducible porting sources for Modern Combat 4 on Android.

## How it works

The original ARMv7 game library runs inside a native `arm64-v8a` Android process
using the Dynarmic A32 JIT. The bridge loads the guest ELF, translates its calls
to host implementations of libc, threading, JNI, OpenGL ES and OpenSL ES, and
adapts Android lifecycle and input handling. It is specific to the input version
listed below; it is not a general Android emulator or a native recompilation of
the game.

The packaging flow embeds the two complete, unchanged OBB containers and the
unchanged ARM32 guest library as uncompressed APK assets. The ARM64 bridge is
the only library packaged under `lib/`. The native build requests 16 KiB ELF
segment alignment; the packaging flow also checks ZIP alignment and hashes.

The sources contain work on offline data access, video/subtitle playback,
audio callbacks, Android Back navigation, touch/orientation handling and native
shop/QA menu integration. These features have had partial device testing, but
there is no claim of complete campaign, multiplayer or device compatibility.

## Current limitations

- A grey sky band and moving dark geometry remain unresolved on tested Mali
  and Adreno devices.
- Native graphics presets and the settings UI experiment are incomplete. The
  backend and UI work are not fully integrated or validated on hardware.
- The last diagnostic build was not accepted as a release. A new default
  logging-off build and a full regression pass are still required.
- Some unsupported guest instructions in the pinned Dynarmic patch advance
  the PC without interpreting the instruction. This is a compatibility shortcut,
  not complete ARM emulation, and can affect correctness.
- Full campaign progression, multiplayer and real 16 KiB-page runtime
  compatibility have not been established. ARM64-only device testing was partial.
- The documented host workflow is Windows with PowerShell and Git Bash.
  Linux/macOS build wrappers are not provided.

## Repository contents

| Path | Purpose |
| --- | --- |
| `arm64_bridge/src/` | Native bridge and game-specific integration |
| `arm64_bridge/patches/` | Patch for the pinned Dynarmic checkout |
| `arm64_bridge/tests/` | Native/source contract tests |
| `patches/android/` | Hash-checked Android edit recipe and newly written additions |
| `patches/menu_advanced.json` | Edit recipe for the unfinished AS3 UI experiment |
| `tools/prepare_app.py` | Recreate `app/` from the original APK and OBBs |
| `tools/prepare_graphics_source.py` | Recreate the optional experimental AS3 source |
| `tools/android/toolchain.sh` | Packaging tool entry points; tools installed separately |
| `work/` | AppData Java source, generation scripts and relevant checks |
| `build.sh` | Verify, build, align and sign a local APK |

**No game files are distributed.** APKs, OBBs, original native game binaries,
decoded game resources, game movies, screenshots, signing keys and build outputs
are excluded. `app/`, `original/`, the experimental generated AS3 source and old
local work may exist in a developer's directory, but are not Git content.
The recipes store edit ranges and replacement text; unchanged game code and
deleted text must come from your own originals. Renamed licensing classes are
reconstructed from the original APK rather than bundled as complete classes.

## Required original inputs

Supply your own legally obtained copy of **version 1.2.3e / versionCode 12329**,
package `com.gameloft.android.ANMP.GloftM4HM`. Different APK variants will be rejected.

| Local path | Bytes | SHA-256 |
| --- | ---: | --- |
| `original/MC4_1.2.3e.apk` | 27915687 | `1e04565e70f7df372d9ece386a37eb07d0a11cb4b6536d8c9f6aa5ddf58d6797` |
| `original/obb/main.1100.com.gameloft.android.ANMP.GloftM4HM.obb` | 2052015324 | `c47c0fff7bfb56f158fa8bd2ef2c6b47caac30c6e48f0cbc91c4ee40931fcd1c` |
| `original/obb/patch.12222.com.gameloft.android.ANMP.GloftM4HM.obb` | 15093838 | `14f53062d1d6a5ad7b02aff603b9b6de09bcac8945fd135301b7f8bc2f0dd670` |

The guest library extracted from the APK must have SHA-256
`f5bcb8e6071cc1b0e09d200922dd2914e971ccbf5002981e8416481fe5b45ba1`.
The main OBB is packaged as `assets/obb/main.12222.obb`; only its filename changes.
The scripts neither download the game nor modify its OBB contents.

## Build prerequisites

- Windows, Git (including Git Bash), PowerShell and Python 3.11 or later.
- JDK 24.0.1 (the recorded toolchain); set `JAVA_HOME` to its installation directory.
- Android SDK; set `ANDROID_SDK_ROOT`. Install platform `android-32`, Build Tools
  `37.0.0`, NDK `27.2.12479018` and CMake `3.22.1` with Ninja.
- Apktool **3.0.3**, and Baksmali **3.0.9-dev** for generated AppData classes.
  Install the JARs as `tools/android/apktool.jar` and `tools/android/baksmali.jar`.
  If needed by auxiliary checks, install matching `tools/android/smali.jar`.
  Tool binaries are deliberately not committed.
- A recursive checkout of [azahar-emu/dynarmic](https://github.com/azahar-emu/dynarmic)
  at `e77b1ba0b7da7cbe93021b01a663acfe7c4dd516`, including its dependency submodules.
- Boost **1.83.0** headers, obtained externally. CMake can download the pinned
  [official release archive](https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.bz2)
  when the wrapper is given `-AllowNetwork`, or use an existing extracted release
  via `-BoostSourceDirectory`. Archive SHA-256:
  `6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e`.
- Your own APK signing key (PKCS8), X.509 certificate and its SHA-256 fingerprint,
  stored outside this repository. These are unrelated to Git commit signing.

The recorded JAR SHA-256 values are:

```text
apktool.jar   dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
baksmali.jar  3ad0aa712038eb21d3ec059db8d88fa12c4d2ecf765ab2470a821074961c0cc6
smali.jar     53a32f0d3e45b00dabc8c0f5a8663e9460f16a6b5116812b0f3d6f99c6e9bbb7
```

## Recreate and build

Run from the repository root in PowerShell. The example paths are placeholders;
replace them with your SDK, JDK, dependency and signing paths.

```powershell
$env:JAVA_HOME = 'C:\path\to\jdk-24.0.1'
$env:ANDROID_SDK_ROOT = 'C:\path\to\Android\Sdk'
$java = Join-Path $env:JAVA_HOME 'bin\java.exe'

python -B tools/prepare_app.py --apktool tools/android/apktool.jar --java $java
```

Preparation verifies all three input hashes, checks the Apktool version, decodes
the original APK, applies the source edits and copies the guest/OBBs. It refuses
to overwrite an existing `app/`. Use `--apk`, `--main`, `--patch` and `--output`
to select different input locations or a separate preparation directory.
`build.sh` packages the root `app/` directory.

Prepare Dynarmic separately (the example downloads source dependencies):

```powershell
git clone https://github.com/azahar-emu/dynarmic.git C:\deps\dynarmic-mc4
git -C C:\deps\dynarmic-mc4 checkout e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
git -C C:\deps\dynarmic-mc4 submodule update --init --recursive
$dynarmicPatch = (Resolve-Path arm64_bridge/patches/dynarmic-e77b1ba-mc4.patch).Path
git -C C:\deps\dynarmic-mc4 apply --check $dynarmicPatch
git -C C:\deps\dynarmic-mc4 apply $dynarmicPatch

.\arm64_bridge\build_arm64.ps1 -BridgeTarget ModernCombat4 -DynarmicSourceDirectory C:\deps\dynarmic-mc4 -AllowNetwork
```

`-AllowNetwork` permits the first Boost download to the ignored build cache
`arm64_bridge/build_arm64/_deps/boost-src/`. The source of neither Boost nor
Dynarmic is committed. For an offline build, extract the verified Boost archive
outside the repository (the directory must contain `boost/version.hpp`) and run:

```powershell
.\arm64_bridge\build_arm64.ps1 -BridgeTarget ModernCombat4 -DynarmicSourceDirectory C:\deps\dynarmic-mc4 -BoostSourceDirectory C:\deps\boost_1_83_0
```

The wrapper builds the native library and writes a source/binary provenance
receipt under `arm64_bridge/dist/`. Do not enable native logging for a normal
build. The receipt records the external Boost location and hashes its headers
alongside the bridge sources. Keep those headers available when packaging.
Always rebuild after source or dependency changes; packaging rejects a stale
receipt. Pre-existing receipts from the vendored-dependency layout must be rebuilt.

Set the signing inputs, then run the packaging script through Git Bash:

```powershell
$env:MC4_SIGN_KEY = 'C:/private/mc4/key.pk8'
$env:MC4_SIGN_CERT = 'C:/private/mc4/cert.pem'
$env:MC4_SIGN_CERT_SHA256 = '<64 hexadecimal SHA-256 digits>'
$env:MC4_APK_NAME = 'MC4_1.2.3e_experimental.apk'
& 'C:\Program Files\Git\bin\bash.exe' ./build.sh
```

Packaging compiles `work/AppData.java`, generates its owned smali classes,
checks bridge provenance, guest/OBB hashes, ABI, ELF/ZIP alignment and signing
certificate, then writes the APK and verification reports to ignored `out/`.
Allow ample free space: the roughly 2.1 GB APK is copied during preparation,
assembly, alignment and signing. Signing with a different key may prevent an
in-place update of an existing installation; preserve your save data yourself.

## Optional unfinished graphics UI experiment

This is development material, not a required step for the baseline build.
To reconstruct the modified AS3 from your own original OBB, install FFDec
**26.2.1** and run:

```powershell
python -B tools/prepare_graphics_source.py --ffdec C:/path/to/ffdec-cli.jar --java $java
python -B work/build_native_graphics_ui.py --ffdec C:/path/to/ffdec-cli.jar --java $java --output-dir work/native-graphics-staging --metadata work/native-graphics-staging/mc4_graphics_ui_asset.h
```

The first command recreates ignored `arm64_bridge/ui/MenuAdvanced.as` using a
hash-checked edit recipe. The second creates four modified movie variants in an
ignored staging directory; original OBBs remain unchanged. Staging is not
automatically packaged. The previous single inert movie is intentionally not
redistributed. Completing UI/preference integration and hardware validation is
still necessary before presenting this as a working graphics settings feature.

## Checks

The preparation recipe has host-only tests with no game inputs:

```powershell
python -B -m unittest discover -s tools -p test_prepare_app.py
python -B -m unittest discover -s arm64_bridge/tests -p test_bridge_provenance.py
python -B -m unittest discover -s arm64_bridge/tests -p test_check_symbols.py
python -B -m unittest discover -s work/obb -p test_verify_obb_apk.py
```

After preparing `app/`, additional checks can read the reconstructed source and
guest library:

```powershell
python -B -m unittest discover -s work -p test_manual_cheat_ui.py
python -B -m unittest discover -s work -p test_orientation_queue.py
python -B -m unittest discover -s work -p test_android_back.py
python -B work/obb/verify_obb_apk.py --verify
.\work\check-app-data.ps1
```

Some native contract tests require a local MSVC C++ installation and Android
NDK headers. The graphics UI tests additionally require reconstructed AS3,
generated movies, Node.js and `MC4_GRAPHICS_UI_DIR` pointing to the staging
directory. Without that staging, failures from the unfinished UI are expected.
Passing source/host checks is not device acceptance.

## License

Original project contributions are licensed under **GPL-3.0-or-later**, a strong
copyleft license. See [LICENSE](LICENSE) and [NOTICE](NOTICE). External
dependencies retain their own licenses and copyright notices.

The license grants no rights to Modern Combat 4 or its game content. You must
supply your own originals and are responsible for any redistribution rights.
This unofficial project is not affiliated with or endorsed by Gameloft.
