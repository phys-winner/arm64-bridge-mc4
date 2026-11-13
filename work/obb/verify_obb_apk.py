#!/usr/bin/env python3
"""Verify the OBB-in-APK asset layout (2026-09-17 directive).

  --verify      : app/assets carries the two verbatim OBB containers and no
                  leftover loose data packs; the guest library stays loose.
  --verify-apk P: stream and hash the two STORED OBB entries and guest ELF in
                  the signed APK; reject duplicates and loose data packs.
"""
import hashlib
import sys
import zipfile
from pathlib import Path

# Keep the original main OBB byte-for-byte. Offline MP lists are supplied by
# the VFS as valid four-byte empty arrays; they do not belong in the OBB.
MAIN_SHA256 = "c47c0fff7bfb56f158fa8bd2ef2c6b47caac30c6e48f0cbc91c4ee40931fcd1c"
PATCH_SHA256 = "14f53062d1d6a5ad7b02aff603b9b6de09bcac8945fd135301b7f8bc2f0dd670"
MAIN_SIZE = 2052015324
PATCH_SIZE = 15093838
GUEST_LIB = Path("assets/guest_libs/libModernCombat4.so")
GUEST_LIB_STR = "assets/guest_libs/libModernCombat4.so"
GUEST_SIZE = 24855648
GUEST_SHA256 = "f5bcb8e6071cc1b0e09d200922dd2914e971ccbf5002981e8416481fe5b45ba1"


def stream_sha256(stream) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        h.update(chunk)
    return h.hexdigest()


def sha256(path: Path) -> str:
    with open(path, "rb") as stream:
        return stream_sha256(stream)


def verify(root: Path) -> None:
    assets = root / "app" / "assets"
    main = assets / "obb" / "main.12222.obb"
    patch = assets / "obb" / "patch.12222.obb"
    for p in (main, patch):
        if not p.is_file():
            raise ValueError(f"missing OBB asset: {p}")
    if main.stat().st_size != MAIN_SIZE:
        raise ValueError(f"main OBB size {main.stat().st_size} != {MAIN_SIZE}")
    if patch.stat().st_size != PATCH_SIZE:
        raise ValueError(f"patch OBB size {patch.stat().st_size} != {PATCH_SIZE}")
    if sha256(main) != MAIN_SHA256:
        raise ValueError("main OBB sha256 mismatch (must be byte-for-byte original main.1100)")
    if sha256(patch) != PATCH_SHA256:
        raise ValueError("patch OBB sha256 mismatch (must be verbatim patch.12222)")
    leftovers = [p.name for p in assets.iterdir()
                 if p.is_file() and (p.name.startswith("data_") or p.name == "eventParameters.json")]
    if (assets / "phase3_main").exists():
        raise ValueError("assets/phase3_main must be gone (members live in main.12222.obb)")
    if leftovers:
        raise ValueError(f"loose data packs must live inside the OBB now: {leftovers}")
    guest = assets / GUEST_LIB.relative_to("assets")
    if not guest.is_file():
        raise ValueError("guest library missing from app/assets")
    if guest.stat().st_size != GUEST_SIZE or sha256(guest) != GUEST_SHA256:
        raise ValueError("guest library is not the exact original ARM32 ELF")
    print("obb_assets verify=OK")


def verify_apk(root: Path, apk: Path) -> None:
    del root  # The signed artifact is checked against immutable identities above.
    expected = {
        "assets/obb/main.12222.obb": (MAIN_SIZE, MAIN_SHA256),
        "assets/obb/patch.12222.obb": (PATCH_SIZE, PATCH_SHA256),
        GUEST_LIB_STR: (GUEST_SIZE, GUEST_SHA256),
    }
    found = {}
    # ZipFile reads the central directory, not the multi-gigabyte APK payload.
    # Opening each named STORED entry validates its local header and CRC while
    # stream_sha256 checks the actual packaged bytes against the originals.
    with zipfile.ZipFile(apk, "r") as archive:
        for entry in archive.infolist():
            name = entry.filename
            if name.startswith("assets/data_") or name.startswith("assets/phase3_main/"):
                raise ValueError(f"loose data pack still in the APK: {name}")
            if name not in expected:
                continue
            if name in found:
                raise ValueError(f"duplicate critical APK entry: {name}")
            if entry.compress_type != zipfile.ZIP_STORED or entry.compress_size != entry.file_size:
                raise ValueError(f"critical APK entry is not STORED: {name}")
            size, _ = expected[name]
            if entry.file_size != size:
                raise ValueError(f"critical APK entry has wrong size: {name}")
            found[name] = entry
        missing = expected.keys() - found.keys()
        if missing:
            raise ValueError(f"critical APK entries missing: {sorted(missing)}")
        for name, entry in found.items():
            with archive.open(entry, "r") as stream:
                digest = stream_sha256(stream)
            if digest != expected[name][1]:
                raise ValueError(f"critical APK entry sha256 mismatch: {name}")
    print("obb_apk verify=OK (main+patch+guest STORED and SHA-256 matched, no duplicates/loose packs)")


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    args = sys.argv[1:]
    if "--verify" in args:
        verify(root)
    apk = None
    if "--verify-apk" in args:
        apk = Path(args[args.index("--verify-apk") + 1])
        verify_apk(root, apk)
    return 0


if __name__ == "__main__":
    sys.exit(main())
