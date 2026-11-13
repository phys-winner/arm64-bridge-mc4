#!/usr/bin/env python3
"""Recreate the port's Android tree from a user-supplied, hash-pinned APK/OBBs."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APK_SHA256 = "1e04565e70f7df372d9ece386a37eb07d0a11cb4b6536d8c9f6aa5ddf58d6797"
INPUTS = (
    ("main", "c47c0fff7bfb56f158fa8bd2ef2c6b47caac30c6e48f0cbc91c4ee40931fcd1c"),
    ("patch", "14f53062d1d6a5ad7b02aff603b9b6de09bcac8945fd135301b7f8bc2f0dd670"),
)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_path(root, name):
    relative = PurePosixPath(name)
    if not relative.parts or relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
        raise ValueError(f"Unsafe recipe path: {name}")
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Recipe path escapes output: {name}")
    return path


def normalized(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def apply_edits(source, record):
    if hashlib.sha256(source.encode()).hexdigest() != record["before_sha256"]:
        raise ValueError(f"Source mismatch: {record['path']}; use Apktool 3.0.3")
    lines = source.splitlines(keepends=True)
    previous = len(lines)
    for start, count, replacement in record["edits"]:
        if not 0 <= start <= start + count <= previous:
            raise ValueError(f"Invalid edit range: {record['path']}")
        lines[start:start + count] = replacement.splitlines(keepends=True)
        previous = start
    result = "".join(lines)
    if hashlib.sha256(result.encode()).hexdigest() != record["after_sha256"]:
        raise ValueError(f"Result mismatch: {record['path']}")
    return result


def apply_recipe(decoded, recipe, additions):
    # Read relocated inputs before pruning the original namespaces.
    results = [(checked_path(decoded, record["path"]),
                apply_edits(normalized(checked_path(decoded, record.get("source", record["path"]))), record))
               for record in recipe["changes"]]
    keep = set(recipe["keep"])
    for path in decoded.rglob("*"):
        if path.is_file() and path.relative_to(decoded).as_posix() not in keep:
            path.unlink()
    for path, text in results:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    for name, expected in recipe["additions"].items():
        source = checked_path(additions, name)
        if sha256(source) != expected:
            raise ValueError(f"Addition checksum mismatch: {name}")
        target = checked_path(decoded, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for directory in sorted((p for p in decoded.rglob("*") if p.is_dir()), reverse=True):
        if not any(directory.iterdir()):
            directory.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, default=ROOT / "original/MC4_1.2.3e.apk")
    parser.add_argument("--main", type=Path, default=ROOT / "original/obb/main.1100.com.gameloft.android.ANMP.GloftM4HM.obb")
    parser.add_argument("--patch", type=Path, default=ROOT / "original/obb/patch.12222.com.gameloft.android.ANMP.GloftM4HM.obb")
    parser.add_argument("--apktool", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--output", type=Path, default=ROOT / "app")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"Output already exists; it will not be overwritten: {args.output}")
    for path, expected in [(args.apk, APK_SHA256)] + [(getattr(args, name), digest) for name, digest in INPUTS]:
        if sha256(path) != expected:
            parser.error(f"Input SHA-256 mismatch: {path}")
    version = subprocess.check_output([args.java, "-jar", str(args.apktool), "--version"], text=True).strip()
    if version != "3.0.3":
        parser.error(f"Apktool 3.0.3 required; found {version}")
    recipe = json.loads((ROOT / "patches/android/recipe.json").read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mc4-prepare-", dir=args.output.parent) as temporary:
        temporary = Path(temporary)
        decoded = temporary / "app"
        subprocess.run([args.java, "-jar", str(args.apktool), "d", "-o", str(decoded), str(args.apk)], check=True)
        guest = temporary / "guest.so"
        shutil.copyfile(decoded / "lib/armeabi-v7a/libModernCombat4.so", guest)
        if sha256(guest) != "f5bcb8e6071cc1b0e09d200922dd2914e971ccbf5002981e8416481fe5b45ba1":
            raise ValueError("Original guest library SHA-256 mismatch")
        apply_recipe(decoded, recipe, ROOT / "patches/android/additions")
        target = decoded / "assets/guest_libs/libModernCombat4.so"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(guest, target)
        (decoded / "assets/obb").mkdir(parents=True, exist_ok=True)
        for name, _ in INPUTS:
            shutil.copyfile(getattr(args, name), decoded / f"assets/obb/{name}.12222.obb")
        decoded.rename(args.output)
    print(f"Prepared {args.output}; build the bridge, then run build.sh")


if __name__ == "__main__":
    main()
