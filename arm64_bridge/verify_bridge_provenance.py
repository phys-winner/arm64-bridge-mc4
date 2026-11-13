#!/usr/bin/env python3
"""Bind a built bridge ELF to the exact local sources that produced it."""
import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT_FILES = ("CMakeLists.txt", "build_arm64.ps1")
ROOT_TREES = ("src",)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def source_fingerprint(root, boost_root):
    root = Path(root).resolve()
    paths = [root / name for name in ROOT_FILES]
    for name in ROOT_TREES:
        directory = root / name
        if not directory.is_dir():
            raise ValueError(f"bridge source input is missing: {name}")
        paths.extend(path for path in directory.rglob("*") if path.is_file())

    inputs = [(path.relative_to(root).as_posix(), path) for path in paths]
    boost_headers = Path(boost_root).resolve() / "boost"
    if not (boost_headers / "version.hpp").is_file():
        raise ValueError("external Boost headers are missing; rebuild with Boost 1.83.0")
    inputs.extend(("external/boost/" + path.relative_to(boost_headers).as_posix(), path)
                  for path in boost_headers.rglob("*") if path.is_file())

    digest = hashlib.sha256()
    for relative, path in sorted(inputs):
        if not path.is_file():
            raise ValueError(f"bridge source input is missing: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest().upper()


def make_manifest(root, bridge, target, boost_root):
    return {
        "schema": 2,
        "target": target,
        "abi": "arm64-v8a",
        "source_sha256": source_fingerprint(root, boost_root),
        "boost_source_directory": str(Path(boost_root).resolve()),
        "bridge_sha256": sha256_file(bridge),
    }


def write_manifest(root, bridge, manifest_path, target, boost_root):
    manifest = make_manifest(root, bridge, target, boost_root)
    path = Path(manifest_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(root, bridge, manifest_path, target, boost_root=None):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema") != 2:
        raise ValueError("unsupported bridge provenance schema")
    if manifest.get("target") != target or manifest.get("abi") != "arm64-v8a":
        raise ValueError("bridge provenance target/ABI does not match this package")
    boost_root = boost_root or manifest.get("boost_source_directory")
    if not boost_root:
        raise ValueError("bridge provenance is missing the external Boost location")
    if manifest.get("source_sha256") != source_fingerprint(root, boost_root):
        raise ValueError("bridge is stale: source fingerprint differs; rebuild arm64_bridge first")
    if manifest.get("bridge_sha256") != sha256_file(bridge):
        raise ValueError("bridge ELF differs from the binary recorded in its provenance")
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--boost-root", type=Path, help="External Boost 1.83.0 root (required when writing)")
    args = parser.parse_args()
    if args.mode == "write" and args.boost_root is None:
        parser.error("--boost-root is required when writing provenance")

    try:
        if args.mode == "write":
            result = write_manifest(args.root, args.bridge, args.manifest, args.target, args.boost_root)
            print("bridge provenance written: source=%s bridge=%s" %
                  (result["source_sha256"], result["bridge_sha256"]))
        else:
            result = verify_manifest(args.root, args.bridge, args.manifest, args.target, args.boost_root)
            print("bridge provenance verified: target=%s abi=%s source=%s bridge=%s" %
                  (result["target"], result["abi"], result["source_sha256"], result["bridge_sha256"]))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"bridge provenance error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
