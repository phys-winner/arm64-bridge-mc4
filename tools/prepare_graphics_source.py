#!/usr/bin/env python3
"""Recreate the unfinished AS3 settings experiment without bundling game scripts."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from prepare_app import ROOT, apply_edits

sys.path.insert(0, str(ROOT / "work"))
from build_native_graphics_ui import original_movie


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ffdec", type=Path, required=True, help="FFDec 26.2.1 CLI JAR")
    parser.add_argument("--java", default="java")
    args = parser.parse_args()
    target = ROOT / "arm64_bridge/ui/MenuAdvanced.as"
    if target.exists():
        parser.error(f"Refusing to overwrite {target}")
    record = json.loads((ROOT / "patches/menu_advanced.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="mc4-as3-") as temporary:
        temporary = Path(temporary)
        movie = temporary / "original.swf"
        movie.write_bytes(original_movie())
        subprocess.run([args.java, "-jar", str(args.ffdec), "-selectclass",
                        "scriptsMC4.singleplayer.settings.MenuAdvanced", "-export", "script",
                        str(temporary / "export"), str(movie)], check=True)
        source = temporary / "export/scripts/scriptsMC4/singleplayer/settings/MenuAdvanced.as"
        result = apply_edits(source.read_text(encoding="utf-8"), record)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(result, encoding="utf-8", newline="\n")
    print(target)


if __name__ == "__main__":
    main()
