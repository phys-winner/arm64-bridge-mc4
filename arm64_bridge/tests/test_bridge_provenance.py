#!/usr/bin/env python3
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_bridge_provenance import verify_manifest, write_manifest


class BridgeProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "bridge"
        (self.root / "src").mkdir(parents=True)
        self.boost = Path(self.temp.name) / "external-boost"
        (self.boost / "boost").mkdir(parents=True)
        (self.root / "CMakeLists.txt").write_text("project(test)\n", encoding="utf-8")
        (self.root / "build_arm64.ps1").write_text("build\n", encoding="utf-8")
        (self.root / "src/jni_bridge.cpp").write_text("void bridge() {}\n", encoding="utf-8")
        (self.boost / "boost/version.hpp").write_text("#define BOOST_VERSION 108300\n", encoding="utf-8")
        self.bridge = Path(self.temp.name) / "libModernCombat4.so"
        self.bridge.write_bytes(b"arm64-elf-fixture")
        self.manifest = Path(self.temp.name) / "bridge.provenance.json"
        write_manifest(self.root, self.bridge, self.manifest, "ModernCombat4", self.boost)

    def tearDown(self):
        self.temp.cleanup()

    def verify(self, target="ModernCombat4"):
        return verify_manifest(self.root, self.bridge, self.manifest, target)

    def test_exact_source_and_binary_pass(self):
        self.assertEqual(self.verify()["abi"], "arm64-v8a")

    def test_changed_source_fails_closed(self):
        (self.root / "src/jni_bridge.cpp").write_text("void changed() {}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source fingerprint"):
            self.verify()

    def test_changed_binary_fails_closed(self):
        self.bridge.write_bytes(b"different-elf")
        with self.assertRaisesRegex(ValueError, "binary recorded"):
            self.verify()

    def test_wrong_target_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "target/ABI"):
            self.verify("arm32_bridge")

    def test_changed_external_headers_fail_closed(self):
        (self.boost / "boost/version.hpp").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source fingerprint"):
            self.verify()

    def test_missing_external_headers_fail_closed(self):
        (self.boost / "boost/version.hpp").unlink()
        with self.assertRaisesRegex(ValueError, "external Boost headers are missing"):
            self.verify()

    def test_dependency_location_does_not_affect_fingerprint(self):
        relocated = Path(self.temp.name) / "relocated-boost"
        shutil.copytree(self.boost, relocated)
        self.assertEqual(verify_manifest(self.root, self.bridge, self.manifest, "ModernCombat4", relocated)["schema"], 2)


if __name__ == "__main__":
    unittest.main()
