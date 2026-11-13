"""Small ZIP fixtures for the signed-APK OBB/guest payload verifier."""

import hashlib
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

import verify_obb_apk as verifier


MAIN = b"MAIN"
PATCH = b"PATCH"
GUEST = b"ELF64"
MAIN_NAME = "assets/obb/main.12222.obb"
PATCH_NAME = "assets/obb/patch.12222.obb"
GUEST_NAME = verifier.GUEST_LIB_STR


class VerifyApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.apk = Path(self.temp.name) / "fixture.apk"
        identities = {
            "MAIN_SIZE": len(MAIN),
            "MAIN_SHA256": hashlib.sha256(MAIN).hexdigest(),
            "PATCH_SIZE": len(PATCH),
            "PATCH_SHA256": hashlib.sha256(PATCH).hexdigest(),
            "GUEST_SIZE": len(GUEST),
            "GUEST_SHA256": hashlib.sha256(GUEST).hexdigest(),
        }
        patcher = mock.patch.multiple(verifier, **identities)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_apk(self, extra=(), main=MAIN, method=zipfile.ZIP_STORED):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.apk, "w") as archive:
                archive.writestr(MAIN_NAME, main, compress_type=method)
                archive.writestr(PATCH_NAME, PATCH, compress_type=zipfile.ZIP_STORED)
                archive.writestr(GUEST_NAME, GUEST, compress_type=zipfile.ZIP_STORED)
                for name, data in extra:
                    archive.writestr(name, data, compress_type=zipfile.ZIP_STORED)

    def test_exact_stored_entries_pass(self):
        self.make_apk()
        verifier.verify_apk(Path(self.temp.name), self.apk)

    def test_same_size_different_payload_fails(self):
        self.make_apk(main=b"FAKE")
        with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
            verifier.verify_apk(Path(self.temp.name), self.apk)

    def test_duplicate_critical_entry_fails(self):
        self.make_apk(extra=((MAIN_NAME, MAIN),))
        with self.assertRaisesRegex(ValueError, "duplicate critical"):
            verifier.verify_apk(Path(self.temp.name), self.apk)

    def test_compressed_critical_entry_fails(self):
        self.make_apk(method=zipfile.ZIP_DEFLATED)
        with self.assertRaisesRegex(ValueError, "not STORED"):
            verifier.verify_apk(Path(self.temp.name), self.apk)

    def test_loose_data_pack_fails(self):
        self.make_apk(extra=(("assets/data_4", b"x"),))
        with self.assertRaisesRegex(ValueError, "loose data pack"):
            verifier.verify_apk(Path(self.temp.name), self.apk)


if __name__ == "__main__":
    unittest.main()
