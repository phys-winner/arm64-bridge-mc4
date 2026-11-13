"""Ensure bridge diagnostics cannot drain the guest's GLES error state.

This is a source preflight; the signed-APK device route is a separate gate.
"""

from pathlib import Path
import re
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "src" / "thunks_gl.cpp").read_text(
    encoding="utf-8"
)


class GlErrorSourceContract(unittest.TestCase):
    def test_only_guest_get_error_thunk_consumes_error(self) -> None:
        calls = list(re.finditer(r"\bglGetError\s*\(\s*\)", SOURCE))
        self.assertEqual(1, len(calls), "host probes must not drain GLES errors")
        thunk = SOURCE.index('RegisterThunk("glGetError",')
        self.assertGreater(calls[0].start(), thunk)

    def test_shader_creation_forwards_type_without_probe(self) -> None:
        start = SOURCE.index('RegisterThunk("glCreateShader",')
        end = SOURCE.index('RegisterThunk("glCullFace",', start)
        body = SOURCE[start:end]
        self.assertIn(
            "jit.Regs()[0] = glCreateShader(static_cast<GLenum>(jit.Regs()[0]));",
            body,
        )
        self.assertNotIn("[GLTRACE]", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
