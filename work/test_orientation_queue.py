"""The sensor callback must not wait on the renderer's native/JIT lock."""
from pathlib import Path
import unittest

from test_manual_cheat_ui import method_body

GLF = Path(__file__).resolve().parents[1] / "app/smali/com/gameloft/glf"


class OrientationQueueContract(unittest.TestCase):
    def test_native_orientation_pair_runs_on_gl_thread(self):
        sensor = (GLF / "c.smali").read_text(encoding="utf-8")
        callback = method_body(sensor, "onOrientationChanged")
        self.assertNotIn("->setCurrentOrientation(I)V", callback)
        self.assertNotIn("GL2JNILib;->orientationChanged(I)V", callback)
        self.assertIn("->setRequestedOrientation(I)V", callback)
        self.assertIn("->queueOrientation(II)V", callback)
        producer = method_body(sensor, "queueOrientation")
        self.assertNotIn("GL2JNILib;", producer)
        self.assertIn("->a(Ljava/lang/Runnable;)V", producer)
        runnable = (GLF / "OrientationEvent.smali").read_text(encoding="utf-8")
        self.assertIn(".field private final current:I", runnable)
        self.assertIn(".field private final direction:I", runnable)
        consumer = method_body(runnable, "run")
        self.assertIn("if-ltz v0, :direction", consumer)
        self.assertLess(consumer.index("->setCurrentOrientation(I)V"),
                        consumer.index("->orientationChanged(I)V"))
        thread = (GLF / "GLSurfaceView$GLThread.smali").read_text(encoding="utf-8")
        loop = method_body(thread, "k")
        self.assertLess(loop.index("monitor-exit v10", loop.index(":goto_3")),
                        loop.index("Ljava/lang/Runnable;->run()V"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
