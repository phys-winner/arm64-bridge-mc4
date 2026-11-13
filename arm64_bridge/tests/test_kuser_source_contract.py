"""Fail-closed checks for the active ARM kuser synchronization thunks."""

from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "src" / "dynarmic_host.cpp").read_text(encoding="utf-8")


class KuserSourceContract(unittest.TestCase):
    def test_cmpxchg_is_one_atomic_operation(self):
        start = SOURCE.index('kuser("kuser_cmpxchg"')
        end = SOURCE.index('kuser("kuser_get_tls"', start)
        body = SOURCE[start:end]
        self.assertIn("mc4::GuestAtomicCompareExchange", body)
        self.assertNotIn("host.MemoryRead32(ptr)", body)
        self.assertNotIn("host.MemoryWrite32(ptr", body)

    def test_cmpxchg_sets_result_carry(self):
        start = SOURCE.index('kuser("kuser_cmpxchg"')
        end = SOURCE.index('kuser("kuser_get_tls"', start)
        body = SOURCE[start:end]
        self.assertIn("mc4::KuserCpsrWithCarry", body)
        self.assertRegex(body, r"jit\.SetCpsr\s*\(")

    def test_memory_barrier_is_not_a_noop(self):
        start = SOURCE.index('kuser("kuser_memory_barrier"')
        end = SOURCE.index('kuser("kuser_cmpxchg"', start)
        self.assertIn("mc4::GuestMemoryBarrier", SOURCE[start:end])

    def test_exclusive_stores_share_atomic_primitive(self):
        start = SOURCE.index("static bool GuestCompareAndSwap(")
        end = SOURCE.index("bool DynarmicHost::MemoryWriteExclusive8", start)
        body = SOURCE[start:end]
        self.assertIn("mc4::GuestAtomicCompareExchange", body)
        self.assertNotIn("*p = value", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
