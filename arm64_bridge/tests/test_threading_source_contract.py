"""Offline preflight for the *active* MC4 guest-threading path.

This deliberately fails on known contract violations. It is a source-level
regression gate, not a substitute for the behavioral test in
THREADING_HOST_TEST_DESIGN.md. No bridge build, network, or device is used.
"""

from pathlib import Path
import re
import unittest


BRIDGE = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (BRIDGE / relative_path).read_text(encoding="utf-8")


def body_after(text: str, marker: str) -> str:
    """Return a C++ body at a unique marker, failing closed on source changes."""
    if text.count(marker) != 1:
        raise AssertionError(f"expected one occurrence of {marker!r}, found {text.count(marker)}")
    start = text.index("{", text.index(marker) + len(marker))
    depth = 0
    for position in range(start, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:position]
    raise AssertionError(f"unclosed body after {marker!r}")


class ActiveThreadingSourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cmake = source("CMakeLists.txt")
        cls.manager = source("src/thunk_manager.cpp")
        cls.libc = source("src/thunks_libc.cpp")
        cls.host = source("src/dynarmic_host.cpp")

    def test_active_implementation_is_known(self) -> None:
        bridge_sources = self.cmake.split("set(BRIDGE_SOURCES", 1)[1].split("add_library", 1)[0]
        self.assertIn("src/thunks_libc.cpp", bridge_sources)
        self.assertNotIn("src/thunks_threading.cpp", bridge_sources,
                         "Active registration changed; review this preflight against the new build")
        registrations = body_after(self.manager, "void ThunkManager::RegisterAllThunks()")
        self.assertIn("RegisterLibcThunks();", registrations)
        self.assertNotIn("RegisterThreadingThunks", registrations,
                         "Active registration changed; review this preflight against the new build")

    def test_mutex_operations_do_not_report_false_success(self) -> None:
        for name in ("pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_trylock"):
            with self.subTest(name=name):
                body = body_after(self.libc, f'RegisterThunk("{name}",')
                compact = re.sub(r"\s+", "", body)
                self.assertNotEqual("jit.Regs()[0]=0;", compact,
                                    f"{name} currently returns success without touching a mutex")

    def test_condition_wait_receives_guest_mutex_and_timeout_result(self) -> None:
        for name in ("pthread_cond_wait", "pthread_cond_timedwait"):
            with self.subTest(name=name):
                body = body_after(self.libc, f'RegisterThunk("{name}",')
                self.assertIn("jit.Regs()[1]", body,
                              f"{name} discards the mutex argument needed for unlock-wait-relock")
                self.assertNotRegex(body, r"jit\.Regs\(\)\[0\]\s*=\s*0\s*;",
                                    f"{name} must return the wait result, not unconditional success")

    def test_signal_is_not_broadcast(self) -> None:
        body = body_after(self.host, "int DynarmicHost::GuestCondSignal(")
        self.assertIn("pthread_cond_signal(&value->native)", body)
        self.assertIn("pthread_cond_broadcast(&value->native)", body)
        self.assertNotIn("(void)all;", body, "signal/broadcast selector is discarded")

    def test_parked_worker_does_not_own_only_worker_jit_slot(self) -> None:
        body = body_after(self.host, "uint32_t DynarmicHost::RunWorkerFunction(")
        self.assertIn("m_worker_cores_cv.wait", body)
        self.assertIn("slot.in_use = true", body)
        self.assertIn("config.processor_id = slot_index + 1", body)
        self.assertIn("core->Run()", body)
        self.assertIn("release_slot();", body)
        self.assertNotIn("m_worker_mutex", body,
                         "One worker mutex must not be held across a parked JIT")
        self.assertIn("ExclusiveMonitor>(kMaxWorkerCores + 1)", self.host)
        invalidate = body_after(self.host, "void DynarmicHost::InvalidateGuestCode(")
        self.assertIn("for (auto& slot : m_worker_cores)", invalidate)
        self.assertIn("slot.jit->InvalidateCacheRange(addr, size)", invalidate)

    def test_worker_cache_invalidation_is_resumed(self) -> None:
        body = body_after(self.host, "uint32_t DynarmicHost::RunWorkerFunction(")
        self.assertIn("if (hr != Dynarmic::HaltReason::CacheInvalidation) break;", body)

    def test_join_waits_for_real_guest_completion(self) -> None:
        created = body_after(self.libc, 'RegisterThunk("pthread_create",')
        joined = body_after(self.libc, 'RegisterThunk("pthread_join",')
        detached = body_after(self.libc, 'RegisterThunk("pthread_detach",')
        self.assertIn("g_guest_threads.emplace(id, completion)", created)
        self.assertIn("completion->finished = true", created)
        self.assertIn("completion->changed.wait(lock", joined)
        self.assertIn("host.MemoryWrite32(result_out, result)", joined)
        self.assertIn("completion->detached = true", detached)

    def test_semaphore_uses_guest_atomic_word_and_futex(self) -> None:
        wait = body_after(self.libc, "static uint32_t GuestSemWait(")
        post = body_after(self.libc, "static uint32_t GuestSemPost(")
        trywait = body_after(self.libc, "static uint32_t GuestSemTryWait(")
        self.assertIn("__atomic_compare_exchange_n", wait)
        self.assertIn("SYS_futex", wait)
        self.assertIn("FUTEX_WAIT_PRIVATE", wait)
        self.assertIn("__atomic_compare_exchange_n", post)
        self.assertIn("FUTEX_WAKE_PRIVATE", post)
        self.assertIn("GuestSemError(host, EAGAIN)", trywait)
        self.assertEqual(self.libc.count('RegisterThunk("sem_post",'), 1)

    def test_once_completes_after_guest_initializer_returns(self) -> None:
        called = body_after(self.libc, 'RegisterThunk("pthread_once",')
        completed = body_after(self.libc, '"__mc4_pthread_once_complete",')
        self.assertIn("__atomic_compare_exchange_n(word, &state, 1u", called)
        self.assertIn("g_guest_once_continuations.push_back", called)
        self.assertIn("jit.Regs()[14] = once_complete", called)
        self.assertIn("FUTEX_WAIT_PRIVATE", called)
        self.assertIn("__atomic_store_n(word, 2u, __ATOMIC_RELEASE)", completed)
        self.assertIn("FUTEX_WAKE_PRIVATE", completed)
        self.assertIn("frame.return_address", completed)

    def test_errno_uses_the_same_guest_tls_slot_as_kuser(self) -> None:
        address = body_after(self.libc, "static uint32_t GuestErrnoAddress(")
        get_errno = body_after(self.libc, 'RegisterThunk("__errno",')
        write_errno = body_after(self.libc, "static void WriteGuestErrno(")
        self.assertIn("host.GuestThreadTls()", address)
        self.assertIn("2u * sizeof(uint32_t)", address)
        self.assertIn("GuestErrnoAddress(host)", get_errno)
        self.assertIn("GuestErrnoAddress(host)", write_errno)
        self.assertNotIn("0x300", self.libc)

    def test_pthread_keys_use_guest_tls_and_worker_exit_cleanup(self) -> None:
        created = body_after(self.libc, 'RegisterThunk("pthread_key_create",')
        set_value = body_after(self.libc, 'RegisterThunk("pthread_setspecific",')
        get_value = body_after(self.libc, 'RegisterThunk("pthread_getspecific",')
        deleted = body_after(self.libc, 'RegisterThunk("pthread_key_delete",')
        worker = body_after(self.libc, 'RegisterThunk("pthread_create",')
        destructor = body_after(self.libc, 'static void RunGuestTlsDestructors(')
        self.assertIn("uint32_t key = 7", created)
        self.assertIn("jit.Regs()[0] = ENOMEM", created)
        self.assertIn("host.GuestThreadTls()", set_value)
        self.assertIn("tls + key * 4u", set_value)
        self.assertIn("host.GuestThreadTls()", get_value)
        self.assertIn("host.GuestClearTlsSlotForAllThreads(key)", deleted)
        self.assertIn("RunGuestTlsDestructors(*host_ptr)", worker)
        self.assertIn("host_ptr->ReleaseGuestThreadTls()", worker)
        self.assertIn("host.RunWorkerFunction(destructor, {value})", destructor)
        self.assertNotIn("g_tls_map", self.libc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
