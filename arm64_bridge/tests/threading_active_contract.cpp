// Executable contract probe for the active MC4 ARM32 pthread thunks.
// Run modes separately under an external hard deadline; each process uses
// the actual RegisterAllThunks -> SVC -> DynarmicHost dispatch path.
#include "dynarmic_host.h"
#include "thunk_manager.h"

#include <cerrno>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <thread>
#include <vector>

namespace {
[[noreturn]] void Fail(const char* what, uint32_t actual, uint32_t expected) {
    std::fprintf(stderr, "FAIL %s: actual=%u expected=%u\n", what, actual, expected);
    std::fflush(stderr);
    std::_Exit(1);
}

void Expect(const char* what, uint32_t actual, uint32_t expected) {
    if (actual != expected) Fail(what, actual, expected);
}

uint32_t Call(DynarmicHost& host, const char* name,
              const std::vector<uint32_t>& args) {
    const uint32_t entry = host.GetThunkManager().FindThunkAddress(name);
    if (!entry) Fail("registered thunk address", 0, 1);
    return host.RunFunction(entry, args);
}

uint32_t WorkerWrapper(DynarmicHost& host, const char* name) {
    const uint32_t thunk = host.GetThunkManager().FindThunkAddress(name);
    if (!thunk) Fail("worker thunk address", 0, 1);
    const uint32_t entry = host.GuestAlloc(20);
    if (!entry) Fail("worker wrapper allocation", 0, 1);
    const uint32_t words[] = {0xe92d4010u, 0xe59f4004u, 0xe12fff34u,
                              0xe8bd8010u, thunk};
    std::memcpy(host.GetGuestMemoryBase() + entry, words, sizeof(words));
    host.AddExecutableRange(entry, sizeof(words));
    return entry;
}

void MutexContract(DynarmicHost& host) {
    const uint32_t mutex = host.GuestAlloc(4);
    if (!mutex) Fail("guest mutex allocation", 0, 1);
    Expect("pthread_mutex_init", Call(host, "pthread_mutex_init", {mutex, 0}), 0);
    Expect("pthread_mutex_lock", Call(host, "pthread_mutex_lock", {mutex}), 0);
    Expect("pthread_mutex_trylock while held", Call(host, "pthread_mutex_trylock", {mutex}), EBUSY);
    Expect("destroy owned mutex", Call(host, "pthread_mutex_destroy", {mutex}), EBUSY);
    const uint32_t foreign_unlock = WorkerWrapper(host, "pthread_mutex_unlock");
    uint32_t foreign_rc = 0;
    std::thread wrong_owner([&] { foreign_rc = host.RunWorkerFunction(foreign_unlock, {mutex}); });
    wrong_owner.join();
    Expect("wrong-thread unlock", foreign_rc, EPERM);
    Expect("pthread_mutex_unlock", Call(host, "pthread_mutex_unlock", {mutex}), 0);
    Expect("pthread_mutex_trylock after unlock", Call(host, "pthread_mutex_trylock", {mutex}), 0);
    Expect("pthread_mutex_unlock after trylock", Call(host, "pthread_mutex_unlock", {mutex}), 0);
    Expect("pthread_mutex_destroy", Call(host, "pthread_mutex_destroy", {mutex}), 0);
    const uint32_t static_mutex = host.GuestAlloc(4);
    Expect("static-initializer trylock", Call(host, "pthread_mutex_trylock", {static_mutex}), 0);
    Expect("static-initializer unlock", Call(host, "pthread_mutex_unlock", {static_mutex}), 0);
    Expect("static-initializer destroy", Call(host, "pthread_mutex_destroy", {static_mutex}), 0);

    const uint32_t attr = host.GuestAlloc(4);
    const uint32_t recursive = host.GuestAlloc(4);
    Expect("pthread_mutexattr_init", Call(host, "pthread_mutexattr_init", {attr}), 0);
    Expect("pthread_mutexattr_settype recursive",
           Call(host, "pthread_mutexattr_settype", {attr, 1}), 0);
    Expect("recursive mutex init", Call(host, "pthread_mutex_init", {recursive, attr}), 0);
    Expect("recursive first lock", Call(host, "pthread_mutex_lock", {recursive}), 0);
    Expect("recursive same-owner trylock", Call(host, "pthread_mutex_trylock", {recursive}), 0);
    Expect("recursive first unlock", Call(host, "pthread_mutex_unlock", {recursive}), 0);
    uint32_t recursive_foreign = 0;
    const uint32_t foreign_trylock = WorkerWrapper(host, "pthread_mutex_trylock");
    std::thread recursive_peer([&] {
        recursive_foreign = host.RunWorkerFunction(foreign_trylock, {recursive});
    });
    recursive_peer.join();
    Expect("recursive remains owned after one unlock", recursive_foreign, EBUSY);
    Expect("recursive second unlock", Call(host, "pthread_mutex_unlock", {recursive}), 0);
    Expect("recursive mutex destroy", Call(host, "pthread_mutex_destroy", {recursive}), 0);
    Expect("pthread_mutexattr_settype errorcheck",
           Call(host, "pthread_mutexattr_settype", {attr, 2}), 0);
    Expect("errorcheck mutex init", Call(host, "pthread_mutex_init", {recursive, attr}), 0);
    Expect("errorcheck first lock", Call(host, "pthread_mutex_lock", {recursive}), 0);
    Expect("errorcheck duplicate lock", Call(host, "pthread_mutex_lock", {recursive}), EDEADLK);
    Expect("errorcheck unlock", Call(host, "pthread_mutex_unlock", {recursive}), 0);
    Expect("errorcheck destroy", Call(host, "pthread_mutex_destroy", {recursive}), 0);
    Expect("pthread_mutexattr_destroy", Call(host, "pthread_mutexattr_destroy", {attr}), 0);
    std::puts("PASS mutex ownership through active ARM32 SVC thunks");
}

void TimedWaitContract(DynarmicHost& host) {
    const uint32_t mutex = host.GuestAlloc(4);
    const uint32_t cond = host.GuestAlloc(4);
    const uint32_t deadline = host.GuestAlloc(8);
    if (!mutex || !cond || !deadline) Fail("guest wait allocation", 0, 1);
    Expect("pthread_mutex_init", Call(host, "pthread_mutex_init", {mutex, 0}), 0);
    Expect("pthread_cond_init", Call(host, "pthread_cond_init", {cond, 0}), 0);
    Expect("pthread_mutex_lock", Call(host, "pthread_mutex_lock", {mutex}), 0);
    host.MemoryWrite32(deadline, static_cast<uint32_t>(std::time(nullptr) - 1));
    host.MemoryWrite32(deadline + 4, 0);
    Expect("expired pthread_cond_timedwait",
           Call(host, "pthread_cond_timedwait", {cond, mutex, deadline}), ETIMEDOUT);
    Expect("mutex owned again after timeout",
           Call(host, "pthread_mutex_trylock", {mutex}), EBUSY);
    Expect("pthread_mutex_unlock", Call(host, "pthread_mutex_unlock", {mutex}), 0);
    Expect("pthread_cond_destroy", Call(host, "pthread_cond_destroy", {cond}), 0);
    Expect("pthread_mutex_destroy", Call(host, "pthread_mutex_destroy", {mutex}), 0);
    std::puts("PASS absolute timeout and mutex reacquire through active ARM32 SVC thunks");
}

void WorkerConcurrencyContract(DynarmicHost& host) {
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    unsigned entered = 0;
    unsigned completed = 0;
    bool first_timed_out = false;
    const uint32_t probe = host.GetThunkManager().RegisterThunk(
        "contract_worker_entry", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            std::unique_lock lock(gate_mutex);
            const bool first = ++entered == 1;
            gate_cv.notify_all();
            if (first && !gate_cv.wait_for(lock, std::chrono::seconds(4),
                                           [&] { return entered == 2; })) {
                first_timed_out = true;
            }
            ++completed;
            gate_cv.notify_all();
            jit.Regs()[0] = 0;
        });

    // ARM32: push {r4,lr}; ldr r4,[pc,#4]; blx r4; pop {r4,pc}; .word probe
    // This is real guest code, not a direct native invocation of the handler.
    const uint32_t entry = host.GuestAlloc(20);
    const uint32_t words[] = {0xe92d4010u, 0xe59f4004u, 0xe12fff34u,
                              0xe8bd8010u, probe};
    std::memcpy(host.GetGuestMemoryBase() + entry, words, sizeof(words));
    host.AddExecutableRange(entry, sizeof(words));
    const uint32_t tid1 = host.GuestAlloc(4);
    const uint32_t tid2 = host.GuestAlloc(4);
    Expect("first pthread_create", Call(host, "pthread_create", {tid1, 0, entry, 1}), 0);
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(5), [&] { return entered >= 1; }))
            Fail("first guest worker entry", 0, 1);
    }
    Expect("second pthread_create", Call(host, "pthread_create", {tid2, 0, entry, 2}), 0);
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(8), [&] { return completed == 2; }))
            Fail("both guest workers completed", completed, 2);
    }
    Expect("workers overlap inside separate JIT instances", first_timed_out ? 1 : 0, 0);
    std::puts("PASS two guest pthreads execute concurrently through active ARM32 SVC thunks");
}

void ConditionHandoffContract(DynarmicHost& host) {
    const uint32_t mutex = host.GuestAlloc(4);
    const uint32_t cond = host.GuestAlloc(4);
    const uint32_t produced = host.GuestAlloc(4);
    if (!mutex || !cond || !produced) Fail("handoff guest allocation", 0, 1);
    Expect("pthread_mutex_init", Call(host, "pthread_mutex_init", {mutex, 0}), 0);
    Expect("pthread_cond_init", Call(host, "pthread_cond_init", {cond, 0}), 0);
    const uint32_t worker_lock = WorkerWrapper(host, "pthread_mutex_lock");
    const uint32_t worker_wait = WorkerWrapper(host, "pthread_cond_wait");
    const uint32_t worker_trylock = WorkerWrapper(host, "pthread_mutex_trylock");
    const uint32_t worker_unlock = WorkerWrapper(host, "pthread_mutex_unlock");

    std::mutex stage_mutex;
    std::condition_variable stage_cv;
    bool locked = false;
    bool proceed = false;
    std::thread consumer([&] {
        Expect("consumer guest lock", host.RunWorkerFunction(worker_lock, {mutex}), 0);
        {
            std::unique_lock lock(stage_mutex);
            locked = true;
            stage_cv.notify_all();
            if (!stage_cv.wait_for(lock, std::chrono::seconds(8), [&] { return proceed; }))
                Fail("producer permits consumer wait", 0, 1);
        }
        // A legal spurious wake simply retries the guest predicate under M.
        while (host.MemoryRead32(produced) == 0)
            Expect("consumer guest cond_wait",
                   host.RunWorkerFunction(worker_wait, {cond, mutex}), 0);
        Expect("consumer owns mutex after wake",
               host.RunWorkerFunction(worker_trylock, {mutex}), EBUSY);
        Expect("consumer guest unlock", host.RunWorkerFunction(worker_unlock, {mutex}), 0);
    });
    {
        std::unique_lock lock(stage_mutex);
        if (!stage_cv.wait_for(lock, std::chrono::seconds(5), [&] { return locked; }))
            Fail("consumer acquired guest mutex", 0, 1);
    }
    Expect("producer trylock while consumer owns M",
           Call(host, "pthread_mutex_trylock", {mutex}), EBUSY);
    {
        std::lock_guard lock(stage_mutex);
        proceed = true;
    }
    stage_cv.notify_all();
    // This cannot complete until cond_wait has atomically released M.
    Expect("producer guest lock during consumer wait",
           Call(host, "pthread_mutex_lock", {mutex}), 0);
    host.MemoryWrite32(produced, 1);
    Expect("producer guest signal", Call(host, "pthread_cond_signal", {cond}), 0);
    Expect("producer guest unlock", Call(host, "pthread_mutex_unlock", {mutex}), 0);
    consumer.join();
    Expect("pthread_cond_destroy", Call(host, "pthread_cond_destroy", {cond}), 0);
    Expect("pthread_mutex_destroy", Call(host, "pthread_mutex_destroy", {mutex}), 0);
    std::puts("PASS guest producer/consumer cond unlock-wait-relock handoff");
}

void TwoWaiterConditionContract(DynarmicHost& host) {
    const uint32_t mutex = host.GuestAlloc(4);
    const uint32_t cond = host.GuestAlloc(4);
    const uint32_t tickets = host.GuestAlloc(4);
    if (!mutex || !cond || !tickets) Fail("two-waiter guest allocation", 0, 1);
    Expect("two-waiter mutex init", Call(host, "pthread_mutex_init", {mutex, 0}), 0);
    Expect("two-waiter cond init", Call(host, "pthread_cond_init", {cond, 0}), 0);
    const uint32_t worker_lock = WorkerWrapper(host, "pthread_mutex_lock");
    const uint32_t worker_wait = WorkerWrapper(host, "pthread_cond_wait");
    const uint32_t worker_unlock = WorkerWrapper(host, "pthread_mutex_unlock");

    std::mutex stage_mutex;
    std::condition_variable stage_cv;
    unsigned ready = 0;
    unsigned wait_returns = 0;
    unsigned completed = 0;
    auto consumer = [&] {
        Expect("two-waiter guest lock", host.RunWorkerFunction(worker_lock, {mutex}), 0);
        {
            std::lock_guard lock(stage_mutex);
            ++ready;
        }
        stage_cv.notify_all();
        // The guest mutex stays owned until cond_wait atomically releases it.
        // Acquiring it after ready==2 therefore proves both callers have
        // entered their guest wait path, without sleeping to order them.
        while (host.MemoryRead32(tickets) == 0) {
            Expect("two-waiter guest cond_wait",
                   host.RunWorkerFunction(worker_wait, {cond, mutex}), 0);
            {
                std::lock_guard lock(stage_mutex);
                ++wait_returns;
            }
            stage_cv.notify_all();
        }
        host.MemoryWrite32(tickets, host.MemoryRead32(tickets) - 1);
        Expect("two-waiter guest unlock", host.RunWorkerFunction(worker_unlock, {mutex}), 0);
        {
            std::lock_guard lock(stage_mutex);
            ++completed;
        }
        stage_cv.notify_all();
    };

    std::thread first(consumer);
    std::thread second(consumer);
    {
        std::unique_lock lock(stage_mutex);
        if (!stage_cv.wait_for(lock, std::chrono::seconds(8), [&] { return ready == 2; }))
            Fail("both guest waiters ready", ready, 2);
    }
    Expect("producer locks after both guest waits",
           Call(host, "pthread_mutex_lock", {mutex}), 0);
    host.MemoryWrite32(tickets, 1);
    Expect("single guest signal", Call(host, "pthread_cond_signal", {cond}), 0);
    Expect("producer unlock after signal", Call(host, "pthread_mutex_unlock", {mutex}), 0);
    {
        std::unique_lock lock(stage_mutex);
        if (!stage_cv.wait_for(lock, std::chrono::seconds(8), [&] { return completed >= 1; }))
            Fail("one waiter consumes signal ticket", completed, 1);
        // A second cond_wait return means signal behaved as broadcast. This
        // bounded negative check cannot rule out an indefinitely delayed
        // wake; the guest predicate still makes spurious wakeups safe.
        if (stage_cv.wait_for(lock, std::chrono::seconds(1),
                              [&] { return wait_returns > 1 || completed > 1; }))
            Fail("signal wakes only one waiter", wait_returns, 1);
    }
    Expect("producer relocks for broadcast", Call(host, "pthread_mutex_lock", {mutex}), 0);
    host.MemoryWrite32(tickets, 1);
    Expect("guest broadcast", Call(host, "pthread_cond_broadcast", {cond}), 0);
    Expect("producer unlock after broadcast", Call(host, "pthread_mutex_unlock", {mutex}), 0);
    {
        std::unique_lock lock(stage_mutex);
        if (!stage_cv.wait_for(lock, std::chrono::seconds(8), [&] { return completed == 2; }))
            Fail("broadcast releases remaining waiter", completed, 2);
    }
    first.join();
    second.join();
    Expect("two-waiter cond destroy", Call(host, "pthread_cond_destroy", {cond}), 0);
    Expect("two-waiter mutex destroy", Call(host, "pthread_mutex_destroy", {mutex}), 0);
    std::puts("PASS two guest waiters: signal one, broadcast remaining");
}

void LiveWorkerInvalidationContract(DynarmicHost& host, bool invalidate) {
    const uint32_t target = host.GuestAlloc(8);
    if (!target) Fail("invalidation target allocation", 0, 1);
    // ARM32: mov r0,#1; bx lr. The patched instruction changes only r0.
    host.MemoryWrite32(target, 0xe3a00001u);
    host.MemoryWrite32(target + 4, 0xe12fff1eu);
    host.AddExecutableRange(target, 8);
    Expect("main core caches old target", host.RunFunction(target, {}), 1);
    Expect("worker core caches old target", host.RunWorkerFunction(target, {}), 1);

    std::mutex stage_mutex;
    std::condition_variable stage_cv;
    bool entered = false;
    bool release = false;
    const uint32_t stage_thunk = host.GetThunkManager().RegisterThunk(
        "contract_invalidation_stage", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            std::unique_lock lock(stage_mutex);
            entered = true;
            stage_cv.notify_all();
            if (!stage_cv.wait_for(lock, std::chrono::seconds(8), [&] { return release; }))
                Fail("release live worker", 0, 1);
            jit.Regs()[0] = 0;
        });
    const uint32_t entry = host.GuestAlloc(8 * sizeof(uint32_t));
    if (!entry) Fail("invalidation wrapper allocation", 0, 1);
    // ARM32: push {r4,lr}; blx stage thunk; blx patched target; pop {r4,pc}.
    const uint32_t words[] = {0xe92d4010u, 0xe59f400cu, 0xe12fff34u,
                              0xe59f4008u, 0xe12fff34u, 0xe8bd8010u,
                              stage_thunk, target};
    std::memcpy(host.GetGuestMemoryBase() + entry, words, sizeof(words));
    host.AddExecutableRange(entry, sizeof(words));

    uint32_t worker_result = UINT32_MAX;
    std::thread worker([&] { worker_result = host.RunWorkerFunction(entry, {}); });
    {
        std::unique_lock lock(stage_mutex);
        if (!stage_cv.wait_for(lock, std::chrono::seconds(8), [&] { return entered; }))
            Fail("live worker reached guest stage thunk", 0, 1);
    }
    // The worker still owns the cached core while blocked in its SVC callback.
    // The same guest address was compiled on both main and worker cores above.
    host.MemoryWrite32(target, 0xe3a00002u);
    if (invalidate) host.InvalidateGuestCode(target, 4);
    {
        std::lock_guard lock(stage_mutex);
        release = true;
    }
    stage_cv.notify_all();
    worker.join();
    const uint32_t expected = invalidate ? 2 : 1;
    Expect("live worker cache result", worker_result, expected);
    Expect("main core cache result", host.RunFunction(target, {}), expected);
    std::puts(invalidate
                  ? "PASS in-use guest worker and main JIT cache invalidation"
                  : "PASS control: both JIT cores keep stale translation without invalidation");
}

void JoinContract(DynarmicHost& host) {
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool worker_entered = false;
    bool release_worker = false;
    bool join_started = false;
    bool join_completed = false;
    uint32_t join_rc = UINT32_MAX;
    constexpr uint32_t kReturn = 0x12345678u;
    host.GetThunkManager().RegisterThunk(
        "contract_join_worker", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            std::unique_lock lock(gate_mutex);
            worker_entered = true;
            gate_cv.notify_all();
            if (!gate_cv.wait_for(lock, std::chrono::seconds(8),
                                  [&] { return release_worker; }))
                Fail("release join worker", 0, 1);
            jit.Regs()[0] = kReturn;
        });
    const uint32_t entry = WorkerWrapper(host, "contract_join_worker");
    const uint32_t tid_out = host.GuestAlloc(4);
    const uint32_t result_out = host.GuestAlloc(4);
    host.MemoryWrite32(result_out, 0xdeadbeefu);
    Expect("join worker create", Call(host, "pthread_create", {tid_out, 0, entry, 0}), 0);
    const uint32_t tid = host.MemoryRead32(tid_out);
    if (!tid) Fail("join worker guest ID", 0, 1);
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(4),
                              [&] { return worker_entered; }))
            Fail("join worker guest entry", 0, 1);
    }
    std::thread joiner([&] {
        {
            std::lock_guard lock(gate_mutex);
            join_started = true;
        }
        gate_cv.notify_all();
        join_rc = Call(host, "pthread_join", {tid, result_out});
        {
            std::lock_guard lock(gate_mutex);
            join_completed = true;
        }
        gate_cv.notify_all();
    });
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(4),
                              [&] { return join_started; }))
            Fail("joiner start", 0, 1);
        if (gate_cv.wait_for(lock, std::chrono::milliseconds(300),
                             [&] { return join_completed; }))
            Fail("join returned while guest worker was blocked", 1, 0);
        release_worker = true;
    }
    gate_cv.notify_all();
    joiner.join();
    Expect("pthread_join result", join_rc, 0);
    Expect("pthread_join guest return value", host.MemoryRead32(result_out), kReturn);
    Expect("second pthread_join", Call(host, "pthread_join", {tid, result_out}), ESRCH);
    Expect("detach already joined", Call(host, "pthread_detach", {tid}), ESRCH);
    const uint32_t self = Call(host, "pthread_self", {});
    Expect("self pthread_join", Call(host, "pthread_join", {self, 0}), EDEADLK);
    const uint32_t attr = host.GuestAlloc(4);
    const uint32_t detached_tid_out = host.GuestAlloc(4);
    Expect("pthread_attr_init", Call(host, "pthread_attr_init", {attr}), 0);
    Expect("invalid detach state", Call(host, "pthread_attr_setdetachstate", {attr, 2}), EINVAL);
    Expect("set detached state", Call(host, "pthread_attr_setdetachstate", {attr, 1}), 0);
    Expect("detached worker create",
           Call(host, "pthread_create", {detached_tid_out, attr, entry, 0}), 0);
    const uint32_t detached_tid = host.MemoryRead32(detached_tid_out);
    const uint32_t detached_join = Call(host, "pthread_join", {detached_tid, 0});
    if (detached_join != EINVAL && detached_join != ESRCH)
        Fail("detached thread cannot be joined", detached_join, EINVAL);
    Expect("pthread_attr_destroy", Call(host, "pthread_attr_destroy", {attr}), 0);
    std::puts("PASS guest pthread join waits for completion and returns r0");
}

void SemaphoreContract(DynarmicHost& host) {
    const uint32_t sem = host.GuestAlloc(4);
    const uint32_t errno_cell = Call(host, "__errno", {});
    if (!sem) Fail("guest semaphore allocation", 0, 1);
    if (!errno_cell) Fail("guest errno pointer", 0, 1);
    Expect("sem_init zero", Call(host, "sem_init", {sem, 0, 0}), 0);
    Expect("sem_trywait empty", Call(host, "sem_trywait", {sem}), UINT32_MAX);
    Expect("sem_trywait EAGAIN", host.MemoryRead32(errno_cell), EAGAIN);
    Expect("sem_post", Call(host, "sem_post", {sem}), 0);
    Expect("sem_trywait after post", Call(host, "sem_trywait", {sem}), 0);
    Expect("sem_trywait depleted", Call(host, "sem_trywait", {sem}), UINT32_MAX);
    Expect("sem_destroy zero", Call(host, "sem_destroy", {sem}), 0);
    Expect("sem_init two", Call(host, "sem_init", {sem, 0, 2}), 0);
    Expect("ARM32 bionic sem_t count encoding", host.MemoryRead32(sem), 4);
    const uint32_t value_out = host.GuestAlloc(4);
    Expect("sem_getvalue two", Call(host, "sem_getvalue", {sem, value_out}), 0);
    Expect("sem_getvalue payload", host.MemoryRead32(value_out), 2);
    Expect("sem_trywait token one", Call(host, "sem_trywait", {sem}), 0);
    Expect("sem_trywait token two", Call(host, "sem_trywait", {sem}), 0);
    Expect("sem_destroy two", Call(host, "sem_destroy", {sem}), 0);
    Expect("sem_init max", Call(host, "sem_init", {sem, 0, 0x3fffffffu}), 0);
    Expect("sem_post overflow", Call(host, "sem_post", {sem}), UINT32_MAX);
    Expect("sem_post EOVERFLOW", host.MemoryRead32(errno_cell), EOVERFLOW);
    Expect("sem_destroy max", Call(host, "sem_destroy", {sem}), 0);
    Expect("sem_init blocking zero", Call(host, "sem_init", {sem, 0, 0}), 0);

    const uint32_t worker_wait = WorkerWrapper(host, "sem_wait");
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool started = false;
    bool completed = false;
    uint32_t wait_result = UINT32_MAX;
    std::thread waiter([&] {
        {
            std::lock_guard lock(gate_mutex);
            started = true;
        }
        gate_cv.notify_all();
        wait_result = host.RunWorkerFunction(worker_wait, {sem});
        {
            std::lock_guard lock(gate_mutex);
            completed = true;
        }
        gate_cv.notify_all();
    });
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(4), [&] { return started; }))
            Fail("semaphore waiter start", 0, 1);
        if (gate_cv.wait_for(lock, std::chrono::milliseconds(300),
                             [&] { return completed; }))
            Fail("empty sem_wait returned before post", 1, 0);
    }
    Expect("sem_post wakes", Call(host, "sem_post", {sem}), 0);
    waiter.join();
    Expect("sem_wait completion", wait_result, 0);
    Expect("sem_destroy", Call(host, "sem_destroy", {sem}), 0);
    std::puts("PASS guest semaphore depletion, EAGAIN and cross-thread wake");
}

void OnceContract(DynarmicHost& host) {
    const uint32_t control = host.GuestAlloc(4);
    const uint32_t initialized = host.GuestAlloc(4);
    if (!control || !initialized) Fail("pthread_once guest allocation", 0, 1);
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool init_entered = false;
    bool release_init = false;
    bool second_started = false;
    bool second_completed = false;
    unsigned init_count = 0;
    uint32_t first_rc = UINT32_MAX;
    uint32_t second_rc = UINT32_MAX;
    const uint32_t init_entry = host.GetThunkManager().RegisterThunk(
        "contract_once_initializer", [&](Dynarmic::A32::Jit& jit, DynarmicHost& inner) {
            std::unique_lock lock(gate_mutex);
            ++init_count;
            init_entered = true;
            gate_cv.notify_all();
            if (!gate_cv.wait_for(lock, std::chrono::seconds(8),
                                  [&] { return release_init; }))
                Fail("pthread_once initializer release", 0, 1);
            inner.MemoryWrite32(initialized, 1);
            jit.Regs()[0] = 0;
        });
    const uint32_t once_entry = WorkerWrapper(host, "pthread_once");
    std::thread first([&] {
        first_rc = host.RunWorkerFunction(once_entry, {control, init_entry});
    });
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(4),
                              [&] { return init_entered; }))
            Fail("first guest once initializer entered", 0, 1);
    }
    std::thread second([&] {
        {
            std::lock_guard lock(gate_mutex);
            second_started = true;
        }
        gate_cv.notify_all();
        second_rc = host.RunWorkerFunction(once_entry, {control, init_entry});
        {
            std::lock_guard lock(gate_mutex);
            second_completed = true;
        }
        gate_cv.notify_all();
    });
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(4),
                              [&] { return second_started; }))
            Fail("second guest once call started", 0, 1);
        if (gate_cv.wait_for(lock, std::chrono::milliseconds(300),
                             [&] { return second_completed; }))
            Fail("second pthread_once returned before initializer", 1, 0);
        release_init = true;
    }
    gate_cv.notify_all();
    first.join();
    second.join();
    Expect("first pthread_once", first_rc, 0);
    Expect("second pthread_once", second_rc, 0);
    Expect("initializer runs exactly once", init_count, 1);
    Expect("initialized value visible", host.MemoryRead32(initialized), 1);
    Expect("completed bionic once state", host.MemoryRead32(control), 2);
    Expect("pthread_once after completion", Call(host, "pthread_once", {control, init_entry}), 0);
    Expect("initializer still once", init_count, 1);
    // The game's guest code may supply a Thumb initializer even though the
    // public SVC trampoline is ARM. Verify both return-state transitions.
    const uint32_t thumb_control = host.GuestAlloc(4);
    const uint32_t thumb_value = host.GuestAlloc(4);
    const uint32_t thumb_entry = host.GuestAlloc(12);
    if (!thumb_control || !thumb_value || !thumb_entry)
        Fail("Thumb once guest allocation", 0, 1);
    const uint16_t thumb_code[] = {0x4801u, 0x2101u, 0x6001u, 0x4770u};
    std::memcpy(host.GetGuestMemoryBase() + thumb_entry, thumb_code, sizeof(thumb_code));
    host.MemoryWrite32(thumb_entry + 8, thumb_value);
    host.AddExecutableRange(thumb_entry, 12);
    Expect("Thumb initializer pthread_once",
           Call(host, "pthread_once", {thumb_control, thumb_entry | 1u}), 0);
    Expect("Thumb initialized value", host.MemoryRead32(thumb_value), 1);
    Expect("Thumb completed once state", host.MemoryRead32(thumb_control), 2);
    std::puts("PASS guest pthread_once waits until initializer return");
}

void ErrnoContract(DynarmicHost& host) {
    const uint32_t entry = WorkerWrapper(host, "__errno");
    const uint32_t main_cell = Call(host, "__errno", {});
    if (!main_cell) Fail("main guest errno pointer", 0, 1);
    Expect("Bionic TLS slot two", main_cell, host.GuestThreadTls() + 8u);
    host.MemoryWrite32(main_cell, 111);
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool first_ready = false;
    bool second_ready = false;
    uint32_t first_cell = 0;
    uint32_t first_repeat = 0;
    uint32_t first_value = 0;
    uint32_t second_cell = 0;
    std::thread first([&] {
        first_cell = host.RunWorkerFunction(entry, {});
        if (!first_cell) Fail("first guest errno pointer", 0, 1);
        host.MemoryWrite32(first_cell, 222);
        {
            std::lock_guard lock(gate_mutex);
            first_ready = true;
        }
        gate_cv.notify_all();
        {
            std::unique_lock lock(gate_mutex);
            if (!gate_cv.wait_for(lock, std::chrono::seconds(4),
                                  [&] { return second_ready; }))
                Fail("second errno worker reached barrier", 0, 1);
        }
        first_repeat = host.RunWorkerFunction(entry, {});
        first_value = host.MemoryRead32(first_cell);
    });
    std::thread second([&] {
        {
            std::unique_lock lock(gate_mutex);
            if (!gate_cv.wait_for(lock, std::chrono::seconds(4),
                                  [&] { return first_ready; }))
                Fail("first errno worker reached barrier", 0, 1);
        }
        second_cell = host.RunWorkerFunction(entry, {});
        if (!second_cell) Fail("second guest errno pointer", 0, 1);
        host.MemoryWrite32(second_cell, 333);
        {
            std::lock_guard lock(gate_mutex);
            second_ready = true;
        }
        gate_cv.notify_all();
    });
    first.join();
    second.join();
    if (main_cell == first_cell || main_cell == second_cell ||
        first_cell == second_cell)
        Fail("guest errno cells are thread-local", 0, 1);
    Expect("main guest errno unchanged", host.MemoryRead32(main_cell), 111);
    Expect("first guest errno unchanged", first_value, 222);
    Expect("second guest errno unchanged", host.MemoryRead32(second_cell), 333);
    Expect("guest errno pointer stable within thread", first_repeat, first_cell);
    std::puts("PASS guest errno pointer and value are thread-local");
}

void KeyLifecycleContract(DynarmicHost& host) {
    const uint32_t key_out = host.GuestAlloc(4);
    if (!key_out) Fail("guest key output allocation", 0, 1);
    Expect("pthread_key_create", Call(host, "pthread_key_create", {key_out, 0}), 0);
    const uint32_t key = host.MemoryRead32(key_out);
    Expect("first Bionic user TLS slot", key, 7);
    Expect("pthread_setspecific", Call(host, "pthread_setspecific", {key, 0x12345678u}), 0);
    Expect("pthread_getspecific", Call(host, "pthread_getspecific", {key}), 0x12345678u);
    const uint32_t main_tls = host.GuestThreadTls();
    Expect("TLS_SLOT_SELF", host.MemoryRead32(main_tls), main_tls);
    Expect("main key value uses Bionic guest TLS array",
           host.MemoryRead32(main_tls + key * 4u), 0x12345678u);

    const uint32_t worker_set = WorkerWrapper(host, "pthread_setspecific");
    const uint32_t worker_get = WorkerWrapper(host, "pthread_getspecific");
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool peer_ready = false;
    bool peer_release = false;
    uint32_t peer_tls = 0;
    uint32_t peer_value_after_delete = UINT32_MAX;
    uint32_t peer_get_after_delete = UINT32_MAX;
    std::thread peer([&] {
        Expect("peer pthread_setspecific",
               host.RunWorkerFunction(worker_set, {key, 0x87654321u}), 0);
        peer_tls = host.GuestThreadTls();
        {
            std::unique_lock lock(gate_mutex);
            peer_ready = true;
            gate_cv.notify_all();
            if (!gate_cv.wait_for(lock, std::chrono::seconds(5),
                                  [&] { return peer_release; }))
                Fail("peer key delete release", 0, 1);
        }
        peer_value_after_delete = host.MemoryRead32(peer_tls + key * 4u);
        peer_get_after_delete = host.RunWorkerFunction(worker_get, {key});
        host.ReleaseGuestThreadTls();
    });
    {
        std::unique_lock lock(gate_mutex);
        if (!gate_cv.wait_for(lock, std::chrono::seconds(5),
                              [&] { return peer_ready; }))
            Fail("peer key value ready", 0, 1);
    }
    if (peer_tls == main_tls) Fail("independent guest TLS pages", 0, 1);
    Expect("peer value in guest TLS array",
           host.MemoryRead32(peer_tls + key * 4u), 0x87654321u);
    Expect("pthread_key_delete", Call(host, "pthread_key_delete", {key}), 0);
    {
        std::lock_guard lock(gate_mutex);
        peer_release = true;
    }
    gate_cv.notify_all();
    peer.join();
    Expect("deleted key clears peer TLS", peer_value_after_delete, 0);
    Expect("deleted key clears peer getspecific", peer_get_after_delete, 0);
    Expect("peer TLS page freed at exit", host.GuestAllocSize(peer_tls), 0);
    Expect("deleted key clears main TLS", host.MemoryRead32(main_tls + key * 4u), 0);
    Expect("deleted key no longer exposes stale data",
           Call(host, "pthread_getspecific", {key}), 0);
    Expect("pthread_setspecific rejects deleted key",
           Call(host, "pthread_setspecific", {key, 42}), EINVAL);
    Expect("pthread_key_delete rejects deleted key",
           Call(host, "pthread_key_delete", {key}), EINVAL);
    Expect("key slot recycled", Call(host, "pthread_key_create", {key_out, 0}), 0);
    Expect("first free slot reused", host.MemoryRead32(key_out), key);
    Expect("recycled key begins null", Call(host, "pthread_getspecific", {key}), 0);
    Expect("delete recycled key", Call(host, "pthread_key_delete", {key}), 0);

    uint32_t destructor_key = 0;
    std::atomic<uint32_t> destructor_calls{0};
    std::atomic<uint32_t> first_data{0};
    std::atomic<uint32_t> second_data{0};
    uint32_t worker_tls = 0;
    host.GetThunkManager().RegisterThunk(
        "contract_key_destructor", [&](Dynarmic::A32::Jit& jit, DynarmicHost& guest) {
            const uint32_t tls = guest.GuestThreadTls();
            Expect("TLS value cleared before guest destructor",
                   guest.MemoryRead32(tls + destructor_key * 4u), 0);
            const uint32_t count = destructor_calls.fetch_add(1) + 1;
            if (count == 1) {
                first_data.store(jit.Regs()[0]);
                guest.MemoryWrite32(tls + destructor_key * 4u, jit.Regs()[0] + 1u);
            } else if (count == 2) {
                second_data.store(jit.Regs()[0]);
            }
        });
    const uint32_t destructor_entry = WorkerWrapper(host, "contract_key_destructor");
    Expect("create destructor key",
           Call(host, "pthread_key_create", {key_out, destructor_entry}), 0);
    destructor_key = host.MemoryRead32(key_out);
    host.GetThunkManager().RegisterThunk(
        "contract_key_worker_entry", [&](Dynarmic::A32::Jit& jit, DynarmicHost& guest) {
            worker_tls = guest.GuestThreadTls();
            guest.MemoryWrite32(worker_tls + destructor_key * 4u, jit.Regs()[0]);
            jit.Regs()[0] = 0xCAFEBABEu;
        });
    const uint32_t worker_entry = WorkerWrapper(host, "contract_key_worker_entry");
    const uint32_t tid_out = host.GuestAlloc(4);
    const uint32_t result_out = host.GuestAlloc(4);
    Expect("create guest destructor worker",
           Call(host, "pthread_create", {tid_out, 0, worker_entry, 0x11110000u}), 0);
    Expect("join guest destructor worker",
           Call(host, "pthread_join", {host.MemoryRead32(tid_out), result_out}), 0);
    Expect("worker result survives destructor", host.MemoryRead32(result_out), 0xCAFEBABEu);
    Expect("guest destructor repeated once", destructor_calls.load(), 2);
    Expect("guest destructor first value", first_data.load(), 0x11110000u);
    Expect("guest destructor second value", second_data.load(), 0x11110001u);
    Expect("guest worker TLS released after destructors", host.GuestAllocSize(worker_tls), 0);
    Expect("delete destructor key", Call(host, "pthread_key_delete", {destructor_key}), 0);

    for (uint32_t expected_key = 7; expected_key < 64; ++expected_key) {
        Expect("allocate Bionic key up to limit",
               Call(host, "pthread_key_create", {key_out, 0}), 0);
        Expect("bounded Bionic key number", host.MemoryRead32(key_out), expected_key);
    }
    Expect("Bionic key table exhaustion",
           Call(host, "pthread_key_create", {key_out, 0}), ENOMEM);
    for (uint32_t allocated_key = 7; allocated_key < 64; ++allocated_key)
        Expect("delete bounded Bionic key", Call(host, "pthread_key_delete", {allocated_key}), 0);
    std::puts("PASS Bionic guest pthread key TLS, delete, reuse, destructor and bound");
}
}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc != 2 || (std::strcmp(argv[1], "mutex") &&
                      std::strcmp(argv[1], "timedwait") &&
                      std::strcmp(argv[1], "workers") &&
                      std::strcmp(argv[1], "handoff") &&
                      std::strcmp(argv[1], "two-waiters") &&
                      std::strcmp(argv[1], "live-invalidate") &&
                      std::strcmp(argv[1], "live-cache-control") &&
                      std::strcmp(argv[1], "join") &&
                      std::strcmp(argv[1], "semaphore") &&
                      std::strcmp(argv[1], "once") &&
                      std::strcmp(argv[1], "errno") &&
                      std::strcmp(argv[1], "keys"))) {
        std::fprintf(stderr, "usage: %s {mutex|timedwait|workers|handoff|two-waiters|live-invalidate|live-cache-control|join|semaphore|once|errno|keys}\n", argv[0]);
        return 2;
    }
    // The bridge owns process-lifetime diagnostics, so keep it alive until exit.
    auto* host = new DynarmicHost;
    if (!host->Initialize()) Fail("DynarmicHost initialization", 0, 1);
    if (!std::strcmp(argv[1], "mutex")) MutexContract(*host);
    else if (!std::strcmp(argv[1], "timedwait")) TimedWaitContract(*host);
    else if (!std::strcmp(argv[1], "workers")) WorkerConcurrencyContract(*host);
    else if (!std::strcmp(argv[1], "handoff")) ConditionHandoffContract(*host);
    else if (!std::strcmp(argv[1], "two-waiters")) TwoWaiterConditionContract(*host);
    else if (!std::strcmp(argv[1], "live-invalidate")) LiveWorkerInvalidationContract(*host, true);
    else if (!std::strcmp(argv[1], "live-cache-control")) LiveWorkerInvalidationContract(*host, false);
    else if (!std::strcmp(argv[1], "join")) JoinContract(*host);
    else if (!std::strcmp(argv[1], "semaphore")) SemaphoreContract(*host);
    else if (!std::strcmp(argv[1], "once")) OnceContract(*host);
    else if (!std::strcmp(argv[1], "errno")) ErrnoContract(*host);
    else KeyLifecycleContract(*host);
    std::_Exit(0);
}
