// Threading backport from the Conduit-derived base POSIX bridge.
// ARM32 synchronization objects stay 4-byte tokens; native Bionic objects
// and pthread_t values never overwrite guest storage. One game host/process.
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <semaphore.h>
#include <cerrno>
#include <climits>
#include <condition_variable>
#include <thread>
#include <stdexcept>
JavaVM* GetHostJavaVM();
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "Arm32Bridge_Threads", __VA_ARGS__)
// Held guest-mutex tracking at file scope: HeldMutexMark/UnwindTo are used
// by DynarmicHost's run functions to release locks that an aborted guest
// call abandoned (bring-up halts), which otherwise freeze every thread.
static thread_local std::vector<pthread_mutex_t*> t_held_guest_mutexes;
static void HeldMutexAcquire(pthread_mutex_t* m){
    t_held_guest_mutexes.push_back(m);
}
static void HeldMutexRelease(pthread_mutex_t* m){
    for(size_t i=0;i<t_held_guest_mutexes.size();++i)
        if(t_held_guest_mutexes[i]==m){t_held_guest_mutexes.erase(t_held_guest_mutexes.begin()+i);return;}
}
static void HeldMutexReleaseAll(){
    for(auto* m:t_held_guest_mutexes){
        int rc=pthread_mutex_unlock(m);
        LOGI("[MTX] thread exit released abandoned guest mutex %p (rc=%d)",(void*)m,rc);
    }
    t_held_guest_mutexes.clear();
}
size_t HeldMutexMark(){ return t_held_guest_mutexes.size(); }
void HeldMutexUnwindTo(size_t mark){
    while(t_held_guest_mutexes.size()>mark){
        auto* m=t_held_guest_mutexes.back();
        int rc=pthread_mutex_unlock(m);
        t_held_guest_mutexes.pop_back();
        LOGI("[MTX] aborted run released abandoned guest mutex %p (rc=%d)",(void*)m,rc);
    }
}

namespace {
using Jit = Dynarmic::A32::Jit;
using Host = DynarmicHost;
[[noreturn]] void Invalid(const char* message) { throw std::runtime_error(message); }
void* Span(Host& h, uint32_t p, size_t n) {
    auto* ptr = GuestSpan(h.GetGuestMemoryBase(), h.GetGuestMemorySize(), p, n);
    if (!ptr || (!p && n)) Invalid("Invalid guest threading pointer");
    return ptr;
}
const char* String(Host& h, uint32_t p) { return GuestCString(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),p); }
uint32_t Tls(Host& host);
void Errno(Host& h,int value) { h.MemoryWrite32(Tls(h)+8,value); }
void Result(Jit& j,Host& h,int result) { const int saved=errno;j.Regs()[0]=result;if(result<0)Errno(h,saved); }
void Failure(Jit& j,Host& h,int error) { errno=error;Result(j,h,-1); }
struct Time32 { int32_t sec, nsec; };
static_assert(sizeof(Time32) == 8);
bool ReadTime(Host& host, uint32_t p, timespec& result) {
    auto* t = static_cast<const Time32*>(Span(host, p, sizeof(Time32)));
    if (t->nsec < 0 || t->nsec >= 1000000000) return false;
    result = {t->sec, t->nsec};
    return true;
}
struct Attr32 { uint32_t flags,base,size,guard; int32_t policy,priority; };
// Address-keyed host objects retain their lifetime while waits release the registry lock.

struct Mutex {
    pthread_mutex_t value;
    bool live=false;
    explicit Mutex(int type){
        pthread_mutexattr_t attr;
        int rc=pthread_mutexattr_init(&attr);
        if(rc)Invalid("host mutex attributes");
        rc=pthread_mutexattr_settype(&attr,type);
        if(!rc)rc=pthread_mutex_init(&value,&attr);
        pthread_mutexattr_destroy(&attr);
        if(rc)Invalid("host mutex initialization");
        live=true;
    }
    ~Mutex(){if(live && pthread_mutex_destroy(&value))Invalid("destroying live guest mutex");}
};
struct Condition {
    pthread_cond_t value;
    clockid_t clock;
    bool live=false;
    std::mutex legacy_mutex;
    std::condition_variable legacy_cv;
    size_t legacy_waiters=0;
    size_t legacy_wakeups=0;
    std::atomic<bool> legacy_logged=false;
    explicit Condition(clockid_t c):clock(c){
        pthread_condattr_t attr;
        int rc=pthread_condattr_init(&attr);
        if(rc)Invalid("host condition attributes");
        rc=pthread_condattr_setclock(&attr,c);
        if(!rc)rc=pthread_cond_init(&value,&attr);
        pthread_condattr_destroy(&attr);
        if(rc)Invalid("host condition initialization");
        live=true;
    }
    int WaitWithoutMutex(){
        std::unique_lock lock(legacy_mutex);
        ++legacy_waiters;
        legacy_cv.wait(lock,[&]{return legacy_wakeups!=0;});
        --legacy_wakeups;
        --legacy_waiters;
        return 0;
    }
    int Signal(){
        bool notify=false;
        {
            std::lock_guard lock(legacy_mutex);
            if(legacy_waiters>legacy_wakeups){++legacy_wakeups;notify=true;}
        }
        if(notify){legacy_cv.notify_one();return 0;}
        return pthread_cond_signal(&value);
    }
    int Broadcast(){
        int rc=pthread_cond_broadcast(&value);
        bool notify=false;
        {
            std::lock_guard lock(legacy_mutex);
            if(legacy_waiters){legacy_wakeups=legacy_waiters;notify=true;}
        }
        if(notify)legacy_cv.notify_all();
        return rc;
    }
    size_t LegacyWaiters(){
        std::lock_guard lock(legacy_mutex);
        return legacy_waiters;
    }
    ~Condition(){if(live && pthread_cond_destroy(&value))Invalid("destroying live guest condition");}
};
struct Semaphore {
    sem_t value;
    bool live=false;
    explicit Semaphore(unsigned count){if(sem_init(&value,0,count))Invalid("host semaphore initialization");live=true;}
    ~Semaphore(){if(live && sem_destroy(&value))Invalid("destroying live guest semaphore");}
};
struct Once {
    std::mutex mutex;
    std::condition_variable cv;
    unsigned state=0;
    std::thread::id owner{};
    bool Run(const std::function<bool()>& init){
        std::unique_lock lock(mutex);
        cv.wait(lock,[&]{return state!=1;});
        if(state==2)return true;
        state=1;lock.unlock();
        bool complete=false;
        try { complete=init(); }
        catch (...) { lock.lock();state=0;lock.unlock();cv.notify_all();throw; }
        lock.lock();state=complete?2:0;lock.unlock();cv.notify_all();
        return complete;
    }
};
std::mutex g_sync_mutex;
std::unordered_map<uint32_t,std::shared_ptr<Mutex>> g_mutexes;
std::unordered_map<uint32_t,std::shared_ptr<Condition>> g_conditions;
std::unordered_map<uint32_t,std::shared_ptr<Semaphore>> g_semaphores;
std::unordered_map<uint32_t,std::shared_ptr<Once>> g_once;

std::shared_ptr<Mutex> GetMutex(Host& host,uint32_t p){
    if(!p){errno=EINVAL;return {};}
    Span(host,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto it=g_mutexes.find(p);
    if(it!=g_mutexes.end())return it->second;

    uint32_t word=host.MemoryRead32(p);
    if(word&~0xc000u || (word>>14)>2){errno=EINVAL;return {};}
    auto value=std::make_shared<Mutex>(static_cast<int>(word>>14));
    g_mutexes.emplace(p,value);return value;
}

std::shared_ptr<Condition> GetCondition(Host& host,uint32_t p){
    if(!p){errno=EINVAL;return {};}
    Span(host,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto it=g_conditions.find(p);
    if(it!=g_conditions.end())return it->second;
    uint32_t word=host.MemoryRead32(p);
    if(word&~2u){errno=(word&1)?ENOTSUP:EINVAL;return {};}
    auto value=std::make_shared<Condition>((word&2)?CLOCK_MONOTONIC:CLOCK_REALTIME);
    g_conditions.emplace(p,value);return value;
}
std::shared_ptr<Semaphore> GetSemaphore(uint32_t p){
    std::lock_guard lock(g_sync_mutex);
    auto it=g_semaphores.find(p);
    if(it==g_semaphores.end()){errno=EINVAL;return {};}
    return it->second;
}
int WaitCondition(Host& host,uint32_t cond,uint32_t mutex,uint32_t deadline,bool relative){
    auto c=GetCondition(host,cond);if(!c)return errno;
    // Immersion's legacy Android library deliberately passes a null mutex and
    // treats pthread_cond_wait as an event wait. Bionic tolerated this pattern;
    // returning EINVAL makes its haptic worker spin at 100% instead of sleeping.
    if(!mutex){
        if(relative || deadline)return EINVAL;
        if(!c->legacy_logged.exchange(true,std::memory_order_relaxed))
            LOGI("legacy pthread_cond_wait(cond=0x%08x, mutex=null): event wait enabled",cond);
        return c->WaitWithoutMutex();
    }
    auto m=GetMutex(host,mutex);if(!m)return errno;
    if(!relative && !deadline)return pthread_cond_wait(&c->value,&m->value);
    timespec time{};
    if(relative){
        if(clock_gettime(c->clock,&time))return errno;
        time.tv_sec+=deadline/1000;time.tv_nsec+=(deadline%1000)*1000000LL;
        time.tv_sec+=time.tv_nsec/1000000000;time.tv_nsec%=1000000000;
    }else if(!ReadTime(host,deadline,time))return EINVAL;
    return pthread_cond_timedwait(&c->value,&m->value,&time);
}

struct Thread {
    std::mutex mutex;
    pthread_t native{};
    bool detached=false,finished=false,joining=false,external=false;
    uint32_t retval=0,id=0,tls=0;
};
std::mutex g_threads_mutex;
std::unordered_map<uint32_t,std::shared_ptr<Thread>> g_threads;
uint32_t g_next_thread=1;
thread_local std::shared_ptr<Thread> t_thread;
struct Key {uint32_t destructor;};
std::mutex g_keys_mutex;
std::unordered_map<uint32_t,Key> g_keys;
// ponytail: opaque monotonic keys avoid stale deleted-key values; 2^32 creations per process.
uint32_t g_next_key=1;
thread_local std::unordered_map<uint32_t,uint32_t> t_keys;

std::shared_ptr<Thread> GetThread(uint32_t id){
    std::lock_guard lock(g_threads_mutex);
    auto it=g_threads.find(id);return it==g_threads.end()?nullptr:it->second;
}
void ForgetThread(const std::shared_ptr<Thread>& thread){
    std::lock_guard lock(g_threads_mutex);
    auto it=g_threads.find(thread->id);
    if(it!=g_threads.end() && it->second==thread)g_threads.erase(it);
}
std::shared_ptr<Thread> NewThread(){
    std::lock_guard lock(g_threads_mutex);
    if(!g_next_thread)return {};
    auto thread=std::make_shared<Thread>();thread->id=g_next_thread++;
    g_threads.emplace(thread->id,thread);return thread;
}
uint32_t Self(){
    auto& current=t_thread; // Initialize before the cleanup destructor is registered.
    struct Cleanup {~Cleanup(){if(t_thread&&t_thread->external)ForgetThread(t_thread);}};
    static thread_local Cleanup cleanup;
    (void)current;(void)cleanup;
    if(!t_thread){
        t_thread=NewThread();if(!t_thread)Invalid("guest thread identifiers exhausted");
        t_thread->native=pthread_self();t_thread->external=true;t_thread->detached=true;
    }
    return t_thread->id;
}
void RunTlsDestructors(Host& host){
    for(unsigned pass=0;pass<4;++pass){
        std::vector<std::pair<uint32_t,uint32_t>> pending;
        {
            std::lock_guard lock(g_keys_mutex);
            for(auto& [key,value]:t_keys){
                auto it=g_keys.find(key);
                if(value && it!=g_keys.end() && it->second.destructor){
                    pending.emplace_back(it->second.destructor,value);value=0;
                }
            }
        }
        if(pending.empty())break;
        for(auto [fn,value]:pending)host.RunWorkerFunction(fn,{value});
    }
    t_keys.clear();
}

struct ThreadStart {Host* host;uint32_t function,arg;std::shared_ptr<Thread> thread;};
uint32_t Tls(Host& host) {
    Self();
    if (!t_thread->tls) {
        t_thread->tls=host.GuestAlloc(256,16);
        if (!t_thread->tls) throw std::bad_alloc();
        host.MemoryWrite32(t_thread->tls,t_thread->tls);
        host.MemoryWrite32(t_thread->tls+4,t_thread->id);
    }
    return t_thread->tls;
}
void* ThreadEntry(void* opaque){
    std::unique_ptr<ThreadStart> start(static_cast<ThreadStart*>(opaque));
    auto thread=start->thread;t_thread=thread;
    {std::lock_guard lock(thread->mutex);thread->native=pthread_self();}
    BridgeAttachCurrentThread();
    uint32_t result=0xFFFFFFFFu;
    try {
        result=start->host->RunWorkerFunction(start->function,{start->arg});
        RunTlsDestructors(*start->host);
    } catch (const std::exception& error) { LOGI("Guest thread failed: %s",error.what()); }
    catch (...) { LOGI("Guest thread failed with unknown exception"); }
    HeldMutexReleaseAll();
    if (auto* vm=GetHostJavaVM()) vm->DetachCurrentThread();
    if (thread->tls) { start->host->GuestFree(thread->tls);thread->tls=0; }
    bool detached;
    {std::lock_guard lock(thread->mutex);thread->retval=result;thread->finished=true;detached=thread->detached;}
    if(detached)ForgetThread(thread);
    t_thread.reset();
    return reinterpret_cast<void*>(static_cast<uintptr_t>(result));
}
int CreateThread(Host& host,uint32_t output,uint32_t attr_ptr,uint32_t function,uint32_t arg){
    if(!output || !function)return EINVAL;
    Span(host,output,4);
    Attr32 guest{0,0,1024*1024,4096,SCHED_OTHER,0};
    if(attr_ptr)memcpy(&guest,Span(host,attr_ptr,sizeof(guest)),sizeof(guest));
    // host stacks reserve 1 MiB per guest thread; support sized arenas before accepting another size.
    if(guest.base || (guest.size<16384 || guest.size>4*1024*1024-65536) || (guest.flags&~1u))return ENOTSUP;
    auto thread=NewThread();if(!thread)return EAGAIN;
    thread->detached=(guest.flags&1)!=0;
    auto start=std::make_unique<ThreadStart>(ThreadStart{&host,function,arg,thread});
    pthread_attr_t attr;
    int rc=pthread_attr_init(&attr);
    if(rc){ForgetThread(thread);return rc;}
    rc=pthread_attr_setstacksize(&attr,8*1024*1024);
    if(!rc)rc=pthread_attr_setdetachstate(&attr,thread->detached?PTHREAD_CREATE_DETACHED:PTHREAD_CREATE_JOINABLE);
    if(!rc)rc=pthread_attr_setschedpolicy(&attr,guest.policy);
    sched_param schedule{};schedule.sched_priority=guest.priority;
    if(!rc)rc=pthread_attr_setschedparam(&attr,&schedule);
    pthread_t native{};
    if(!rc)rc=pthread_create(&native,&attr,ThreadEntry,start.get());
    pthread_attr_destroy(&attr);
    if(rc){ForgetThread(thread);return rc;}
    start.release();
    {std::lock_guard lock(thread->mutex);thread->native=native;}
    host.MemoryWrite32(output,thread->id);
    return 0;
}
int JoinThread(Host& host,uint32_t id,uint32_t output){
    auto thread=GetThread(id);if(!thread)return ESRCH;
    if(id==Self())return EDEADLK;
    if(output)Span(host,output,4);
    pthread_t native;
    {std::lock_guard lock(thread->mutex);
        if(thread->detached || thread->external || thread->joining)return EINVAL;
        thread->joining=true;native=thread->native;
    }
    void* result=nullptr;int rc=pthread_join(native,&result);
    if(rc){std::lock_guard lock(thread->mutex);thread->joining=false;return rc;}
    if(output)host.MemoryWrite32(output,static_cast<uint32_t>(reinterpret_cast<uintptr_t>(result)));
    ForgetThread(thread);return 0;
}
int DetachThread(uint32_t id){
    auto thread=GetThread(id);if(!thread)return ESRCH;
    bool finished;
    {std::lock_guard lock(thread->mutex);
        if(thread->detached || thread->external || thread->joining)return EINVAL;
        int rc=pthread_detach(thread->native);if(rc)return rc;
        thread->detached=true;finished=thread->finished;
    }
    if(finished)ForgetThread(thread);return 0;
}

} // namespace

uint32_t Mc4GuestTlsAddress(DynarmicHost& host) { return Tls(host); }
void RegisterThreadingThunks(ThunkManager& manager) {
    auto RegisterThunk = [&](const char* name, ThunkHandler handler) { return manager.RegisterThunk(name,std::move(handler)); };
    RegisterThunk("__errno",[](Jit& j,Host& h){j.Regs()[0]=Tls(h)+8;});

    RegisterThunk("pthread_create",[](Jit& j,Host& h){j.Regs()[0]=CreateThread(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],j.Regs()[3]);});
    RegisterThunk("pthread_self",[](Jit& j,Host&){j.Regs()[0]=Self();});
    RegisterThunk("pthread_join",[](Jit& j,Host& h){j.Regs()[0]=JoinThread(h,j.Regs()[0],j.Regs()[1]);});
    RegisterThunk("pthread_detach",[](Jit& j,Host&){j.Regs()[0]=DetachThread(j.Regs()[0]);});
    RegisterThunk("pthread_attr_init",[](Jit& j,Host& h){
        Attr32 a{0,0,1024*1024,4096,SCHED_OTHER,0};memcpy(Span(h,j.Regs()[0],sizeof(a)),&a,sizeof(a));j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],sizeof(Attr32));j.Regs()[0]=0;});
    RegisterThunk("pthread_attr_getstacksize",[](Jit& j,Host& h){
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->size);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_getschedparam",[](Jit& j,Host& h){
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->priority);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_setschedparam",[](Jit& j,Host& h){
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);int priority=static_cast<int32_t>(h.MemoryRead32(j.Regs()[1]));
        if(priority<sched_get_priority_min(a->policy)||priority>sched_get_priority_max(a->policy)){j.Regs()[0]=EINVAL;return;}
        a->priority=priority;j.Regs()[0]=0;
    });
    RegisterThunk("pthread_setschedparam",[](Jit& j,Host& h){
        auto t=GetThread(j.Regs()[0]);if(!t){j.Regs()[0]=ESRCH;return;}
        Span(h,j.Regs()[2],4);sched_param p{};p.sched_priority=static_cast<int32_t>(h.MemoryRead32(j.Regs()[2]));
        pthread_t native;{std::lock_guard lock(t->mutex);native=t->native;}
        j.Regs()[0]=pthread_setschedparam(native,static_cast<int>(j.Regs()[1]),&p);
    });
    RegisterThunk("pthread_setname_np",[](Jit& j,Host& h){
        auto t=GetThread(j.Regs()[0]);if(!t){j.Regs()[0]=ESRCH;return;}
        const char* name=String(h,j.Regs()[1]);if(!name){j.Regs()[0]=EINVAL;return;}
        pthread_t native;{std::lock_guard lock(t->mutex);native=t->native;}
        j.Regs()[0]=pthread_setname_np(native,name);
    });
    RegisterThunk("pthread_mutexattr_init",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);h.MemoryWrite32(j.Regs()[0],0);j.Regs()[0]=0;});
    RegisterThunk("pthread_mutexattr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);j.Regs()[0]=0;});
    RegisterThunk("pthread_mutexattr_settype",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);if(j.Regs()[1]>2){j.Regs()[0]=EINVAL;return;}
        h.MemoryWrite32(j.Regs()[0],j.Regs()[1]);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_mutex_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];Span(h,p,4);int type=0;
        if(j.Regs()[1]){Span(h,j.Regs()[1],4);type=h.MemoryRead32(j.Regs()[1]);}
        if(type<0||type>2){j.Regs()[0]=ENOTSUP;return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_mutexes.count(p)){j.Regs()[0]=EBUSY;return;}
        g_mutexes.emplace(p,std::make_shared<Mutex>(type));h.MemoryWrite32(p,type<<14);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_mutex_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto value=GetMutex(h,p);if(!value){j.Regs()[0]=errno;return;}
        std::lock_guard lock(g_sync_mutex);
        if(value.use_count()<2){j.Regs()[0]=EBUSY;return;}
        int rc=pthread_mutex_destroy(&value->value);
        if(!rc){value->live=false;g_mutexes.erase(p);h.MemoryWrite32(p,0xdeadc0de);}
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_mutex_lock",[](Jit& j,Host& h){
        auto m=GetMutex(h,j.Regs()[0]);
        if(!m){j.Regs()[0]=errno;return;}
        const bool holds_run_mutex=Host::SyncRunMutexHeld();
        // Uncontended fast path: try-lock first. The run-mutex
        // unlock/relock dance (below) is only needed when the lock would
        // actually block; pthread_mutex_trylock on an uncontended mutex is
        // a single atomic and keeps the hot render/mutex loop cheap.
        int rc=pthread_mutex_trylock(&m->value);
        if(rc==EBUSY){
            if(holds_run_mutex)h.SyncRunMutexUnlock();
            rc=pthread_mutex_lock(&m->value);
            if(holds_run_mutex)h.SyncRunMutexRelock();
        }
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_mutex_trylock",[](Jit& j,Host& h){auto m=GetMutex(h,j.Regs()[0]);j.Regs()[0]=m?pthread_mutex_trylock(&m->value):errno;});
    RegisterThunk("pthread_mutex_unlock",[](Jit& j,Host& h){auto m=GetMutex(h,j.Regs()[0]);j.Regs()[0]=m?pthread_mutex_unlock(&m->value):errno;});
    RegisterThunk("pthread_cond_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],word=0;Span(h,p,4);
        if(j.Regs()[1]){Span(h,j.Regs()[1],4);word=h.MemoryRead32(j.Regs()[1]);}
        if(word&~2u){j.Regs()[0]=ENOTSUP;return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_conditions.count(p)){j.Regs()[0]=EBUSY;return;}
        g_conditions.emplace(p,std::make_shared<Condition>((word&2)?CLOCK_MONOTONIC:CLOCK_REALTIME));
        h.MemoryWrite32(p,word);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_cond_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto value=GetCondition(h,p);if(!value){j.Regs()[0]=errno;return;}
        std::lock_guard lock(g_sync_mutex);
        if(value.use_count()!=2){j.Regs()[0]=EBUSY;return;}
        int rc=pthread_cond_destroy(&value->value);
        if(!rc){value->live=false;g_conditions.erase(p);h.MemoryWrite32(p,0xdeadc0de);}
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_cond_wait",[](Jit& j,Host& h){j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],0,false);});
    RegisterThunk("pthread_cond_timedwait",[](Jit& j,Host& h){
        if(!j.Regs()[2]){j.Regs()[0]=EINVAL;return;}
        j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],false);
    });
    RegisterThunk("pthread_cond_timeout_np",[](Jit& j,Host& h){j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],true);});
    RegisterThunk("pthread_cond_signal",[](Jit& j,Host& h){auto c=GetCondition(h,j.Regs()[0]);j.Regs()[0]=c?c->Signal():errno;});
    RegisterThunk("pthread_cond_broadcast",[](Jit& j,Host& h){auto c=GetCondition(h,j.Regs()[0]);j.Regs()[0]=c?c->Broadcast():errno;});
    RegisterThunk("pthread_once",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],fn=j.Regs()[1];Span(h,p,4);
        if(!fn){j.Regs()[0]=EINVAL;return;}
        std::shared_ptr<Once> once;
        {std::lock_guard lock(g_sync_mutex);auto& slot=g_once[p];
            if(!slot){slot=std::make_shared<Once>();uint32_t state=h.MemoryRead32(p);
                if(state!=0&&state!=2)Invalid("unknown pthread_once state");slot->state=state;}
            once=slot;
        }
        const bool done=once->Run([&]{h.MemoryWrite32(p,1);h.RunWorkerFunction(fn,{});
            bool complete=h.LastCallReturned();h.MemoryWrite32(p,complete?2:0);return complete;});
        if(!done)Invalid("pthread_once initializer did not return");
        j.Regs()[0]=0;
    });
    RegisterThunk("pthread_key_create",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);std::lock_guard lock(g_keys_mutex);
        if(g_keys.size()>=128||!g_next_key){j.Regs()[0]=EAGAIN;return;}
        uint32_t key=g_next_key++;g_keys.emplace(key,Key{j.Regs()[1]});h.MemoryWrite32(j.Regs()[0],key);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_key_delete",[](Jit& j,Host&){
        uint32_t key=j.Regs()[0];std::lock_guard lock(g_keys_mutex);
        if(!g_keys.erase(key)){j.Regs()[0]=EINVAL;return;}t_keys.erase(key);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_setspecific",[](Jit& j,Host&){
        std::lock_guard lock(g_keys_mutex);
        if(!g_keys.count(j.Regs()[0])){j.Regs()[0]=EINVAL;return;}
        for(auto it=t_keys.begin();it!=t_keys.end();)if(!g_keys.count(it->first))it=t_keys.erase(it);else ++it;
        t_keys[j.Regs()[0]]=j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_getspecific",[](Jit& j,Host&){
        std::lock_guard lock(g_keys_mutex);auto it=t_keys.find(j.Regs()[0]);
        j.Regs()[0]=g_keys.count(j.Regs()[0])&&it!=t_keys.end()?it->second:0;
    });
    RegisterThunk("sem_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];Span(h,p,4);
        if(j.Regs()[1]){Failure(j,h,ENOTSUP);return;}
        if(j.Regs()[2]>INT_MAX){Failure(j,h,EINVAL);return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_semaphores.count(p)){Failure(j,h,EBUSY);return;}
        g_semaphores.emplace(p,std::make_shared<Semaphore>(j.Regs()[2]));h.MemoryWrite32(p,0);j.Regs()[0]=0;
    });
    RegisterThunk("sem_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto sem=GetSemaphore(p);if(!sem){Failure(j,h,EINVAL);return;}
        std::lock_guard lock(g_sync_mutex);
        if(sem.use_count()!=2){Failure(j,h,EBUSY);return;}
        int rc=sem_destroy(&sem->value);if(!rc){sem->live=false;g_semaphores.erase(p);h.MemoryWrite32(p,0xdeadc0de);}Result(j,h,rc);
    });
    RegisterThunk("sem_wait",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_wait(&s->value):-1);});
    RegisterThunk("sem_trywait",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_trywait(&s->value):-1);});
    RegisterThunk("sem_post",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_post(&s->value):-1);});
    RegisterThunk("sem_getvalue",[](Jit& j,Host& h){
        auto s=GetSemaphore(j.Regs()[0]);if(!s){Failure(j,h,EINVAL);return;}
        Span(h,j.Regs()[1],4);int value=0;int rc=sem_getvalue(&s->value,&value);
        if(!rc)h.MemoryWrite32(j.Regs()[1],value);Result(j,h,rc);
    });
    RegisterThunk("pthread_equal",[](Jit& j,Host&){j.Regs()[0]=j.Regs()[0]==j.Regs()[1];});
    RegisterThunk("__get_tls",[](Jit& j,Host& h){j.Regs()[0]=Tls(h);});
    RegisterThunk("pthread_attr_setdetachstate",[](Jit& j,Host& h){
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        if(j.Regs()[1]>1){j.Regs()[0]=EINVAL;return;}
        a->flags=(a->flags&~1u)|j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_setstacksize",[](Jit& j,Host& h){
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        if(j.Regs()[1]<16384||j.Regs()[1]>4*1024*1024-65536){j.Regs()[0]=EINVAL;return;}
        a->size=j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_condattr_init",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);h.MemoryWrite32(j.Regs()[0],0);j.Regs()[0]=0;});
    RegisterThunk("pthread_condattr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);j.Regs()[0]=0;});
    RegisterThunk("pthread_condattr_setclock",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);
        if(j.Regs()[1]!=CLOCK_REALTIME&&j.Regs()[1]!=CLOCK_MONOTONIC){j.Regs()[0]=EINVAL;return;}
        h.MemoryWrite32(j.Regs()[0],j.Regs()[1]==CLOCK_MONOTONIC?2:0);j.Regs()[0]=0;
    });
}
