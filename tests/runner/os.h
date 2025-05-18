#pragma once

#include "helpers.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#ifdef __WATCOMC__
#include <process.h> // provides gettid
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#endif
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#endif

#ifdef _WIN32
typedef CRITICAL_SECTION mutex_t;
typedef CONDITION_VARIABLE condvar_t;
#define HAVE_TIMED_WAIT 0
#else
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t condvar_t;

#if defined(__WATCOMC__) || defined(__APPLE__)
#define HAVE_TIMED_WAIT 0
#else
#define HAVE_TIMED_WAIT 1
#endif
#endif

#define NANOSECONDS_PER_SECOND 1000000000ull

static inline uint64_t get_nanosecond_timer(void)
{
#ifdef _WIN32
    static LARGE_INTEGER frequency;
    LARGE_INTEGER counter;

    if (frequency.QuadPart == 0)
        if (!QueryPerformanceFrequency(&frequency))
            error("QueryPerformanceFrequency failed");

    if (!QueryPerformanceCounter(&counter))
        error("QueryPerformanceCounter failed");

    counter.QuadPart *= NANOSECONDS_PER_SECOND;
    return counter.QuadPart / frequency.QuadPart;
#elif defined(__APPLE__)
    static struct mach_timebase_info tb;
    static bool initialized;

    if (!initialized) {
        if (mach_timebase_info(&tb) != KERN_SUCCESS)
            error("mach_timebase_info failed");
        initialized = true;
    }

    return (mach_absolute_time() * tb.numer) / tb.denom;
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        error("clock_gettime failed");

    return ts.tv_sec * NANOSECONDS_PER_SECOND + ts.tv_nsec;
#endif
}

static inline void *get_thread_id(void)
{
#ifdef _WIN32
    return (void*)((uintptr_t)GetCurrentThreadId());
#elif defined(__APPLE__)
    uint64_t id;

    if (pthread_threadid_np(NULL, &id))
        error("pthread_threadid_np failed");
    return (void*)id;
#else
    return (void*)((uintptr_t)gettid());
#endif
}

static inline void millisecond_sleep(uint64_t milliseconds)
{
#ifdef _WIN32
    Sleep(milliseconds);
#else
    if (usleep(milliseconds * 1000))
        error("usleep failed");
#endif
}

static inline void mutex_init(mutex_t *mutex)
{
#ifdef _WIN32
    InitializeCriticalSection(mutex);
#else
    if (pthread_mutex_init(mutex, NULL))
        error("pthread_mutex_init failed");
#endif
}

static inline void mutex_free(mutex_t *mutex)
{
#ifdef _WIN32
    DeleteCriticalSection(mutex);
#else
    if (pthread_mutex_destroy(mutex))
        error("pthread_mutex_destroy failed");
#endif
}

static inline bool mutex_try_lock(mutex_t *mutex)
{
#ifdef _WIN32
    return TryEnterCriticalSection(mutex);
#else
    int err = pthread_mutex_trylock(mutex);

    if (err == 0)
        return true;
    if (err != EBUSY)
        error("pthread_mutex_trylock failed");
    return false;
#endif
}

static inline void mutex_lock(mutex_t *mutex)
{
#ifdef _WIN32
    EnterCriticalSection(mutex);
#else
    if (pthread_mutex_lock(mutex))
        error("pthread_mutex_lock failed");
#endif
}

static inline bool mutex_lock_timeout(mutex_t *mutex, uint64_t timeout_ns)
{
#if !HAVE_TIMED_WAIT
    uint64_t end = get_nanosecond_timer() + timeout_ns;

    do {
        if (mutex_try_lock(mutex))
            return true;
        millisecond_sleep(1);
    } while (get_nanosecond_timer() < end);

    return false;
#else
    struct timespec spec;
    int err;

    if (clock_gettime(CLOCK_MONOTONIC, &spec))
        error("clock_gettime failed");

    spec.tv_nsec += timeout_ns;
    spec.tv_sec += spec.tv_nsec / NANOSECONDS_PER_SECOND;
    spec.tv_nsec %= NANOSECONDS_PER_SECOND;

    err = pthread_mutex_clocklock(mutex, CLOCK_MONOTONIC, &spec);
    if (err == 0)
        return true;
    if (err != ETIMEDOUT)
        error("pthread_mutex_clocklock failed");
    return false;
#endif
}

static inline void mutex_unlock(mutex_t *mutex)
{
#ifdef _WIN32
    LeaveCriticalSection(mutex);
#else
    if (pthread_mutex_unlock(mutex))
        error("pthread_mutex_unlock failed");
#endif
}

static inline void condvar_init(condvar_t *var)
{
#ifdef _WIN32
    InitializeConditionVariable(var);
#else
    if (pthread_cond_init(var, NULL))
        error("pthread_cond_init failed");
#endif
}

static inline void condvar_free(condvar_t *var)
{
#ifdef _WIN32
    UACPI_UNUSED(var);
#else
    if (pthread_cond_destroy(var))
        error("pthread_cond_destroy failed");
#endif
}

typedef bool (*condvar_pred_t)(void *ctx);

static inline void condvar_wait(
    condvar_t *var, mutex_t *mutex, condvar_pred_t pred, void *ctx
)
{
    while (!pred(ctx))
#ifdef _WIN32
        if (!SleepConditionVariableCS(var, mutex, INFINITE))
            error("SleepConditionVariableCS failed");
#else
        if (pthread_cond_wait(var, mutex))
            error("pthread_cond_wait failed");
#endif
}

static inline bool condvar_wait_timeout(
    condvar_t *var, mutex_t *mutex, condvar_pred_t pred, void *ctx,
    uint64_t timeout_ns
)
{
#if !HAVE_TIMED_WAIT
    uint64_t end = get_nanosecond_timer() + timeout_ns;

    while (!pred(ctx)) {
        uint64_t cur = get_nanosecond_timer();
#ifdef _WIN32
        DWORD milliseconds;
#endif

        if (cur >= end)
            return false;

#ifdef _WIN32
        milliseconds = (end - cur) / 1000;
        if (milliseconds == 0)
            milliseconds = 1;

        if (!SleepConditionVariableCS(var, mutex, milliseconds) &&
            GetLastError() != ERROR_TIMEOUT) {
            error("SleepConditionVariableCS failed");
        }
#else
        UACPI_UNUSED(var);
        mutex_unlock(mutex);
        millisecond_sleep(1);
        mutex_lock(mutex);
#endif
    }

    return true;
#else
    struct timespec spec;

    if (clock_gettime(CLOCK_MONOTONIC, &spec))
        error("clock_gettime failed");

    spec.tv_nsec += timeout_ns;
    spec.tv_sec += spec.tv_nsec / NANOSECONDS_PER_SECOND;
    spec.tv_nsec %= NANOSECONDS_PER_SECOND;

    while (!pred(ctx)) {
        int err = pthread_cond_clockwait(var, mutex, CLOCK_MONOTONIC, &spec);

        if (err == 0)
            continue;
        if (err != ETIMEDOUT)
            error("pthread_cond_clockwait failed");
        return false;
    }

    return true;
#endif
}

static inline void condvar_signal(condvar_t *var)
{
#ifdef _WIN32
    WakeConditionVariable(var);
#else
    if (pthread_cond_signal(var))
        error("pthread_cond_signal failed");
#endif
}
