// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"

#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>

// This file stubs the following functions used by V8 that
// are not available in the Open Enclave standard libraries.
// Stubbing them is ok because they are not used by V8, mostly
// because we disable threading.

/*
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(sampler.o): in function
`v8::sampler::SignalHandler::IncreaseSamplerCount()':
./../../src/libsampler/sampler.cc:328: undefined reference to `sigemptyset'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(sampler.o): in function
`v8::sampler::Sampler::DoSample()':
./../../src/libsampler/sampler.cc:567: undefined reference to `pthread_kill'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(mutex.o): in function
`v8::base::SharedMutex::TryLockShared()':
./../../src/base/platform/mutex.cc:292: undefined reference to
`pthread_rwlock_tryrdlock' /usr/bin/ld:
../build-v8/debug-sgx/lib/libv8_monolith.a(semaphore.o): in function
`v8::base::Semaphore::Semaphore(int)':
./../../src/base/platform/semaphore.cc:48: undefined reference to `sem_init'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(semaphore.o): in
function `v8::base::Semaphore::~Semaphore()':
./../../src/base/platform/semaphore.cc:55: undefined reference to `sem_destroy'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(semaphore.o): in
function `v8::base::Semaphore::Signal()':
./../../src/base/platform/semaphore.cc:61: undefined reference to `sem_post'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(semaphore.o): in
function `v8::base::Semaphore::Wait()':
./../../src/base/platform/semaphore.cc:73: undefined reference to `sem_wait'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(platform-posix.o): in
function `v8::base::OS::SetPermissions(void*, unsigned long,
v8::base::OS::MemoryPermission)':
./../../src/base/platform/platform-posix.cc:436: undefined reference to
`mprotect' /usr/bin/ld:
../build-v8/debug-sgx/lib/libv8_monolith.a(platform-posix.o): in function
`v8::base::OS::DiscardSystemPages(void*, unsigned long)':
./../../src/base/platform/platform-posix.cc:477: undefined reference to
`madvise' /usr/bin/ld: ./../../src/base/platform/platform-posix.cc:488:
undefined reference to `madvise' /usr/bin/ld:
../build-v8/debug-sgx/lib/libv8_monolith.a(platform-posix.o): in function
`v8::base::OS::GetUserTime(unsigned int*, unsigned int*)':
./../../src/base/platform/platform-posix.cc:656: undefined reference to
`getrusage' /usr/bin/ld:
../build-v8/debug-sgx/lib/libv8_monolith.a(platform-posix.o): in function
`v8::base::Thread::Start()':
./../../src/base/platform/platform-posix.cc:879: undefined reference to
`pthread_attr_init' /usr/bin/ld:
./../../src/base/platform/platform-posix.cc:892: undefined reference to
`pthread_attr_setstacksize' /usr/bin/ld:
./../../src/base/platform/platform-posix.cc:893: undefined reference to
`pthread_attr_destroy' /usr/bin/ld:
./../../src/base/platform/platform-posix.cc:899: undefined reference to
`pthread_attr_destroy' /usr/bin/ld:
./../../src/base/platform/platform-posix.cc:902: undefined reference to
`pthread_attr_destroy' /usr/bin/ld:
../build-v8/debug-sgx/lib/libv8_monolith.a(platform-posix.o): in function
`v8::base::ThreadEntry(void*)':
./../../src/base/platform/platform-posix.cc:850: undefined reference to `prctl'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(stack_trace_posix.o): in
function `v8::base::debug::EnableInProcessStackDumping()':
./../../src/base/debug/stack_trace_posix.cc:336: undefined reference to
`sigemptyset' /usr/bin/ld: ./../../src/base/debug/stack_trace_posix.cc:346:
undefined reference to `sigemptyset' /usr/bin/ld:
../build-v8/debug-sgx/lib/libv8_monolith.a(stack_trace_posix.o): in function
`v8::base::debug::(anonymous namespace)::StackDumpSignalHandler(int, siginfo_t*,
void*)':
./../../src/base/debug/stack_trace_posix.cc:264: undefined reference to `_exit'
/usr/bin/ld: ../build-v8/debug-sgx/lib/libv8_monolith.a(platform-linux.o): in
function `v8::base::OS::RemapShared(void*, void*, unsigned long)':
./../../src/base/platform/platform-linux.cc:149: undefined reference to `mremap'
*/

#define CRASH(msg) \
  puts(msg); \
  abort()

extern "C"
{
  int sigemptyset(sigset_t* set)
  {
    CRASH("Open Enclave sigemptyset() stub called");
  }

  int pthread_attr_init(pthread_attr_t* attr)
  {
    CRASH("Open Enclave pthread_attr_init() stub called");
  }

  int pthread_attr_setstacksize(pthread_attr_t* attr, size_t stacksize)
  {
    CRASH("Open Enclave pthread_attr_setstacksize() stub called");
  }

  int pthread_attr_destroy(pthread_attr_t* attr)
  {
    CRASH("Open Enclave pthread_attr_destroy() stub called");
  }

  int pthread_kill(pthread_t thread, int sig)
  {
    CRASH("Open Enclave pthread_kill() stub called");
  }

  int pthread_rwlock_tryrdlock(pthread_rwlock_t* rwlock)
  {
    CRASH("Open Enclave pthread_rwlock_tryrdlock() stub called");
  }

  int sem_init(sem_t* sem, int pshared, unsigned int value)
  {
    // Semaphores are not supported by OE, but it's okay to con/de-struct them
    // as long as they are not used.
    return 0;
  }

  int sem_destroy(sem_t* sem)
  {
    // Semaphores are not supported by OE, but it's okay to con/de-struct them
    // as long as they are not used.
    return 0;
  }

  int sem_post(sem_t* sem)
  {
    CRASH("Open Enclave sem_post() stub called");
  }

  int sem_wait(sem_t* sem)
  {
    CRASH("Open Enclave sem_wait() stub called");
  }

  int mprotect(void* addr, size_t len, int prot)
  {
    // We can't change memory permissions in SGX, but that's ok.
    return 0;
  }

  int madvise(void* addr, size_t length, int advice)
  {
    // Not supported by OE, but only a performance hint anyway.
    return 0;
  }

  void* mremap(void* old_address, size_t old_size, size_t new_size, int flags)
  {
    CRASH("Open Enclave mremap() stub called");
  }

  int getrusage(int who, struct rusage* usage)
  {
    CRASH("Open Enclave getrusage() stub called");
  }

  int prctl(
    int option,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5)
  {
    CRASH("Open Enclave prctl() stub called");
  }

  void _exit(int status)
  {
    CRASH("Open Enclave _exit() stub called");
  }
}
