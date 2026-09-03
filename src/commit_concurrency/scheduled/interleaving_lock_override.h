// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Force-included (via a -include compiler flag) into every translation
// unit of the scheduled test target, before anything else, so that
// ccf::pal::Mutex itself (see include/ccf/pal/locking.h) resolves to
// SchedulerMutex for the whole of that target - and nowhere else, since no
// other target passes this flag. Every production call site that declares
// a ccf::pal::Mutex is therefore covered automatically, with no
// per-call-site changes anywhere in production code.
//
// Any static/singleton state reachable from this target that itself uses
// ccf::pal::Mutex (e.g. ccf::tasks' job board) is covered by this too, as
// long as every thread that can touch it is registered with the scheduler
// for the currently-running schedule - see DriverRegistration in
// deterministic_scheduler.h for the thread that runs make_run()/
// on_schedule() itself, outside of any actor thread.
//
// CCF_TEST_INTERLEAVING_LOCK_TYPE must be defined before
// deterministic_scheduler.h is included below - that header now also
// includes ccf/pal/locking.h itself (to install its lock-label sink; see
// SchedulerThreadContext), and ccf/pal/locking.h's own #pragma once means
// whichever definition of Mutex is in scope on its first inclusion in this
// translation unit is the one every subsequent include sees.
#define CCF_TEST_INTERLEAVING_LOCK_TYPE ccf::kv::test::SchedulerMutex

#include "commit_concurrency/scheduled/deterministic_scheduler.h"
