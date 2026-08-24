// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(__clang__)
#  define CCF_THREAD_SAFETY_ATTRIBUTE(attribute) __attribute__((attribute))
#else
#  define CCF_THREAD_SAFETY_ATTRIBUTE(attribute)
#endif

#define CCF_CAPABILITY(name) CCF_THREAD_SAFETY_ATTRIBUTE(capability(name))
#define CCF_SCOPED_CAPABILITY CCF_THREAD_SAFETY_ATTRIBUTE(scoped_lockable)
#define CCF_GUARDED_BY(...) CCF_THREAD_SAFETY_ATTRIBUTE(guarded_by(__VA_ARGS__))
#define CCF_PT_GUARDED_BY(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(pt_guarded_by(__VA_ARGS__))
#define CCF_ACQUIRED_BEFORE(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(acquired_before(__VA_ARGS__))
#define CCF_ACQUIRED_AFTER(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(acquired_after(__VA_ARGS__))
#define CCF_REQUIRES(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(requires_capability(__VA_ARGS__))
#define CCF_REQUIRES_SHARED(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(requires_shared_capability(__VA_ARGS__))
#define CCF_EXCLUDES(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(locks_excluded(__VA_ARGS__))
#define CCF_ACQUIRE(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(acquire_capability(__VA_ARGS__))
#define CCF_ACQUIRE_SHARED(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(acquire_shared_capability(__VA_ARGS__))
#define CCF_RELEASE(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(release_capability(__VA_ARGS__))
#define CCF_RELEASE_SHARED(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(release_shared_capability(__VA_ARGS__))
#define CCF_RELEASE_GENERIC(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(release_generic_capability(__VA_ARGS__))
#define CCF_TRY_ACQUIRE(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(try_acquire_capability(__VA_ARGS__))
#define CCF_TRY_ACQUIRE_SHARED(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(try_acquire_shared_capability(__VA_ARGS__))
#define CCF_ASSERT_CAPABILITY(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(assert_capability(__VA_ARGS__))
#define CCF_ASSERT_SHARED_CAPABILITY(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(assert_shared_capability(__VA_ARGS__))
#define CCF_RETURN_CAPABILITY(...) \
  CCF_THREAD_SAFETY_ATTRIBUTE(lock_returned(__VA_ARGS__))
#define CCF_NO_THREAD_SAFETY_ANALYSIS \
  CCF_THREAD_SAFETY_ATTRIBUTE(no_thread_safety_analysis)

// ci-checks exception - only defines macros
namespace ccf
{}
