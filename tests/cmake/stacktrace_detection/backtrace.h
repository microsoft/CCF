// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdint.h>

// Test-only names prevent the host's libbacktrace from satisfying this probe.
#define backtrace_create_state ccf_fixture_backtrace_create_state
#define backtrace_simple ccf_fixture_backtrace_simple
#define backtrace_pcinfo ccf_fixture_backtrace_pcinfo
#define backtrace_syminfo ccf_fixture_backtrace_syminfo

struct backtrace_state;
using backtrace_error_callback = void (*)(void*, const char*, int);
backtrace_state* backtrace_create_state(
  const char*, int, backtrace_error_callback, void*);
int backtrace_simple(
  backtrace_state*,
  int,
  int (*)(void*, uintptr_t),
  backtrace_error_callback,
  void*);
int backtrace_pcinfo(
  backtrace_state*,
  uintptr_t,
  int (*)(void*, uintptr_t, const char*, int, const char*),
  backtrace_error_callback,
  void*);
int backtrace_syminfo(
  backtrace_state*,
  uintptr_t,
  void (*)(void*, uintptr_t, const char*, uintptr_t, uintptr_t),
  backtrace_error_callback,
  void*);
