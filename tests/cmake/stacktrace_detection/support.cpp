// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "backtrace.h"

int ccf_stacktrace_fixture_support()
{
  return 0;
}

backtrace_state* backtrace_create_state(
  const char*, int, backtrace_error_callback, void*)
{
  return nullptr;
}
int backtrace_simple(
  backtrace_state*,
  int,
  int (*)(void*, uintptr_t),
  backtrace_error_callback,
  void*)
{
  return 0;
}
int backtrace_pcinfo(
  backtrace_state*,
  uintptr_t,
  int (*)(void*, uintptr_t, const char*, int, const char*),
  backtrace_error_callback,
  void*)
{
  return 0;
}
int backtrace_syminfo(
  backtrace_state*,
  uintptr_t,
  void (*)(void*, uintptr_t, const char*, uintptr_t, uintptr_t),
  backtrace_error_callback,
  void*)
{
  return 0;
}
