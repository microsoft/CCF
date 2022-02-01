// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifndef INSIDE_ENCLAVE

#  error \
    "This file is a replacement for openenclave/enclave.h, and should only be included from enclave-specific code"

#endif

#ifndef VIRTUAL_ENCLAVE

#  include <openenclave/edger8r/enclave.h> // For oe_lfence
#  include <openenclave/enclave.h>

bool ccf_allocator_mallinfo(ccf_mallinfo_t& info)
{
  oe_mallinfo_t oe_info;
  if (oe_allocator_mallinfo(&oe_info) != OE_OK)
  {
    return false;
  }
  info.max_total_heap_size = oe_info.max_total_heap_size;
  info.current_allocated_heap_size = oe_info.current_allocated_heap_size;
  info.peak_allocated_heap_size = oe_info.peak_allocated_heap_size;
  return true;
}

#else

// Repeat or approximate a lot of OE definitions, so that the virtual library
// can be compiled without any reference to Open Enclave. This may need updating
// to stay up-to-date with OE.

#  define OE_EXTERNC extern "C"

#  ifdef __GNUC__
#    define OE_EXPORT __attribute__((visibility("default")))
#  elif _MSC_VER
#    define OE_EXPORT __declspec(dllexport)
#  else
#    error "OE_EXPORT unimplemented"
#  endif

#  define OE_ECALL OE_EXTERNC OE_EXPORT __attribute__((section(".ecall")))

OE_EXTERNC bool oe_is_within_enclave(const void*, std::size_t)
{
  return false;
}

OE_EXTERNC bool oe_is_outside_enclave(const void*, std::size_t)
{
  return true;
}

#  define oe_lfence() // nop

bool ccf_allocator_mallinfo(ccf_mallinfo_t& info)
{
  info.max_total_heap_size = std::numeric_limits<size_t>::max();
  info.current_allocated_heap_size = 0;
  info.peak_allocated_heap_size = 0;
  return true;
}

#endif