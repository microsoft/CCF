// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifndef INSIDE_ENCLAVE

#  error \
    "This file is a replacement for openenclave/enclave.h, and should only be included from enclave-specific code"

#endif

#ifndef VIRTUAL_ENCLAVE

#  include <openenclave/enclave.h>

#else

// Repeat or approximate a lot of OE definitions, so that the virtual library
// can be compiled without any reference to OpenEnclave. This may need updating
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

OE_EXTERNC bool oe_is_within_enclave(const void* p, std::size_t n)
{
  return false;
}

OE_EXTERNC bool oe_is_outside_enclave(const void* p, std::size_t n)
{
  return !oe_is_within_enclave(p, n);
}

#endif