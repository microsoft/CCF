// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/bits/security.h>
#else
#  include <cstring>
#endif

static inline void* ccf_memcpy(void* dest, const void* src, size_t count)
{
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
  return oe_memcpy_with_barrier(dest, src, count);
#else
  return ::memcpy(dest, src, count);
#endif
}
