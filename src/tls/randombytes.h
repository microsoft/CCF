// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <stddef.h>

// TODO: Rename this function
extern int ccf_randombytes(void* buf, size_t n);

static inline int randombytes(void *buf, size_t n)
{
  ccf_randombytes(buf, n);
  return 0;
}

