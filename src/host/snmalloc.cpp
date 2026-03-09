// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
// NOLINTBEGIN
#define NO_BOOTSTRAP_ALLOCATOR
#define SNMALLOC_USE_WAIT_ON_ADDRESS 0

#ifndef NDEBUG
#  define NDEBUG
#endif

#include "snmalloc/src/snmalloc/override/malloc.cc"
#include "snmalloc/src/snmalloc/override/new.cc"
// NOLINTEND