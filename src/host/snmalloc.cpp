// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define NO_BOOTSTRAP_ALLOCATOR

#ifndef NDEBUG
#  define NDEBUG
#endif

#include "snmalloc/src/override/malloc.cc"
#include "snmalloc/src/override/new.cc"