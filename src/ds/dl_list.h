// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cassert>
#include <cstdint>

#define SNMALLOC_ASSERT assert

namespace snmalloc
{
  using address_t = uintptr_t;
}

#include "snmalloc/src/ds/dllist.h"

#include <assert.h>