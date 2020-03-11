#pragma once

#define SNMALLOC_ASSERT assert

namespace snmalloc
{
  using address_t = uintptr_t;
}

#include "snmalloc/src/ds/dllist.h"

#include <assert.h>