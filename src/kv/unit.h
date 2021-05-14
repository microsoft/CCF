// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/serialised_entry.h"

namespace kv
{
  // A single-valued type, used as a utility type to convert kv::Maps to
  // kv::Values and kv::Sets. Specifically, these are implemented as wrappers so
  // that kv::Value<T> is implemented as kv::Map<Unit, T>, and kv::Set<T> is
  // kv::Map<T, Unit>.
  struct Unit
  {
    static kv::serialisers::SerialisedEntry get()
    {
      return {};
    }
  };
}
