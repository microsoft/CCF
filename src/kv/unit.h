// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/serialised_entry.h"

namespace kv
{
  // A single-valued type, used as a utility type to convert kv::Maps to
  // kv::Values and kv::Sets. Specifically, these are implemented as wrappers so
  // that kv::Value<T> is essentially kv::Map<Unit, T>, and kv::Set<T> is
  // kv::Map<T, Unit>.
  struct Unit
  {
    static kv::serialisers::SerialisedEntry get()
    {
      // TODO: Should this be a 0? Our existing mono-valued tables had a single
      // value at key 0, we could remain ledger-compatible if we produce the
      // same value here. But that only works where we can guess the
      // serialisation format of that 0, and we're stuck with that inefficiency
      // forever.
      return {};
    }
  };
}
