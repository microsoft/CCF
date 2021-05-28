// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/serialised_entry.h"

namespace kv
{
  // Unit serialisations are used as a utility type to convert kv::Maps to
  // kv::Maps and kv::Sets. Specifically, these are implemented as wrappers so
  // that kv::Value<T> is essentially kv::Map<Unit, T>, and kv::Set<T> is
  // kv::Map<T, Unit>.
  // This is used as a template parameter allowing the caller to specify what
  // value is inserted into the ledger.

  // This is the default UnitCreator, returning 8 null bytes for compatibility
  // with old ledgers (where Values were previously Maps with a single entry
  // at key 0, serialised as a uint64_t)
  struct UnitCreator
  {
    static kv::serialisers::SerialisedEntry get()
    {
      kv::serialisers::SerialisedEntry e;
      e.assign(8, 0u);
      return e;
    }
  };

  struct EmptyUnitCreator
  {
    static kv::serialisers::SerialisedEntry get()
    {
      return {};
    }
  };
}
