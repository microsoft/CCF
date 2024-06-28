// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/serialisers/serialised_entry.h"

namespace ccf::kv::serialisers
{
  // Unit serialisations are used as a utility type to convert ccf::kv::Maps to
  // ccf::kv::Maps and ccf::kv::Sets. Specifically, these are implemented as
  // wrappers so that ccf::kv::Value<T> is essentially ccf::kv::Map<Unit, T>,
  // and ccf::kv::Set<T> is ccf::kv::Map<T, Unit>. This is used as a template
  // parameter allowing the caller to specify what value is inserted into the
  // ledger.

  // This is the default UnitCreator, returning 8 null bytes for compatibility
  // with old ledgers (where Values were previously Maps with a single entry
  // at key 0, serialised as a uint64_t)
  struct ZeroBlitUnitCreator
  {
    static ccf::kv::serialisers::SerialisedEntry get()
    {
      ccf::kv::serialisers::SerialisedEntry e;
      e.assign(sizeof(uint64_t), 0u);
      return e;
    }
  };

  struct EmptyUnitCreator
  {
    static ccf::kv::serialisers::SerialisedEntry get()
    {
      return {};
    }
  };
}
