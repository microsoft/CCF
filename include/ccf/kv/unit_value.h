// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/get_name.h"
#include "ccf/kv/hooks.h"
#include "ccf/kv/unit_value_handle.h"
#include "ccf/kv/untyped.h"

namespace ccf::kv
{
  /** Defines the schema of a touched-only type accessed by a @c ccf::Tx. This
   * value is a container for an optional single marker indicating whether it
   * has been touched.
   *
   * This is implemented as a @c ccf::kv::Map from Unit to Unit, and the
   * serialisation of the fixed key and value are overridable with the Unit
   * template parameter.
   */
  template <typename Unit = ccf::kv::serialisers::ZeroBlitUnitCreator>
  class UnitValue : public GetName
  {
  public:
    using ReadOnlyHandle = ccf::kv::ReadableUnitValueHandle<Unit>;
    using WriteOnlyHandle = ccf::kv::WriteableUnitValueHandle<Unit>;
    using Handle = ccf::kv::UnitValueHandle<Unit>;

    using Write = std::optional<ccf::kv::serialisers::SerialisedEntry>;
    using MapHook = ccf::kv::MapHook<Write>;
    using CommitHook = ccf::kv::CommitHook<Write>;

    using GetName::GetName;

    static ccf::kv::serialisers::SerialisedEntry create_unit()
    {
      return Unit::get();
    }

  private:
    static Write deserialise_write(const ccf::kv::untyped::Write& w)
    {
      const auto it = w.find(Unit::get());
      if (it == w.end() || !it->second.has_value())
      {
        return std::nullopt;
      }

      return Unit::get();
    }

  public:
    static ccf::kv::untyped::CommitHook wrap_commit_hook(const CommitHook& hook)
    {
      return [hook](Version v, const ccf::kv::untyped::Write& w) {
        hook(v, deserialise_write(w));
      };
    }

    static ccf::kv::untyped::MapHook wrap_map_hook(const MapHook& hook)
    {
      return [hook](Version v, const ccf::kv::untyped::Write& w) {
        return hook(v, deserialise_write(w));
      };
    }
  };
}
