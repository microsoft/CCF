// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

namespace kv::serialisers
{
  template <typename FmtExtender>
  struct BlitSerialiser<ccf::EntityId<FmtExtender>>
  {
    static SerialisedEntry to_serialised(
      const ccf::EntityId<FmtExtender>& entity_id)
    {
      const auto& data = entity_id.value();
      return SerialisedEntry(data.begin(), data.end());
    }

    static ccf::EntityId<FmtExtender> from_serialised(
      const SerialisedEntry& data)
    {
      return ccf::EntityId<FmtExtender>(std::string(data.begin(), data.end()));
    }
  };
}