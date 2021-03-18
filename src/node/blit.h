// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "crypto/pem.h"
#include "kv/serialise_entry_blit.h"

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<ccf::EntityId>
  {
    static SerialisedEntry to_serialised(const ccf::EntityId& entity_id)
    {
      const auto& data = entity_id.value();
      return SerialisedEntry(data.begin(), data.end());
    }

    static ccf::EntityId from_serialised(const SerialisedEntry& data)
    {
      return ccf::EntityId(std::string(data.begin(), data.end()));
    }
  };

  template <>
  struct BlitSerialiser<crypto::Pem>
  {
    static SerialisedEntry to_serialised(const crypto::Pem& pem)
    {
      const auto& data = pem.raw();
      return SerialisedEntry(data.begin(), data.end());
    }

    static crypto::Pem from_serialised(const SerialisedEntry& data)
    {
      return crypto::Pem(data.data(), data.size());
    }
  };
}