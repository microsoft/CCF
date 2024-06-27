// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<ccf::crypto::Pem>
  {
    static SerialisedEntry to_serialised(const ccf::crypto::Pem& pem)
    {
      const auto& data = pem.raw();
      return SerialisedEntry(data.begin(), data.end());
    }

    static ccf::crypto::Pem from_serialised(const SerialisedEntry& data)
    {
      return ccf::crypto::Pem(data.data(), data.size());
    }
  };
}