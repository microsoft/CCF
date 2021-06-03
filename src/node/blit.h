// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "code_id.h"
#include "crypto/pem.h"
#include "kv/serialise_entry_blit.h"

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

  template <>
  struct BlitSerialiser<ccf::CodeDigest>
  {
    static SerialisedEntry to_serialised(const ccf::CodeDigest& code_digest)
    {
      auto hex_str = ds::to_hex(code_digest.data);
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::CodeDigest from_serialised(const SerialisedEntry& data)
    {
      ccf::CodeDigest ret;
      ds::from_hex(std::string(data.data(), data.end()), ret.data);
      return ret;
    }
  };
}