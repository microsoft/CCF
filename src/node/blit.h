// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/pem.h"
#include "entity_id.h"
#include "kv/serialise_entry_blit.h"
#include "node/rpc/endpoint.h"

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

  template <>
  struct BlitSerialiser<ccf::endpoints::EndpointKey>
  {
    static SerialisedEntry to_serialised(
      const ccf::endpoints::EndpointKey& endpoint_key)
    {
      size_t size_ = sizeof(size_t) + endpoint_key.uri_path.size() +
        sizeof(endpoint_key.verb);
      SerialisedEntry data(size_);
      auto data_ = data.data();

      serialized::write(data_, size_, endpoint_key.uri_path);
      serialized::write(data_, size_, endpoint_key.verb);
      return data;
    }

    static ccf::endpoints::EndpointKey from_serialised(
      const SerialisedEntry& data)
    {
      auto data_ = data.data();
      auto size_ = data.size();

      auto uri_path = serialized::read<ccf::endpoints::URI>(data_, size_);
      auto verb = serialized::read<ccf::RESTVerb>(data_, size_);
      return {uri_path, verb};
    }
  };
}
