// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "tls/key_pair.h"
#include "tls/verifier.h"

#include <vector>

namespace aft
{
  class Replica
  {
  public:
    Replica(kv::NodeId id_, const std::vector<uint8_t>& cert_) :
      id(id_),
      verifier(tls::make_unique_verifier(cert_))
    {}

    kv::NodeId get_id() const
    {
      return id;
    }

  private:
    kv::NodeId id;
    tls::VerifierUniquePtr verifier;
  };
}