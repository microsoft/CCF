// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/research/create_tx_claims_digest.h"

#include <optional>

namespace ccf
{
  std::optional<ccf::ClaimsDigest::Digest> __attribute__((weak))
  get_create_tx_claims_digest(ccf::kv::ReadOnlyTx& tx)
  {
    return std::nullopt;
  }
}
