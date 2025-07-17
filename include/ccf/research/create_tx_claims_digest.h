// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <kv/kv_types.h>
#include <optional>

namespace ccf
{
  /** Can be optionally implemented by the application to set the claims digest
   * for the initial network create transaction.
   *
   * @return an optional claims digest
   */
  std::optional<ccf::ClaimsDigest::Digest> get_create_tx_claims_digest(
    ccf::kv::ReadOnlyTx& tx);
}
