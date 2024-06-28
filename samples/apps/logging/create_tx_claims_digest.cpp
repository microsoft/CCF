// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <ccf/receipt.h>
#include <ccf/service/tables/constitution.h>
#include <ccf/tx.h>
#include <optional>

namespace ccf
{
  std::optional<ccf::ClaimsDigest::Digest> get_create_tx_claims_digest(
    kv::ReadOnlyTx& tx)
  {
    auto constitution =
      tx.ro<ccf::Constitution>(ccf::Tables::CONSTITUTION)->get();
    if (!constitution.has_value())
    {
      throw std::logic_error("Constitution is missing");
    }
    return ccf::ClaimsDigest::Digest(constitution.value());
  }
}
