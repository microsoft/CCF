// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string_view>

namespace ccf::Tables
{
  // Names of the internal tables which the KV inspects when applying a ledger
  // entry, to identify signature transactions and past ledger secrets. They
  // are defined here rather than alongside the corresponding service table
  // types so that kv does not depend on service.
  static constexpr auto SIGNATURES = "public:ccf.internal.signatures";
  static constexpr auto COSE_SIGNATURES = "public:ccf.internal.cose_signatures";
  static constexpr auto SERIALISED_MERKLE_TREE = "public:ccf.internal.tree";
  static constexpr auto ENCRYPTED_PAST_LEDGER_SECRET =
    "public:ccf.internal.historical_encrypted_ledger_secret";
}

namespace ccf::kv
{
  inline constexpr bool is_signature_table(std::string_view name)
  {
    return name == ccf::Tables::SIGNATURES ||
      name == ccf::Tables::COSE_SIGNATURES ||
      name == ccf::Tables::SERIALISED_MERKLE_TREE;
  }
}