// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace ccf
{
  /** Transactions occur within a fixed View. Each View generally spans a range
   * of transactions, though empty Views are also possible. The View is advanced
   * by the consensus protocol during election of a new leader, and a single
   * leader is assigned in each View.
   */
  using View = uint64_t;

  // No transactions occur in View 0.
  constexpr View VIEW_UNKNOWN = 0;

  /** Each transaction is assigned a unique incrementing SeqNo, maintained
   * across View transitions. This matches the order in which transactions are
   * applied, where a higher SeqNo means that a transaction executed later.
   * SeqNos are unique during normal operation, but around elections it is
   * possible for distinct transactions in separate Views to have the same
   * SeqNo. Only one of these transactions will ever commit, and the others are
   * ephemeral.
   */
  using SeqNo = uint64_t;

  // No transaction is assigned seqno 0.
  constexpr SeqNo SEQNO_UNKNOWN = 0;

  // The combination of View and SeqNo produce a unique TxID for each
  // transaction executed by CCF.
  struct TxID
  {
    View view;
    SeqNo seqno;

    std::string to_str() const;

    static std::optional<TxID> from_str(const std::string_view& sv);

    bool operator==(const TxID& other) const;
  };

  // ADL-found functions used during JSON conversion and OpenAPI/JSON schema
  // generation
  void to_json(nlohmann::json& j, const TxID& tx_id);
  void from_json(const nlohmann::json& j, TxID& tx_id);
  std::string schema_name(const TxID&);
  void fill_json_schema(nlohmann::json& schema, const TxID&);
}
