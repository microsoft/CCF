// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <charconv>
#include <cstdint>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace ccf
{
  /** Transactions occur within a fixed View. Each View generally spans a range
   * of transactions, though empty Views are also possible. The View is advanced
   * by the consensus protocol during election of a new leader, and a single
   * leader is assigned in each View.  *View* and *Term* are synonymous.
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
    View view = VIEW_UNKNOWN;
    SeqNo seqno = SEQNO_UNKNOWN;

    [[nodiscard]] std::string to_str() const
    {
      return std::to_string(view) + "." + std::to_string(seqno);
    }

    static std::optional<TxID> from_str(const std::string_view& sv)
    {
      const auto separator_idx = sv.find('.');
      if (separator_idx == std::string_view::npos)
      {
        return std::nullopt;
      }

      TxID tx_id;

      {
        const auto view_sv = sv.substr(0, separator_idx);
        const auto [p, ec] =
          std::from_chars(view_sv.begin(), view_sv.end(), tx_id.view);
        if (
          ec != std::errc() || p != view_sv.end() || tx_id.view == VIEW_UNKNOWN)
        {
          return std::nullopt;
        }
      }

      {
        const auto seqno_sv = sv.substr(separator_idx + 1);
        const auto [p, ec] =
          std::from_chars(seqno_sv.begin(), seqno_sv.end(), tx_id.seqno);
        if (
          ec != std::errc() || p != seqno_sv.end() ||
          tx_id.seqno == SEQNO_UNKNOWN)
        {
          return std::nullopt;
        }
      }

      return tx_id;
    }

    bool operator==(const TxID& other) const
    {
      return view == other.view && seqno == other.seqno;
    }
  };

  // ADL-found functions used during JSON conversion and OpenAPI/JSON schema
  // generation
  inline void to_json(nlohmann::json& j, const TxID& tx_id)
  {
    j = tx_id.to_str();
  }

  inline void from_json(const nlohmann::json& j, TxID& tx_id)
  {
    if (!j.is_string())
    {
      throw ccf::JsonParseError(
        fmt::format("Cannot parse TxID: Expected string, got {}", j.dump()));
    }

    const auto opt = TxID::from_str(j.get<std::string>());
    if (!opt.has_value())
    {
      throw ccf::JsonParseError(fmt::format("Cannot parse TxID: {}", j.dump()));
    }

    tx_id = opt.value();
  }

  inline std::string schema_name(
    [[maybe_unused]] const TxID* transaction_id_type)
  {
    return "TransactionId";
  }

  inline void fill_json_schema(
    nlohmann::json& schema, [[maybe_unused]] const TxID* transaction_id_type)
  {
    schema["type"] = "string";
    schema["pattern"] = "^[0-9]+\\.[0-9]+$";
  }
}
