// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/tx_id.h"

#include "ccf/ds/json.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  std::string TxID::to_str() const
  {
    return std::to_string(view) + "." + std::to_string(seqno);
  }

  std::optional<TxID> TxID::from_str(const std::string_view& sv)
  {
    const auto separator_idx = sv.find(".");
    if (separator_idx == std::string_view::npos)
    {
      return std::nullopt;
    }

    TxID tx_id;

    {
      const auto view_sv = sv.substr(0, separator_idx);
      const auto [p, ec] =
        std::from_chars(view_sv.begin(), view_sv.end(), tx_id.view);
      if (ec != std::errc() || p != view_sv.end())
      {
        return std::nullopt;
      }
    }

    {
      const auto seqno_sv = sv.substr(separator_idx + 1);
      const auto [p, ec] =
        std::from_chars(seqno_sv.begin(), seqno_sv.end(), tx_id.seqno);
      if (ec != std::errc() || p != seqno_sv.end())
      {
        return std::nullopt;
      }
    }

    return tx_id;
  }

  bool TxID::operator==(const TxID& other) const
  {
    return view == other.view && seqno == other.seqno;
  }

  void to_json(nlohmann::json& j, const TxID& tx_id)
  {
    j = tx_id.to_str();
  }

  void from_json(const nlohmann::json& j, TxID& tx_id)
  {
    if (!j.is_string())
    {
      throw JsonParseError(
        fmt::format("Cannot parse TxID: Expected string, got {}", j.dump()));
    }

    const auto opt = TxID::from_str(j.get<std::string>());
    if (!opt.has_value())
    {
      throw JsonParseError(fmt::format("Cannot parse TxID: {}", j.dump()));
    }

    tx_id = opt.value();
  }

  std::string schema_name(const TxID&)
  {
    return "TransactionId";
  }

  void fill_json_schema(nlohmann::json& schema, const TxID&)
  {
    schema["type"] = "string";
    schema["pattern"] = "^[0-9]+\\.[0-9]+$";
  }
}
