// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ccf
{
  using View = uint64_t;
  using SeqNo = uint64_t;

  struct TxID
  {
    View view;
    SeqNo seqno;

    std::string to_str() const
    {
      return std::to_string(view) + "." + std::to_string(seqno);
    }

    static std::optional<TxID> from_str(const std::string_view& sv)
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
  };

  // ADL-found functions used during OpenAPI/JSON schema generation
  inline std::string schema_name(const TxID&)
  {
    return "TransactionId";
  }

  inline void fill_json_schema(nlohmann::json& schema, const TxID&)
  {
    schema["type"] = "string";
    schema["pattern"] = "^[0-9]+\\.[0-9]+$";
  }
}