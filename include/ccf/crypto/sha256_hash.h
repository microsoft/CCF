// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"

#include <array>
#include <span>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace crypto
{
  class Sha256Hash
  {
  public:
    static constexpr size_t SIZE = 256 / 8;
    using Representation = std::array<uint8_t, SIZE>;
    Representation h = {0};

    Sha256Hash() = default;

    inline void set(Representation&& r)
    {
      h = std::move(r);
    }

    Sha256Hash(const uint8_t* data, size_t size);
    Sha256Hash(const std::vector<uint8_t>& vec);
    Sha256Hash(const std::string& str);
    Sha256Hash(const Sha256Hash& left, const Sha256Hash& right);
    Sha256Hash(
      const Sha256Hash& first,
      const Sha256Hash& second,
      const Sha256Hash& third);

    friend std::ostream& operator<<(
      std::ostream& os, const crypto::Sha256Hash& h);

    std::string hex_str() const;

    static Sha256Hash from_hex_string(const std::string& str);
    static Sha256Hash from_span(const std::span<const uint8_t, SIZE>& sp);
    static Sha256Hash from_representation(const Representation& r);
  };

  void to_json(nlohmann::json& j, const Sha256Hash& hash);

  void from_json(const nlohmann::json& j, Sha256Hash& hash);

  std::string schema_name(const Sha256Hash*);

  void fill_json_schema(nlohmann::json& schema, const Sha256Hash*);

  bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs);

  bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs);
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<crypto::Sha256Hash>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const crypto::Sha256Hash& p, FormatContext& ctx) const
  {
    return format_to(ctx.out(), "<sha256 {:02x}>", fmt::join(p.h, ""));
  }
};
FMT_END_NAMESPACE

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<crypto::Sha256Hash>
  {
    static SerialisedEntry to_serialised(const crypto::Sha256Hash& h)
    {
      auto hex_str = h.hex_str();
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static crypto::Sha256Hash from_serialised(const SerialisedEntry& data)
    {
      auto data_str = std::string{data.begin(), data.end()};
      crypto::Sha256Hash ret;
      return ret.from_hex_string(data_str);
    }
  };
}
