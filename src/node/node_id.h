// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <fmt/format.h>
#include <string>

namespace ccf
{
  struct NodeId
  {
    // The underlying value type should be blit-serialisable so that it can be
    // written to and read from the ring buffer
    using Value =
      std::string; // < hex-encoded hash of node's identity public key
    Value id;

    NodeId() = default;

    NodeId(const Value& id_) : id(id_) {}

    void operator=(const NodeId& other)
    {
      id = other.id;
    }

    void operator=(const Value& id_)
    {
      id = id_;
    }

    bool operator==(const NodeId& other) const
    {
      return id == other.id;
    }

    bool operator!=(const NodeId& other) const
    {
      return !(*this == other);
    }

    bool operator<(const NodeId& other) const
    {
      return id < other.id;
    }

    operator Value() const
    {
      return id;
    }

    auto& value() const
    {
      return id;
    }

    size_t size() const
    {
      return id.size();
    }

    MSGPACK_DEFINE(id);
  };

  inline void to_json(nlohmann::json& j, const NodeId& node_id)
  {
    j = node_id.id;
  }

  inline void from_json(const nlohmann::json& j, NodeId& node_id)
  {
    if (j.is_string())
    {
      // We should check that the node ID is a valid hex-encoded sha-256 hash.
      // However, the BFT variant of the consensus still uses monotic node IDs
      // so this cannot be done just yet (see
      // https://github.com/microsoft/CCF/issues/1852)
      node_id = j.get<std::string>();
    }
    else
    {
      throw JsonParseError(
        fmt::format("Unable to parse Node id from this JSON: {}", j.dump()));
    }
  }

  inline std::string schema_name(const NodeId&)
  {
    return "NodeId";
  }

  inline void fill_json_schema(nlohmann::json& schema, const NodeId&)
  {
    schema["type"] = "string";

    // According to the spec, "format is an open value, so you can use any
    // formats, even not those defined by the OpenAPI Specification"
    // https://swagger.io/docs/specification/data-models/data-types/#format
    schema["format"] = "hex";
  }

  template <typename T>
  void add_schema_components(T&, nlohmann::json& j, const NodeId&)
  {
    j["type"] = "string";
    j["pattern"] = "^[a-f0-9]{64}$";
  }
}

namespace std
{
  static inline std::ostream& operator<<(
    std::ostream& os, const ccf::NodeId& node_id)
  {
    os << node_id.id;
    return os;
  }

  template <>
  struct hash<ccf::NodeId>
  {
    size_t operator()(const ccf::NodeId& node_id) const
    {
      return std::hash<std::string>{}(node_id.id);
    }
  };
}

// Only display the first node_id_truncation_max_char_count character when
// printing the node id to the node's log
static constexpr size_t node_id_truncation_max_char_count = 10;

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::NodeId>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::NodeId& node_id, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(
      ctx.out(),
      "{}",
      node_id.id.substr(
        0, std::min(node_id.id.size(), node_id_truncation_max_char_count)));
  }
};
FMT_END_NAMESPACE