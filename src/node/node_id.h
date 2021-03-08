// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entity_id.h"

#include <fmt/format.h>
#include <string>

namespace ccf
{
  struct NodeId : EntityId
  {
    NodeId() = default;

    NodeId(const Value& id_) : EntityId(id_) {}
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
    j["pattern"] = fmt::format("^[a-f0-9]{{{}}}$", EntityId::LENGTH);
  }
}

namespace std
{
  template <>
  struct hash<ccf::NodeId>
  {
    size_t operator()(const ccf::NodeId& node_id) const
    {
      return std::hash<ccf::EntityId>{}(node_id);
    }
  };
}

// Node ids are printed in many places (e.g. consensus) so only display the
// first node_id_truncation_max_char_count characters when printing it to the
// node's log (e.g. using the LOG_..._FMT() macros)
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
      node_id.value().substr(
        0, std::min(node_id.size(), node_id_truncation_max_char_count)));
  }
};
FMT_END_NAMESPACE