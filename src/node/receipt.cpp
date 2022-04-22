// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/receipt.h"

namespace ccf
{
  void to_json(nlohmann::json& j, const Receipt::ProofStep& step)
  {
    j = nlohmann::json::object();
    const auto key =
      step.direction == Receipt::ProofStep::Left ? "left" : "right";
    j[key] = step.hash;
  }

  void from_json(const nlohmann::json& j, Receipt::ProofStep& step)
  {
    if (!j.is_object())
    {
      throw JsonParseError(fmt::format(
        "Cannot parse Receipt Step: Expected object, got {}", j.dump()));
    }

    const auto l_it = j.find("left");
    const auto r_it = j.find("right");
    if ((l_it == j.end()) == (r_it == j.end()))
    {
      throw JsonParseError(fmt::format(
        "Cannot parse Receipt Step: Expected either 'left' or 'right' field, "
        "got {}",
        j.dump()));
    }

    if (l_it != j.end())
    {
      step.direction = Receipt::ProofStep::Left;
      step.hash = l_it.value();
    }
    else
    {
      step.direction = Receipt::ProofStep::Right;
      step.hash = r_it.value();
    }
  }

  std::string schema_name(const Receipt::ProofStep*)
  {
    return "Receipt__Element";
  }

  void fill_json_schema(nlohmann::json& schema, const Receipt::ProofStep*)
  {
    schema = nlohmann::json::object();

    auto possible_hash = [](const auto& name) {
      auto schema = nlohmann::json::object();
      schema["required"] = nlohmann::json::array();
      schema["required"].push_back(name);
      schema["properties"] = nlohmann::json::object();
      // schema["properties"][name] =
      //   ds::openapi::add_schema_component<crypto::Sha256Hash>();
      return schema;
    };

    schema["type"] = "object";
    schema["oneOf"] = nlohmann::json::array();
    schema["oneOf"].push_back(possible_hash("left"));
    schema["oneOf"].push_back(possible_hash("right"));
  }

  void to_json(nlohmann::json& j, const ReceiptPtr& receipt) {}

  void from_json(const nlohmann::json& j, ReceiptPtr& receipt) {}

  std::string schema_name(const ReceiptPtr*)
  {
    return "Receipt";
  }

  void fill_json_schema(nlohmann::json& schema, const ReceiptPtr*)
  {
    schema = nlohmann::json::object();
    schema["type"] = "object";

    auto required = nlohmann::json::array();
    auto properties = nlohmann::json::object();

    {
      required.push_back("signature");
      // properties["signature"] =
      //   ds::openapi::add_schema_component<decltype(Receipt::signature)>();
    }

    schema["required"] = required;
    schema["properties"] = properties;
  }
}