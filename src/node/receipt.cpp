// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/receipt.h"

#define FROM_JSON_TRY_PARSE(TYPE, FIELD) \
  try \
  { \
    out.FIELD = it->get<decltype(TYPE::FIELD)>(); \
  } \
  catch (JsonParseError & jpe) \
  { \
    jpe.pointer_elements.push_back(#FIELD); \
    throw; \
  }

#define FROM_JSON_GET_REQUIRED_FIELD(TYPE, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it == j.end()) \
    { \
      throw JsonParseError(fmt::format( \
        "Missing required field '" #FIELD "' in object:", j.dump())); \
    } \
    FROM_JSON_TRY_PARSE(TYPE, FIELD) \
  }

#define FROM_JSON_GET_OPTIONAL_FIELD(TYPE, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it != j.end()) \
    { \
      FROM_JSON_TRY_PARSE(TYPE, FIELD) \
    } \
  }

namespace ccf
{
  void to_json(
    nlohmann::json& j, const LeafExpandedReceipt::Components& components)
  {
    j = nlohmann::json::object();

    j["write_set_digest"] = components.write_set_digest;
    j["commit_evidence"] = components.commit_evidence;
    j["claims_digest"] = components.claims_digest;
  }

  void from_json(const nlohmann::json& j, LeafExpandedReceipt::Components& out)
  {
    if (!j.is_object())
    {
      throw JsonParseError(fmt::format(
        "Cannot parse Receipt LeafComponents: Expected object, got {}",
        j.dump()));
    }

    FROM_JSON_GET_REQUIRED_FIELD(
      LeafExpandedReceipt::Components, write_set_digest);
    FROM_JSON_GET_REQUIRED_FIELD(
      LeafExpandedReceipt::Components, commit_evidence);

    // claims_digest is always _emitted_ by current code, but may be
    // missing from old receipts. When parsing those from JSON, treat it as
    // optional
    FROM_JSON_GET_OPTIONAL_FIELD(
      LeafExpandedReceipt::Components, claims_digest);
  }

  std::string schema_name(const LeafExpandedReceipt::Components*)
  {
    return "Receipt__LeafComponents";
  }

  void fill_json_schema(
    nlohmann::json& schema, const LeafExpandedReceipt::Components*)
  {
    schema = nlohmann::json::object();
    schema["type"] = "object";

    auto required = nlohmann::json::array();
    auto properties = nlohmann::json::object();

    {
      required.push_back("claims_digest");
      properties["claims_digest"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(
          LeafExpandedReceipt::Components::claims_digest)>());

      required.push_back("commit_evidence");
      properties["commit_evidence"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(
          LeafExpandedReceipt::Components::commit_evidence)>());

      required.push_back("write_set_digest");
      properties["write_set_digest"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(
          LeafExpandedReceipt::Components::write_set_digest)>());
    }

    schema["required"] = required;
    schema["properties"] = properties;
  }

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
      schema["properties"][name] = ds::openapi::components_ref_object(
        ds::json::schema_name<crypto::Sha256Hash>());
      return schema;
    };

    schema["type"] = "object";
    schema["oneOf"] = nlohmann::json::array();
    schema["oneOf"].push_back(possible_hash("left"));
    schema["oneOf"].push_back(possible_hash("right"));
  }

  void to_json(nlohmann::json& j, const ReceiptPtr& receipt)
  {
    if (receipt == nullptr)
    {
      throw JsonParseError(
        fmt::format("Cannot serialise Receipt to JSON: Got nullptr"));
    }

    j = nlohmann::json::object();

    j["signature"] = receipt->signature;
    j["proof"] = receipt->proof;
    j["node_id"] = receipt->node_id;
    j["cert"] = receipt->cert;
    j["service_endorsements"] = receipt->service_endorsements;

    if (auto ld_receipt = std::dynamic_pointer_cast<LeafDigestReceipt>(receipt))
    {
      j["leaf"] = ld_receipt->leaf;
    }
    else if (
      auto le_receipt = std::dynamic_pointer_cast<LeafExpandedReceipt>(receipt))
    {
      j["leaf_components"] = le_receipt->leaf_components;
    }
  }

  void from_json(const nlohmann::json& j, ReceiptPtr& receipt)
  {
    if (!j.is_object())
    {
      throw JsonParseError(
        fmt::format("Cannot parse Receipt: Expected object, got {}", j.dump()));
    }

    const auto leaf_it = j.find("leaf");
    const auto has_leaf = leaf_it != j.end();

    const auto leaf_components_it = j.find("leaf_components");
    const auto has_leaf_components = leaf_components_it != j.end();

    if (has_leaf && !has_leaf_components)
    {
      auto ld_receipt = std::make_shared<LeafDigestReceipt>();

      auto& out = *ld_receipt;
      FROM_JSON_GET_REQUIRED_FIELD(LeafDigestReceipt, leaf);

      receipt = ld_receipt;
    }
    else if (!has_leaf && has_leaf_components)
    {
      auto le_receipt = std::make_shared<LeafExpandedReceipt>();

      auto& out = *le_receipt;
      FROM_JSON_GET_REQUIRED_FIELD(LeafExpandedReceipt, leaf_components);

      receipt = le_receipt;
    }
    else
    {
      throw JsonParseError(fmt::format(
        "Cannot parse Receipt: Expected either 'leaf' or 'leaf_components' "
        "field, got {}",
        j.dump()));
    }

    auto& out = *receipt;
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, signature);
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, proof);
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, node_id);
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, cert);

    // service_endorsements is always _emitted_ by current code, but may be
    // missing from old receipts. When parsing those from JSON, treat it as
    // optional
    FROM_JSON_GET_OPTIONAL_FIELD(Receipt, service_endorsements);
  }

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
      required.push_back("cert");
      properties["cert"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::cert)>());

      required.push_back("node_id");
      properties["node_id"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::node_id)>());

      required.push_back("proof");
      properties["proof"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::proof)>());

      required.push_back("service_endorsements");
      properties["service_endorsements"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::service_endorsements)>());

      required.push_back("signature");
      properties["signature"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::signature)>());

      properties["leaf_components"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(
          LeafExpandedReceipt::leaf_components)>());

      properties["leaf"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(LeafDigestReceipt::leaf)>());

      // This says the required properties are all the properties we currently
      // have, AND one of either leaf OR leaf_components. It inserts the
      // following element into the schema, constructing a composite required
      // list:
      // "allOf":
      // [
      //   {"required": ["cert", "signature"...]},
      //   {
      //     "oneOf": [
      //       {"required": ["leaf"]},
      //       {"required": ["leaf_components"]}
      //     ]
      //   }
      // ]
      const auto oneOf = nlohmann::json::object(
        {{"oneOf",
          nlohmann::json::array(
            {nlohmann::json::object(
               {{"required", nlohmann::json::array({"leaf"})}}),
             nlohmann::json::object(
               {{"required", nlohmann::json::array({"leaf_components"})}})})}});

      schema["allOf"] = nlohmann::json::array(
        {nlohmann::json::object({{"required", required}}), oneOf});
    }

    schema["properties"] = properties;
  }
}