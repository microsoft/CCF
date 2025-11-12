// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/receipt.h"

#define FROM_JSON_TRY_PARSE(TYPE, DOC, FIELD) \
  try \
  { \
    (DOC).FIELD = it->get<decltype(TYPE::FIELD)>(); \
  } \
  catch (ccf::JsonParseError & jpe) \
  { \
    jpe.pointer_elements.emplace_back(#FIELD); \
    throw; \
  }

#define FROM_JSON_GET_REQUIRED_FIELD(TYPE, DOC, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it == j.end()) \
    { \
      throw ccf::JsonParseError(fmt::format( \
        "Missing required field '" #FIELD "' in object:", j.dump())); \
    } \
    FROM_JSON_TRY_PARSE(TYPE, DOC, FIELD) \
  }

#define FROM_JSON_GET_OPTIONAL_FIELD(TYPE, DOC, FIELD) \
  { \
    const auto it = j.find(#FIELD); \
    if (it != j.end()) \
    { \
      FROM_JSON_TRY_PARSE(TYPE, DOC, FIELD) \
    } \
  }

namespace ccf
{
  void to_json(nlohmann::json& j, const ProofReceipt::Components& components)
  {
    j = nlohmann::json::object();

    j["write_set_digest"] = components.write_set_digest;
    j["commit_evidence"] = components.commit_evidence;

    if (!components.claims_digest.empty())
    {
      j["claims_digest"] = components.claims_digest;
    }
  }

  void from_json(const nlohmann::json& j, ProofReceipt::Components& components)
  {
    if (!j.is_object())
    {
      throw ccf::JsonParseError(fmt::format(
        "Cannot parse Receipt LeafComponents: Expected object, got {}",
        j.dump()));
    }

    FROM_JSON_GET_REQUIRED_FIELD(
      ProofReceipt::Components, components, write_set_digest);
    FROM_JSON_GET_REQUIRED_FIELD(
      ProofReceipt::Components, components, commit_evidence);

    // claims_digest is always _emitted_ by current code, but may be
    // missing from old receipts. When parsing those from JSON, treat it as
    // optional
    FROM_JSON_GET_OPTIONAL_FIELD(
      ProofReceipt::Components, components, claims_digest);
  }

  std::string schema_name(const ProofReceipt::Components* components)
  {
    (void)components;
    return "Receipt__LeafComponents";
  }

  void fill_json_schema(
    nlohmann::json& schema, const ProofReceipt::Components* components)
  {
    (void)components;
    schema = nlohmann::json::object();
    schema["type"] = "object";

    auto required = nlohmann::json::array();
    auto properties = nlohmann::json::object();

    {
      required.push_back("claims_digest");
      properties["claims_digest"] = ds::openapi::components_ref_object(
        ds::json::schema_name<
          decltype(ProofReceipt::Components::claims_digest)>());

      required.push_back("commit_evidence");
      properties["commit_evidence"] = ds::openapi::components_ref_object(
        ds::json::schema_name<
          decltype(ProofReceipt::Components::commit_evidence)>());

      required.push_back("write_set_digest");
      properties["write_set_digest"] = ds::openapi::components_ref_object(
        ds::json::schema_name<
          decltype(ProofReceipt::Components::write_set_digest)>());
    }

    schema["required"] = required;
    schema["properties"] = properties;
  }

  void to_json(nlohmann::json& j, const ProofReceipt::ProofStep& step)
  {
    j = nlohmann::json::object();
    const auto* const key =
      step.direction == ProofReceipt::ProofStep::Direction::Left ? "left" :
                                                                   "right";
    j[key] = step.hash;
  }

  void from_json(const nlohmann::json& j, ProofReceipt::ProofStep& step)
  {
    if (!j.is_object())
    {
      throw ccf::JsonParseError(fmt::format(
        "Cannot parse Receipt Step: Expected object, got {}", j.dump()));
    }

    const auto l_it = j.find("left");
    const auto r_it = j.find("right");
    if ((l_it == j.end()) == (r_it == j.end()))
    {
      throw ccf::JsonParseError(fmt::format(
        "Cannot parse Receipt Step: Expected either 'left' or 'right' field, "
        "got {}",
        j.dump()));
    }

    if (l_it != j.end())
    {
      step.direction = ProofReceipt::ProofStep::Direction::Left;
      step.hash = l_it.value();
    }
    else
    {
      step.direction = ProofReceipt::ProofStep::Direction::Right;
      step.hash = r_it.value();
    }
  }

  std::string schema_name(const ProofReceipt::ProofStep* step)
  {
    (void)step;
    return "Receipt__Element";
  }

  void fill_json_schema(
    nlohmann::json& schema, const ProofReceipt::ProofStep* step)
  {
    (void)step;
    schema = nlohmann::json::object();

    auto possible_hash = [](const auto& name) {
      auto schema = nlohmann::json::object();
      schema["required"] = nlohmann::json::array();
      schema["required"].push_back(name);
      schema["properties"] = nlohmann::json::object();
      schema["properties"][name] = ds::openapi::
        components_ref_object( // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
          ds::json::schema_name<ccf::crypto::Sha256Hash>());
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
      throw ccf::JsonParseError(
        fmt::format("Cannot serialise Receipt to JSON: Got nullptr"));
    }

    j = nlohmann::json::object();

    j["signature"] = receipt->signature;
    j["node_id"] = receipt->node_id;
    j["cert"] = receipt->cert;
    j["service_endorsements"] = receipt->service_endorsements;
    j["is_signature_transaction"] = receipt->is_signature_transaction();

    if (receipt->is_signature_transaction())
    {
      throw std::logic_error(
        "Conversion of signature receipts to JSON is currently undefined");
    }

    auto p_receipt = std::dynamic_pointer_cast<ProofReceipt>(receipt);
    if (p_receipt == nullptr)
    {
      throw std::logic_error("Unexpected receipt type");
    }

    j["leaf_components"] = p_receipt->leaf_components;
    j["proof"] = p_receipt->proof;
  }

  void from_json(const nlohmann::json& j, ReceiptPtr& receipt)
  {
    if (!j.is_object())
    {
      throw ccf::JsonParseError(
        fmt::format("Cannot parse Receipt: Expected object, got {}", j.dump()));
    }

    const auto is_sig_it = j.find("is_signature_transaction");
    if (is_sig_it != j.end())
    {
      const bool is_sig = is_sig_it->get<bool>();

      if (!is_sig)
      {
        auto p_receipt = std::make_shared<ProofReceipt>();

        auto& out = *p_receipt;
        FROM_JSON_GET_REQUIRED_FIELD(ProofReceipt, out, leaf_components);
        FROM_JSON_GET_REQUIRED_FIELD(ProofReceipt, out, proof);

        receipt = p_receipt;
      }
      else
      {
        throw ccf::JsonParseError(fmt::format(
          "Cannot parse Receipt: Expected 'leaf_components' and 'proof'"
          "fields, got {}",
          j.dump()));
      }
    }
    else
    {
      // An old receipt format! Look for leaf field or leaf_components, and
      // parse to new representation accordingly
      const auto leaf_it = j.find("leaf");
      const auto has_leaf = leaf_it != j.end();

      const auto leaf_components_it = j.find("leaf_components");
      const auto has_leaf_components = leaf_components_it != j.end();

      if (has_leaf && !has_leaf_components)
      {
        auto sig_receipt = std::make_shared<SignatureReceipt>();

        try
        {
          sig_receipt->signed_root =
            leaf_it->get<decltype(SignatureReceipt::signed_root)>();
        }
        catch (ccf::JsonParseError& jpe)
        {
          jpe.pointer_elements.emplace_back("leaf");
          throw;
        }

        receipt = sig_receipt;
      }
      else if (!has_leaf && has_leaf_components)
      {
        auto p_receipt = std::make_shared<ProofReceipt>();

        auto& out = *p_receipt;
        FROM_JSON_GET_REQUIRED_FIELD(ProofReceipt, out, leaf_components);
        FROM_JSON_GET_REQUIRED_FIELD(ProofReceipt, out, proof);

        receipt = p_receipt;
      }
      else
      {
        throw ccf::JsonParseError(fmt::format(
          "Cannot parse v1 Receipt: Expected either 'leaf' or "
          "'leaf_components' "
          "field, got {}",
          j.dump()));
      }
    }

    auto& out = *receipt;
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, out, signature);
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, out, node_id);
    FROM_JSON_GET_REQUIRED_FIELD(Receipt, out, cert);

    // service_endorsements is always _emitted_ by current code, but may be
    // missing from old receipts. When parsing those from JSON, treat it as
    // optional
    FROM_JSON_GET_OPTIONAL_FIELD(Receipt, out, service_endorsements);
  }

  std::string schema_name(const ReceiptPtr* receipt)
  {
    (void)receipt;
    return "Receipt";
  }

  void fill_json_schema(nlohmann::json& schema, const ReceiptPtr* receipt)
  {
    (void)receipt;
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

      required.push_back("service_endorsements");
      properties["service_endorsements"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::service_endorsements)>());

      required.push_back("signature");
      properties["signature"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(Receipt::signature)>());

      required.push_back("proof");
      properties["proof"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(ProofReceipt::proof)>());

      properties["leaf_components"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(ProofReceipt::leaf_components)>());

      properties["leaf"] = ds::openapi::components_ref_object(
        ds::json::schema_name<decltype(SignatureReceipt::signed_root)>());

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
      //       {"required": ["leaf_components", "proof"]}
      //     ]
      //   }
      // ]
      const auto oneOf = nlohmann::json::object(
        {{"oneOf",
          nlohmann::json::array(
            {nlohmann::json::object(
               {{"required", nlohmann::json::array({"leaf"})}}),
             nlohmann::json::object(
               {{"required",
                 nlohmann::json::array({"leaf_components", "proof"})}})})}});

      schema["allOf"] = nlohmann::json::array(
        {nlohmann::json::object({{"required", required}}), oneOf});
    }

    schema["properties"] = properties;
  }
}