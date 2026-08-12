// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf::gov::endpoints::api
{
  namespace detail
  {
    inline nlohmann::json string(
      const std::optional<std::string>& pattern = std::nullopt)
    {
      auto schema = nlohmann::json{{"type", "string"}};
      if (pattern.has_value())
      {
        schema["pattern"] = pattern.value();
      }
      return schema;
    }

    inline nlohmann::json integer()
    {
      return {{"type", "integer"}, {"minimum", 0}};
    }

    inline nlohmann::json array(nlohmann::json items)
    {
      return {{"type", "array"}, {"items", std::move(items)}};
    }

    inline nlohmann::json map(nlohmann::json values)
    {
      return {{"type", "object"}, {"additionalProperties", std::move(values)}};
    }

    inline nlohmann::json object(
      nlohmann::json properties,
      std::initializer_list<const char*> required = {})
    {
      auto schema = nlohmann::json{
        {"type", "object"}, {"properties", std::move(properties)}};
      if (required.size() > 0)
      {
        schema["required"] = required;
      }
      return schema;
    }

    inline nlohmann::json id()
    {
      return string("^[a-f0-9]{64}$");
    }

    inline nlohmann::json proposal()
    {
      const auto failure =
        object({{"reason", string()}, {"trace", string()}}, {"reason"});
      return object(
        {
          {"proposalId", id()},
          {"proposerId", id()},
          {"proposalState",
           {{"type", "string"},
            {"enum",
             {"Open",
              "Accepted",
              "Withdrawn",
              "Rejected",
              "Failed",
              "Dropped"}}}},
          {"ballotCount", integer()},
          {"ballotSubmitters", array(id())},
          {"finalVotes", map({{"type", "boolean"}})},
          {"voteFailures", map(failure)},
          {"failure", failure},
        },
        {
          "proposalId",
          "proposerId",
          "proposalState",
          "ballotCount",
          "ballotSubmitters",
        });
    }

    inline nlohmann::json member()
    {
      return object(
        {
          {"memberId", id()},
          {"status", {{"type", "string"}, {"enum", {"Accepted", "Active"}}}},
          {"memberData", nlohmann::json::object()},
          {"certificate", string()},
          {"publicEncryptionKey", string()},
          {"recoveryRole",
           {{"type", "string"},
            {"enum", {"NonParticipant", "Participant", "Owner"}}}},
        },
        {"memberId", "status", "memberData", "recoveryRole"});
    }

    inline nlohmann::json user()
    {
      return object(
        {
          {"userId", id()},
          {"certificate", string()},
          {"userData", nlohmann::json::object()},
        },
        {"userId", "certificate", "userData"});
    }

    inline nlohmann::json node()
    {
      const auto network_interface = object(
        {{"publishedAddress", string()}, {"protocol", string()}},
        {"publishedAddress"});
      const auto quote_info = object(
        {
          {"format",
           {{"type", "string"},
            {"enum", {"OE_SGX_v1", "Insecure_Virtual", "AMD_SEV_SNP_v1"}}}},
          {"quote", string()},
          {"endorsements", string()},
          {"rawQuote", string()},
          {"details", {{"type", "object"}}},
          {"uvmEndorsements", string()},
          {"endorsedTcb", string()},
        },
        {"format"});
      return object(
        {
          {"nodeId", id()},
          {"status",
           {{"type", "string"}, {"enum", {"Pending", "Trusted", "Retired"}}}},
          {"nodeData", nlohmann::json::object()},
          {"certificate", string()},
          {"retiredCommitted", {{"type", "boolean"}}},
          {"quoteInfo", quote_info},
          {"rpcInterfaces", map(network_interface)},
        },
        {
          "nodeId",
          "status",
          "nodeData",
          "retiredCommitted",
          "quoteInfo",
          "rpcInterfaces",
        });
    }
  }

  struct StateDigest
  {};
  struct Proposal
  {};
  struct ProposalList
  {};
  struct ProposalActions
  {};
  struct EncryptedRecoveryShare
  {};
  struct RecoveryResponse
  {};
  struct Transaction
  {};
  struct ServiceInfo
  {};
  struct JavascriptApp
  {};
  struct OriginalCase
  {};
  struct JavascriptModules
  {};
  struct JoinPolicy
  {};
  struct JwkInfo
  {};
  struct Member
  {};
  struct MemberList
  {};
  struct User
  {};
  struct UserList
  {};
  struct Node
  {};
  struct NodeList
  {};

  inline std::string schema_name(const StateDigest*)
  {
    return "GovStateDigest";
  }

  inline void fill_json_schema(nlohmann::json& schema, const StateDigest*)
  {
    schema = detail::object(
      {
        {"memberId", detail::id()},
        {"stateDigest", detail::string("^[a-f0-9]{64}$")},
      },
      {"memberId", "stateDigest"});
  }

  inline std::string schema_name(const Proposal*)
  {
    return "GovProposal";
  }

  inline void fill_json_schema(nlohmann::json& schema, const Proposal*)
  {
    schema = detail::proposal();
  }

  inline std::string schema_name(const ProposalList*)
  {
    return "GovProposalList";
  }

  inline void fill_json_schema(nlohmann::json& schema, const ProposalList*)
  {
    schema =
      detail::object({{"value", detail::array(detail::proposal())}}, {"value"});
  }

  inline std::string schema_name(const ProposalActions*)
  {
    return "GovProposalActions";
  }

  inline void fill_json_schema(nlohmann::json& schema, const ProposalActions*)
  {
    const auto action = detail::object(
      {{"name", detail::string()}, {"args", nlohmann::json::object()}},
      {"name"});
    schema = detail::object({{"actions", detail::array(action)}}, {"actions"});
  }

  inline std::string schema_name(const EncryptedRecoveryShare*)
  {
    return "GovEncryptedRecoveryShare";
  }

  inline void fill_json_schema(
    nlohmann::json& schema, const EncryptedRecoveryShare*)
  {
    schema = detail::object(
      {
        {"memberId", detail::id()},
        {"encryptedShare", {{"type", "string"}, {"format", "byte"}}},
      },
      {"memberId", "encryptedShare"});
  }

  inline std::string schema_name(const RecoveryResponse*)
  {
    return "GovRecoveryResponse";
  }

  inline void fill_json_schema(nlohmann::json& schema, const RecoveryResponse*)
  {
    schema = detail::object(
      {
        {"message", detail::string()},
        {"submittedCount", detail::integer()},
        {"recoveryThreshold", detail::integer()},
        {"fullKeySubmitted", {{"type", "boolean"}}},
      },
      {
        "message",
        "submittedCount",
        "recoveryThreshold",
        "fullKeySubmitted",
      });
  }

  inline std::string schema_name(const Transaction*)
  {
    return "GovTransaction";
  }

  inline void fill_json_schema(nlohmann::json& schema, const Transaction*)
  {
    schema = detail::object(
      {
        {"status",
         {{"type", "string"},
          {"enum", {"Unknown", "Pending", "Committed", "Invalid"}}}},
        {"transactionId", detail::string("^[0-9]+\\.[0-9]+$")},
      },
      {"status", "transactionId"});
  }

  inline std::string schema_name(const ServiceInfo*)
  {
    return "GovServiceInfo";
  }

  inline void fill_json_schema(nlohmann::json& schema, const ServiceInfo*)
  {
    const auto configuration = detail::object(
      {
        {"recoveryThreshold", detail::integer()},
        {"maximumNodeCertificateValidityDays", detail::integer()},
        {"maximumServiceCertificateValidityDays", detail::integer()},
        {"recentCoseProposalsWindowSize", detail::integer()},
      },
      {
        "recoveryThreshold",
        "maximumNodeCertificateValidityDays",
        "maximumServiceCertificateValidityDays",
        "recentCoseProposalsWindowSize",
      });
    schema = detail::object(
      {
        {"status",
         {{"type", "string"},
          {"enum",
           {"Opening", "Open", "WaitingForRecoveryShares", "Recovering"}}}},
        {"certificate", detail::string()},
        {"recoveryCount", detail::integer()},
        {"creationTransactionId", detail::string("^[0-9]+\\.[0-9]+$")},
        {"previousServiceCreationTransactionId",
         detail::string("^[0-9]+\\.[0-9]+$")},
        {"serviceData", nlohmann::json::object()},
        {"configuration", configuration},
      },
      {"status", "certificate", "recoveryCount", "serviceData"});
  }

  inline std::string schema_name(const JavascriptApp*)
  {
    return "GovJavascriptApp";
  }

  inline void fill_json_schema(nlohmann::json& schema, const JavascriptApp*)
  {
    schema = detail::object(
      {{"endpoints", detail::map({{"type", "object"}})}}, {"endpoints"});
  }

  inline std::string schema_name(const OriginalCase*)
  {
    return "GovJavascriptAppCase";
  }

  inline void fill_json_schema(nlohmann::json& schema, const OriginalCase*)
  {
    schema = {{"type", "string"}, {"enum", {"original"}}};
  }

  inline std::string schema_name(const JavascriptModules*)
  {
    return "GovJavascriptModules";
  }

  inline void fill_json_schema(nlohmann::json& schema, const JavascriptModules*)
  {
    const auto module =
      detail::object({{"moduleName", detail::string()}}, {"moduleName"});
    schema = detail::object({{"value", detail::array(module)}}, {"value"});
  }

  inline std::string schema_name(const JoinPolicy*)
  {
    return "GovJoinPolicy";
  }

  inline void fill_json_schema(nlohmann::json& schema, const JoinPolicy*)
  {
    const auto measurements =
      detail::array({{"type", "string"}, {"format", "hex"}});
    const auto basic_policy =
      detail::object({{"measurements", measurements}}, {"measurements"});
    const auto virtual_policy = detail::object(
      {
        {"measurements", measurements},
        {"hostData", detail::array(detail::string("^[a-f0-9]{64}$"))},
      },
      {"measurements", "hostData"});
    const auto snp_policy = detail::object(
      {
        {"measurements", measurements},
        {"hostData", detail::map(detail::string())},
        {"uvmEndorsements", {{"type", "object"}}},
        {"tcbVersions", {{"type", "object"}}},
      },
      {"measurements", "hostData", "uvmEndorsements", "tcbVersions"});
    schema = detail::object(
      {
        {"sgx", basic_policy},
        {"virtual", virtual_policy},
        {"snp", snp_policy},
      },
      {"sgx", "virtual", "snp"});
  }

  inline std::string schema_name(const JwkInfo*)
  {
    return "GovJwkInfo";
  }

  inline void fill_json_schema(nlohmann::json& schema, const JwkInfo*)
  {
    const auto issuer = detail::object(
      {
        {"autoRefresh", {{"type", "boolean"}}},
        {"caCertBundleName", detail::string()},
      },
      {"autoRefresh"});
    const auto key = detail::object(
      {
        {"publicKey", detail::string()},
        {"issuer", detail::string()},
        {"constraint", nlohmann::json::object()},
      },
      {"publicKey", "issuer", "constraint"});
    schema = detail::object(
      {
        {"issuers", detail::map(issuer)},
        {"keys", detail::map(detail::array(key))},
        {"caCertBundles", detail::map(detail::string())},
      },
      {"issuers", "keys", "caCertBundles"});
  }

  inline std::string schema_name(const Member*)
  {
    return "GovMember";
  }

  inline void fill_json_schema(nlohmann::json& schema, const Member*)
  {
    schema = detail::member();
  }

  inline std::string schema_name(const MemberList*)
  {
    return "GovMemberList";
  }

  inline void fill_json_schema(nlohmann::json& schema, const MemberList*)
  {
    schema =
      detail::object({{"value", detail::array(detail::member())}}, {"value"});
  }

  inline std::string schema_name(const User*)
  {
    return "GovUser";
  }

  inline void fill_json_schema(nlohmann::json& schema, const User*)
  {
    schema = detail::user();
  }

  inline std::string schema_name(const UserList*)
  {
    return "GovUserList";
  }

  inline void fill_json_schema(nlohmann::json& schema, const UserList*)
  {
    schema =
      detail::object({{"value", detail::array(detail::user())}}, {"value"});
  }

  inline std::string schema_name(const Node*)
  {
    return "GovNode";
  }

  inline void fill_json_schema(nlohmann::json& schema, const Node*)
  {
    schema = detail::node();
  }

  inline std::string schema_name(const NodeList*)
  {
    return "GovNodeList";
  }

  inline void fill_json_schema(nlohmann::json& schema, const NodeList*)
  {
    schema =
      detail::object({{"value", detail::array(detail::node())}}, {"value"});
  }
}
