// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/nonstd.h"
#include "frontend.h"
#include "lua_interp/lua_json.h"
#include "lua_interp/tx_script_runner.h"
#include "node/genesis_gen.h"
#include "node/jwt.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/quote.h"
#include "node/secret_share.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "tls/base64.h"
#include "tls/key_pair.h"

#include <charconv>
#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <openenclave/attestation/verifier.h>
#include <set>
#include <sstream>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif

namespace ccf
{
  constexpr auto INVALID_PROPOSAL_ID = "INVALID";

  static oe_result_t oe_verify_attestation_certificate_with_evidence_cb(
    oe_claim_t* claims, size_t claims_length, void* arg)
  {
    auto claims_map = (std::map<std::string, std::vector<uint8_t>>*)arg;
    for (size_t i = 0; i < claims_length; i++)
    {
      std::string claim_name(claims[i].name);
      std::vector<uint8_t> claim_value(
        claims[i].value, claims[i].value + claims[i].value_size);
      claims_map->emplace(std::move(claim_name), std::move(claim_value));
    }
    return OE_OK;
  }

  class MemberTsr : public lua::TxScriptRunner
  {
    void setup_environment(
      lua::Interpreter& li,
      const std::optional<Script>& env_script) const override
    {
      TxScriptRunner::setup_environment(li, env_script);
    }

  public:
    MemberTsr(NetworkTables& network) : TxScriptRunner(network) {}
  };

  struct SetMemberData
  {
    MemberId member_id;
    nlohmann::json member_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SetMemberData)
  DECLARE_JSON_REQUIRED_FIELDS(SetMemberData, member_id)
  DECLARE_JSON_OPTIONAL_FIELDS(SetMemberData, member_data)

  struct SetUserData
  {
    UserId user_id;
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SetUserData)
  DECLARE_JSON_REQUIRED_FIELDS(SetUserData, user_id)
  DECLARE_JSON_OPTIONAL_FIELDS(SetUserData, user_data)

  struct SetModule
  {
    std::string name;
    Module module;
  };
  DECLARE_JSON_TYPE(SetModule)
  DECLARE_JSON_REQUIRED_FIELDS(SetModule, name, module)

  struct JsBundleEndpointMethod : public ccf::endpoints::EndpointProperties
  {
    std::string js_module;
    std::string js_function;
  };
  DECLARE_JSON_TYPE_WITH_BASE(
    JsBundleEndpointMethod, ccf::endpoints::EndpointProperties)
  DECLARE_JSON_REQUIRED_FIELDS(JsBundleEndpointMethod, js_module, js_function)

  using JsBundleEndpoint = std::map<std::string, JsBundleEndpointMethod>;

  struct JsBundleMetadata
  {
    std::map<std::string, JsBundleEndpoint> endpoints;
  };
  DECLARE_JSON_TYPE(JsBundleMetadata)
  DECLARE_JSON_REQUIRED_FIELDS(JsBundleMetadata, endpoints)

  struct JsBundle
  {
    JsBundleMetadata metadata;
    std::vector<SetModule> modules;
  };
  DECLARE_JSON_TYPE(JsBundle)
  DECLARE_JSON_REQUIRED_FIELDS(JsBundle, metadata, modules)

  struct DeployJsApp
  {
    JsBundle bundle;
  };
  DECLARE_JSON_TYPE(DeployJsApp)
  DECLARE_JSON_REQUIRED_FIELDS(DeployJsApp, bundle)

  struct JsonWebKey
  {
    std::vector<std::string> x5c;
    std::string kid;
    std::string kty;

    bool operator==(const JsonWebKey& rhs) const
    {
      return x5c == rhs.x5c && kid == rhs.kid && kty == rhs.kty;
    }
  };
  DECLARE_JSON_TYPE(JsonWebKey)
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKey, x5c, kid, kty)

  struct JsonWebKeySet
  {
    std::vector<JsonWebKey> keys;

    bool operator!=(const JsonWebKeySet& rhs) const
    {
      return keys != rhs.keys;
    }
  };
  DECLARE_JSON_TYPE(JsonWebKeySet)
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeySet, keys)

  struct SetJwtIssuer : public ccf::JwtIssuerMetadata
  {
    std::string issuer;
    std::optional<JsonWebKeySet> jwks;
  };
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(
    SetJwtIssuer, ccf::JwtIssuerMetadata)
  DECLARE_JSON_REQUIRED_FIELDS(SetJwtIssuer, issuer)
  DECLARE_JSON_OPTIONAL_FIELDS(SetJwtIssuer, jwks)

  struct RemoveJwtIssuer
  {
    std::string issuer;
  };
  DECLARE_JSON_TYPE(RemoveJwtIssuer)
  DECLARE_JSON_REQUIRED_FIELDS(RemoveJwtIssuer, issuer)

  struct SetJwtPublicSigningKeys
  {
    std::string issuer;
    JsonWebKeySet jwks;
  };
  DECLARE_JSON_TYPE(SetJwtPublicSigningKeys)
  DECLARE_JSON_REQUIRED_FIELDS(SetJwtPublicSigningKeys, issuer, jwks)

  struct SetCaCert
  {
    std::string name;
    std::string cert;
  };
  DECLARE_JSON_TYPE(SetCaCert)
  DECLARE_JSON_REQUIRED_FIELDS(SetCaCert, name, cert)

  class MemberEndpoints : public CommonEndpointRegistry
  {
  private:
    Script get_script(kv::Tx& tx, std::string name)
    {
      const auto s = tx.ro(network.gov_scripts)->get(name);
      if (!s)
      {
        throw std::logic_error(
          fmt::format("Could not find gov script: {}", name));
      }
      return *s;
    }

    void set_js_scripts(kv::Tx& tx, std::map<std::string, std::string> scripts)
    {
      auto tx_scripts = tx.rw(network.app_scripts);

      // First, remove all existing handlers
      tx_scripts->foreach(
        [&tx_scripts](const std::string& name, const Script&) {
          tx_scripts->remove(name);
          return true;
        });

      for (auto& rs : scripts)
      {
        tx_scripts->put(rs.first, {rs.second});
      }
    }

    bool deploy_js_app(kv::Tx& tx, const JsBundle& bundle)
    {
      std::string module_prefix = "/";
      remove_modules(tx, module_prefix);
      set_modules(tx, module_prefix, bundle.modules);

      remove_endpoints(tx);

      auto endpoints =
        tx.rw<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      std::map<std::string, std::string> scripts;
      for (auto& [url, endpoint] : bundle.metadata.endpoints)
      {
        for (auto& [method, info] : endpoint)
        {
          const std::string& js_module = info.js_module;
          if (std::none_of(
                bundle.modules.cbegin(),
                bundle.modules.cend(),
                [&js_module](const SetModule& item) {
                  return item.name == js_module;
                }))
          {
            LOG_FAIL_FMT(
              "{} {}: module '{}' not found in bundle",
              method,
              url,
              info.js_module);
            return false;
          }

          auto verb = nlohmann::json(method).get<RESTVerb>();
          endpoints->put(ccf::endpoints::EndpointKey{url, verb}, info);

          // CCF currently requires each endpoint to have an inline JS module.
          std::string method_uppercase = method;
          nonstd::to_upper(method_uppercase);
          std::string url_without_leading_slash = url.substr(1);
          std::string key =
            fmt::format("{} {}", method_uppercase, url_without_leading_slash);
          std::string script = fmt::format(
            "import {{ {} as f }} from '.{}{}'; export default (r) => f(r);",
            info.js_function,
            module_prefix,
            info.js_module);
          scripts.emplace(key, script);
        }
      }

      set_js_scripts(tx, scripts);

      return true;
    }

    bool remove_js_app(kv::Tx& tx)
    {
      remove_modules(tx, "/");
      set_js_scripts(tx, {});

      return true;
    }

    void set_modules(
      kv::Tx& tx, std::string prefix, const std::vector<SetModule>& modules)
    {
      for (auto& set_module_ : modules)
      {
        std::string full_name = prefix + set_module_.name;
        if (!set_module(tx, full_name, set_module_.module))
        {
          throw std::logic_error(
            fmt::format("Unexpected error while setting module {}", full_name));
        }
      }
    }

    bool set_module(kv::Tx& tx, std::string name, Module module)
    {
      if (name.empty() || name[0] != '/')
      {
        LOG_FAIL_FMT("module names must start with /");
        return false;
      }
      auto tx_modules = tx.rw(network.modules);
      tx_modules->put(name, module);
      return true;
    }

    void remove_modules(kv::Tx& tx, std::string prefix)
    {
      auto tx_modules = tx.rw(network.modules);
      tx_modules->foreach(
        [&tx_modules, &prefix](const std::string& name, const Module&) {
          if (nonstd::starts_with(name, prefix))
          {
            if (!tx_modules->remove(name))
            {
              throw std::logic_error(
                fmt::format("Unexpected error while removing module {}", name));
            }
          }
          return true;
        });
    }

    bool remove_module(kv::Tx& tx, std::string name)
    {
      auto tx_modules = tx.rw(network.modules);
      return tx_modules->remove(name);
    }

    void remove_jwt_keys(kv::Tx& tx, std::string issuer)
    {
      auto keys = tx.rw(this->network.jwt_public_signing_keys);
      auto key_issuer = tx.rw(this->network.jwt_public_signing_key_issuer);

      key_issuer->foreach(
        [&issuer, &keys, &key_issuer](const auto& k, const auto& v) {
          if (v == issuer)
          {
            keys->remove(k);
            key_issuer->remove(k);
          }
          return true;
        });
    }

    bool set_jwt_public_signing_keys(
      kv::Tx& tx,
      const ProposalId& proposal_id,
      std::string issuer,
      const JwtIssuerMetadata& issuer_metadata,
      const JsonWebKeySet& jwks)
    {
      auto keys = tx.rw(this->network.jwt_public_signing_keys);
      auto key_issuer = tx.rw(this->network.jwt_public_signing_key_issuer);

      auto log_prefix = proposal_id == INVALID_PROPOSAL_ID ?
        "JWT key auto-refresh" :
        fmt::format("Proposal {}", proposal_id);

      // add keys
      if (jwks.keys.empty())
      {
        LOG_FAIL_FMT("{}: JWKS has no keys", log_prefix, proposal_id);
        return false;
      }
      std::map<std::string, std::vector<uint8_t>> new_keys;
      for (auto& jwk : jwks.keys)
      {
        if (keys->has(jwk.kid) && key_issuer->get(jwk.kid).value() != issuer)
        {
          LOG_FAIL_FMT(
            "{}: key id {} already added for different issuer",
            log_prefix,
            jwk.kid);
          return false;
        }
        if (jwk.x5c.empty())
        {
          LOG_FAIL_FMT("{}: JWKS is invalid (empty x5c)", log_prefix);
          return false;
        }

        auto& der_base64 = jwk.x5c[0];
        ccf::Cert der;
        try
        {
          der = tls::raw_from_b64(der_base64);
        }
        catch (const std::invalid_argument& e)
        {
          LOG_FAIL_FMT(
            "{}: Could not parse x5c of key id {}: {}",
            log_prefix,
            jwk.kid,
            e.what());
          return false;
        }

        std::map<std::string, std::vector<uint8_t>> claims;
        bool has_key_policy_sgx_claims =
          issuer_metadata.key_policy.has_value() &&
          issuer_metadata.key_policy.value().sgx_claims.has_value() &&
          !issuer_metadata.key_policy.value().sgx_claims.value().empty();
        if (
          issuer_metadata.key_filter == JwtIssuerKeyFilter::SGX ||
          has_key_policy_sgx_claims)
        {
          oe_verifier_initialize();
          oe_verify_attestation_certificate_with_evidence(
            der.data(),
            der.size(),
            oe_verify_attestation_certificate_with_evidence_cb,
            &claims);
        }

        if (
          issuer_metadata.key_filter == JwtIssuerKeyFilter::SGX &&
          claims.empty())
        {
          LOG_INFO_FMT(
            "{}: Skipping JWT signing key with kid {} (not OE "
            "attested)",
            log_prefix,
            jwk.kid);
          continue;
        }

        if (has_key_policy_sgx_claims)
        {
          for (auto& [claim_name, expected_claim_val_hex] :
               issuer_metadata.key_policy.value().sgx_claims.value())
          {
            if (claims.find(claim_name) == claims.end())
            {
              LOG_FAIL_FMT(
                "{}: JWKS kid {} is missing the {} SGX claim",
                log_prefix,
                jwk.kid,
                claim_name);
              return false;
            }
            auto& actual_claim_val = claims[claim_name];
            auto actual_claim_val_hex =
              fmt::format("{:02x}", fmt::join(actual_claim_val, ""));
            if (expected_claim_val_hex != actual_claim_val_hex)
            {
              LOG_FAIL_FMT(
                "{}: JWKS kid {} has a mismatching {} SGX claim",
                log_prefix,
                jwk.kid,
                claim_name);
              return false;
            }
          }
        }
        else
        {
          try
          {
            tls::check_is_cert(der);
          }
          catch (std::invalid_argument& exc)
          {
            LOG_FAIL_FMT(
              "{}: JWKS kid {} has an invalid X.509 certificate: {}",
              log_prefix,
              jwk.kid,
              exc.what());
            return false;
          }
        }
        LOG_INFO_FMT(
          "{}: Storing JWT signing key with kid {}", log_prefix, jwk.kid);
        new_keys.emplace(jwk.kid, der);
      }
      if (new_keys.empty())
      {
        LOG_FAIL_FMT("{}: no keys left after applying filter", log_prefix);
        return false;
      }

      remove_jwt_keys(tx, issuer);
      for (auto& [kid, der] : new_keys)
      {
        keys->put(kid, der);
        key_issuer->put(kid, issuer);
      }

      return true;
    }

    void remove_endpoints(kv::Tx& tx)
    {
      auto endpoints =
        tx.rw<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);
      endpoints->foreach([&endpoints](const auto& k, const auto&) {
        endpoints->remove(k);
        return true;
      });
    }

    bool add_new_code_id(
      kv::Tx& tx,
      const CodeDigest& new_code_id,
      CodeIDs& code_id_table,
      const ProposalId& proposal_id)
    {
      auto code_ids = tx.rw(code_id_table);
      auto existing_code_id = code_ids->get(new_code_id);
      if (existing_code_id)
      {
        LOG_FAIL_FMT(
          "Proposal {}: Code signature already exists with digest: {:02x}",
          proposal_id,
          fmt::join(new_code_id, ""));
        return false;
      }
      code_ids->put(new_code_id, CodeStatus::ALLOWED_TO_JOIN);
      return true;
    }

    bool retire_code_id(
      kv::Tx& tx,
      const CodeDigest& code_id,
      CodeIDs& code_id_table,
      const ProposalId& proposal_id)
    {
      auto code_ids = tx.rw(code_id_table);
      auto existing_code_id = code_ids->get(code_id);
      if (!existing_code_id)
      {
        LOG_FAIL_FMT(
          "Proposal {}: No such code id in table: {:02x}",
          proposal_id,
          fmt::join(code_id, ""));
        return false;
      }
      code_ids->remove(code_id);
      return true;
    }

    //! Table of functions that proposal scripts can propose to invoke
    const std::unordered_map<
      std::string,
      std::function<bool(const ProposalId&, kv::Tx&, const nlohmann::json&)>>
      hardcoded_funcs = {
        // set the js application script
        {"set_js_app",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_js_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));
           return true;
         }},
        // deploy the js application bundle
        {"deploy_js_app",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<DeployJsApp>();
           return deploy_js_app(tx, parsed.bundle);
         }},
        // undeploy/remove the js application
        {"remove_js_app",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json&) {
           return remove_js_app(tx);
         }},
        // add/update a module
        {"set_module",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<SetModule>();
           return set_module(tx, parsed.name, parsed.module);
         }},
        // remove a module
        {"remove_module",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto name = args.get<std::string>();
           return remove_module(tx, name);
         }},
        // add a new member
        {"new_member",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<MemberPubInfo>();
           GenesisGenerator g(this->network, tx);
           g.add_member(parsed);

           return true;
         }},
        // retire an existing member
        {"retire_member",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto member_id = args.get<MemberId>();

           GenesisGenerator g(this->network, tx);

           auto member_info = g.get_member_info(member_id);
           if (!member_info.has_value())
           {
             return false;
           }

           if (!g.retire_member(member_id))
           {
             return false;
           }

           if (
             member_info->status == MemberStatus::ACTIVE &&
             member_info->is_recovery())
           {
             // A retired member with recovery share should not have access to
             // the private ledger going forward so rekey ledger, issuing new
             // share to remaining active members
             if (!node.rekey_ledger(tx))
             {
               return false;
             }
           }

           return true;
         }},
        {"set_member_data",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto parsed = args.get<SetMemberData>();
           auto members = tx.rw(this->network.members);
           auto member_info = members->get(parsed.member_id);
           if (!member_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid member ID",
               proposal_id,
               parsed.member_id);
             return false;
           }

           member_info->member_data = parsed.member_data;
           members->put(parsed.member_id, member_info.value());
           return true;
         }},
        {"new_user",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto user_info = args.get<ccf::UserInfo>();

           GenesisGenerator g(this->network, tx);
           g.add_user(user_info);

           return true;
         }},
        {"remove_user",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const UserId user_id = args;

           GenesisGenerator g(this->network, tx);
           auto r = g.remove_user(user_id);
           if (!r)
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid user ID", proposal_id, user_id);
           }

           return r;
         }},
        {"set_user_data",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto parsed = args.get<SetUserData>();
           auto users = tx.rw(this->network.users);
           auto user_info = users->get(parsed.user_id);
           if (!user_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid user ID",
               proposal_id,
               parsed.user_id);
             return false;
           }

           user_info->user_data = parsed.user_data;
           users->put(parsed.user_id, user_info.value());
           return true;
         }},
        {"set_ca_cert",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto parsed = args.get<SetCaCert>();
           auto ca_certs = tx.rw(this->network.ca_certs);
           std::vector<uint8_t> cert_der;
           try
           {
             cert_der = tls::cert_pem_to_der(parsed.cert);
           }
           catch (const std::invalid_argument& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: certificate is not a valid X.509 certificate in "
               "PEM format: {}",
               proposal_id,
               e.what());
             return false;
           }
           ca_certs->put(parsed.name, cert_der);
           return true;
         }},
        {"remove_ca_cert",
         [this](const ProposalId&, kv::Tx& tx, const nlohmann::json& args) {
           const auto cert_name = args.get<std::string>();
           auto ca_certs = tx.rw(this->network.ca_certs);
           ca_certs->remove(cert_name);
           return true;
         }},
        {"set_jwt_issuer",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto parsed = args.get<SetJwtIssuer>();
           auto issuers = tx.rw(this->network.jwt_issuers);
           auto ca_certs = tx.ro(this->network.ca_certs);

           if (parsed.auto_refresh)
           {
             if (!parsed.ca_cert_name.has_value())
             {
               LOG_FAIL_FMT(
                 "Proposal {}: ca_cert_name is missing but required if "
                 "auto_refresh is true",
                 proposal_id);
               return false;
             }
             if (!ca_certs->has(parsed.ca_cert_name.value()))
             {
               LOG_FAIL_FMT(
                 "Proposal {}: No CA cert found with name '{}'",
                 proposal_id,
                 parsed.ca_cert_name.value());
               return false;
             }
             http::URL issuer_url;
             try
             {
               issuer_url = http::parse_url_full(parsed.issuer);
             }
             catch (const std::runtime_error&)
             {
               LOG_FAIL_FMT(
                 "Proposal {}: issuer must be a URL if auto_refresh is true",
                 proposal_id);
               return false;
             }
             if (issuer_url.scheme != "https")
             {
               LOG_FAIL_FMT(
                 "Proposal {}: issuer must be a URL starting with https:// if "
                 "auto_refresh is true",
                 proposal_id);
               return false;
             }
             if (!issuer_url.query.empty() || !issuer_url.fragment.empty())
             {
               LOG_FAIL_FMT(
                 "Proposal {}: issuer must be a URL without query/fragment if "
                 "auto_refresh is true",
                 proposal_id);
               return false;
             }
           }

           bool success = true;
           if (parsed.jwks.has_value())
           {
             success = set_jwt_public_signing_keys(
               tx, proposal_id, parsed.issuer, parsed, parsed.jwks.value());
           }
           if (success)
           {
             issuers->put(parsed.issuer, parsed);
           }

           return success;
         }},
        {"remove_jwt_issuer",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto parsed = args.get<RemoveJwtIssuer>();
           const auto issuer = parsed.issuer;
           auto issuers = tx.rw(this->network.jwt_issuers);

           if (!issuers->remove(issuer))
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid issuer", proposal_id, issuer);
             return false;
           }

           remove_jwt_keys(tx, issuer);

           return true;
         }},
        {"set_jwt_public_signing_keys",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto parsed = args.get<SetJwtPublicSigningKeys>();

           auto issuers = tx.rw(this->network.jwt_issuers);
           auto issuer_metadata_ = issuers->get(parsed.issuer);
           if (!issuer_metadata_.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid issuer",
               proposal_id,
               parsed.issuer);
             return false;
           }
           auto& issuer_metadata = issuer_metadata_.value();

           return set_jwt_public_signing_keys(
             tx, proposal_id, parsed.issuer, issuer_metadata, parsed.jwks);
         }},
        // accept a node
        {"trust_node",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto node_id = args.get<NodeId>();
           try
           {
             GenesisGenerator g(network, tx);
             g.trust_node(
               node_id, network.ledger_secrets->get_latest(tx).first);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT("Proposal {} failed: {}", proposal_id, e.what());
             return false;
           }
           return true;
         }},
        // retire a node
        {"retire_node",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto id = args.get<NodeId>();
           auto nodes = tx.rw(this->network.nodes);
           auto node_info = nodes->get(id);
           if (!node_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node {} does not exist", proposal_id, id);
             return false;
           }
           if (node_info->status == NodeStatus::RETIRED)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node {} is already retired", proposal_id, id);
             return false;
           }
           node_info->status = NodeStatus::RETIRED;
           nodes->put(id, node_info.value());
           LOG_INFO_FMT("Node {} is now {}", id, node_info->status);
           return true;
         }},
        // accept new node code ID
        {"new_node_code",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           return this->add_new_code_id(
             tx,
             args.get<CodeDigest>(),
             this->network.node_code_ids,
             proposal_id);
         }},
        // retire node code ID
        {"retire_node_code",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           return this->retire_code_id(
             tx,
             args.get<CodeDigest>(),
             this->network.node_code_ids,
             proposal_id);
         }},
        {"accept_recovery",
         [this](
           const ProposalId& proposal_id, kv::Tx& tx, const nlohmann::json&) {
           if (node.is_part_of_public_network())
           {
             const auto accept_recovery = node.accept_recovery(tx);
             if (!accept_recovery)
             {
               LOG_FAIL_FMT("Proposal {}: Accept recovery failed", proposal_id);
             }
             return accept_recovery;
           }
           else
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node is not part of public network", proposal_id);
             return false;
           }
         }},
        {"open_network",
         [this](
           const ProposalId& proposal_id, kv::Tx& tx, const nlohmann::json&) {
           // On network open, the service checks that a sufficient number of
           // recovery members have become active. If so, recovery shares are
           // allocated to each recovery member
           try
           {
             share_manager.issue_recovery_shares(tx);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Issuing recovery shares failed when opening the "
               "network: {}",
               proposal_id,
               e.what());
             return false;
           }

           GenesisGenerator g(this->network, tx);
           const auto network_opened = g.open_service();
           if (!network_opened)
           {
             LOG_FAIL_FMT("Proposal {}: Open network failed", proposal_id);
           }
           else
           {
             node.open_user_frontend();
           }
           return network_opened;
         }},
        {"rekey_ledger",
         [this](
           const ProposalId& proposal_id, kv::Tx& tx, const nlohmann::json&) {
           const auto ledger_rekeyed = node.rekey_ledger(tx);
           if (!ledger_rekeyed)
           {
             LOG_FAIL_FMT("Proposal {}: Ledger rekey failed", proposal_id);
           }
           return ledger_rekeyed;
         }},
        {"update_recovery_shares",
         [this](
           const ProposalId& proposal_id, kv::Tx& tx, const nlohmann::json&) {
           try
           {
             share_manager.shuffle_recovery_shares(tx);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Updating recovery shares failed: {}",
               proposal_id,
               e.what());
             return false;
           }
           return true;
         }},
        {"set_recovery_threshold",
         [this](
           const ProposalId& proposal_id,
           kv::Tx& tx,
           const nlohmann::json& args) {
           const auto new_recovery_threshold = args.get<size_t>();

           GenesisGenerator g(this->network, tx);

           if (new_recovery_threshold == g.get_recovery_threshold())
           {
             // If the recovery threshold is the same as before, return with no
             // effect
             return true;
           }

           if (!g.set_recovery_threshold(new_recovery_threshold))
           {
             return false;
           }

           try
           {
             share_manager.shuffle_recovery_shares(tx);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Setting recovery threshold failed: {}",
               proposal_id,
               e.what());
             return false;
           }
           return true;
         }},
      };

    ProposalInfo complete_proposal(
      kv::Tx& tx, const ProposalId& proposal_id, Proposal& proposal)
    {
      if (proposal.state != ProposalState::OPEN)
      {
        throw std::logic_error(fmt::format(
          "Cannot complete non-open proposal - current state is {}",
          proposal.state));
      }

      auto proposals = tx.rw(this->network.proposals);

      // run proposal script
      const auto proposed_calls = tsr.run<nlohmann::json>(
        tx,
        {proposal.script,
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         get_script(tx, GovScriptIds::ENV_PROPOSAL)},
        // vvv arguments to script vvv
        proposal.parameter);

      nlohmann::json votes = nlohmann::json::object();
      // Collect all member votes
      for (const auto& vote : proposal.votes)
      {
        // valid voter
        if (!check_member_active(tx, vote.first))
        {
          continue;
        }

        // does the voter agree?
        votes[std::to_string(vote.first)] = tsr.run<bool>(
          tx,
          {vote.second,
           {}, // can't write
           WlIds::MEMBER_CAN_READ,
           {}},
          proposed_calls);
      }

      const auto pass = tsr.run<int>(
        tx,
        {get_script(tx, GovScriptIds::PASS),
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         {}},
        // vvv arguments to script vvv
        proposed_calls,
        votes,
        proposal.proposer);

      switch (pass)
      {
        case CompletionResult::PASSED:
        {
          // vote passed, go on to update the state
          break;
        }
        case CompletionResult::PENDING:
        {
          // vote is pending, return false but do not update state
          return get_proposal_info(proposal_id, proposal);
        }
        case CompletionResult::REJECTED:
        {
          // vote unsuccessful, update the proposal's state
          proposal.state = ProposalState::REJECTED;
          proposals->put(proposal_id, proposal);
          return get_proposal_info(proposal_id, proposal);
        }
        default:
        {
          throw std::logic_error(fmt::format(
            "Invalid completion result ({}) for proposal {}",
            pass,
            proposal_id));
        }
      };

      // execute proposed calls
      ProposedCalls pc = proposed_calls;
      for (const auto& call : pc)
      {
        // proposing a hardcoded C++ function?
        const auto f = hardcoded_funcs.find(call.func);
        if (f != hardcoded_funcs.end())
        {
          if (!f->second(proposal_id, tx, call.args))
          {
            proposal.state = ProposalState::FAILED;
            proposals->put(proposal_id, proposal);
            return get_proposal_info(proposal_id, proposal);
          }
          continue;
        }

        // proposing a script function?
        const auto s = tx.rw(network.gov_scripts)->get(call.func);
        if (!s.has_value())
        {
          continue;
        }
        tsr.run<void>(
          tx,
          {s.value(),
           WlIds::MEMBER_CAN_PROPOSE, // can write!
           {},
           {}},
          call.args);
      }

      // if the vote was successful, update the proposal's state
      proposal.state = ProposalState::ACCEPTED;
      proposals->put(proposal_id, proposal);

      return get_proposal_info(proposal_id, proposal);
    }

    bool check_member_active(kv::ReadOnlyTx& tx, MemberId id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_accepted(kv::ReadOnlyTx& tx, MemberId id)
    {
      return check_member_status(
        tx, id, {MemberStatus::ACTIVE, MemberStatus::ACCEPTED});
    }

    bool check_member_status(
      kv::ReadOnlyTx& tx,
      MemberId id,
      std::initializer_list<MemberStatus> allowed)
    {
      auto member = tx.ro(this->network.members)->get(id);
      if (!member)
      {
        return false;
      }
      for (const auto s : allowed)
      {
        if (member->status == s)
        {
          return true;
        }
      }
      return false;
    }

    void record_voting_history(
      kv::Tx& tx, MemberId caller_id, const SignedReq& signed_request)
    {
      auto governance_history = tx.rw(network.governance_history);
      governance_history->put(caller_id, {signed_request});
    }

    static ProposalInfo get_proposal_info(
      const ProposalId& proposal_id, const Proposal& proposal)
    {
      return ProposalInfo{proposal_id, proposal.proposer, proposal.state};
    }

    bool get_proposal_id_from_path(
      const enclave::PathParams& params,
      ProposalId& proposal_id,
      std::string& error)
    {
      return get_path_param(params, "proposal_id", proposal_id, error);
    }

    bool get_member_id_from_path(
      const enclave::PathParams& params,
      MemberId& member_id,
      std::string& error)
    {
      return get_path_param(params, "member_id", member_id, error);
    }

    NetworkState& network;
    ShareManager& share_manager;
    const MemberTsr tsr;

  public:
    MemberEndpoints(
      NetworkState& network,
      AbstractNodeState& node_state,
      ShareManager& share_manager) :
      CommonEndpointRegistry(
        get_actor_prefix(ActorsType::members),
        node_state,
        Tables::MEMBER_CERT_DERS),
      network(network),
      share_manager(share_manager),
      tsr(network)
    {
      openapi_info.title = "CCF Governance API";
      openapi_info.description =
        "This API is used to submit and query proposals which affect CCF's "
        "public governance tables.";
    }

    static MemberId get_caller_member_id(CommandEndpointContext& ctx)
    {
      if (
        const auto* sig_ident =
          ctx.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
      {
        return sig_ident->member_id;
      }
      else if (
        const auto* cert_ident =
          ctx.try_get_caller<ccf::MemberCertAuthnIdentity>())
      {
        return cert_ident->member_id;
      }

      LOG_FATAL_FMT("Request was not authenticated with a member auth policy");
      return INVALID_ID;
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      const AuthnPolicies member_sig_only = {member_signature_auth_policy};

      const AuthnPolicies member_cert_or_sig = {member_cert_auth_policy,
                                                member_signature_auth_policy};

      auto read = [this](EndpointContext& ctx, nlohmann::json&& params) {
        const auto member_id = get_caller_member_id(ctx);
        if (!check_member_status(
              ctx.tx,
              member_id,
              {MemberStatus::ACTIVE, MemberStatus::ACCEPTED}))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active or accepted.");
        }

        const auto in = params.get<KVRead::In>();

        const ccf::Script read_script(R"xxx(
        local tables, table_name, key = ...
        return tables[table_name]:get(key) or {}
        )xxx");

        auto value = tsr.run<nlohmann::json>(
          ctx.tx,
          {read_script, {}, WlIds::MEMBER_CAN_READ, {}},
          in.table,
          in.key);
        if (value.empty())
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::KeyNotFound,
            fmt::format(
              "Key {} does not exist in table {}.", in.key.dump(), in.table));
        }

        return make_success(value);
      };
      make_endpoint("read", HTTP_POST, json_adapter(read), member_cert_or_sig)
        // This can be executed locally, but can't currently take ReadOnlyTx due
        // to restrictions in our lua wrappers
        .set_forwarding_required(ForwardingRequired::Sometimes)
        .set_auto_schema<KVRead>()
        .install();

      auto query = [this](EndpointContext& ctx, nlohmann::json&& params) {
        const auto member_id = get_caller_member_id(ctx);
        if (!check_member_accepted(ctx.tx, member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not accepted.");
        }

        const auto script = params.get<ccf::Script>();
        return make_success(tsr.run<nlohmann::json>(
          ctx.tx, {script, {}, WlIds::MEMBER_CAN_READ, {}}));
      };
      make_endpoint("query", HTTP_POST, json_adapter(query), member_cert_or_sig)
        // This can be executed locally, but can't currently take ReadOnlyTx due
        // to restrictions in our lua wrappers
        .set_forwarding_required(ForwardingRequired::Sometimes)
        .set_auto_schema<Script, nlohmann::json>()
        .install();

      auto propose = [this](EndpointContext& ctx, nlohmann::json&& params) {
        const auto& caller_identity =
          ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();
        if (!check_member_active(ctx.tx, caller_identity.member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
        }

        const auto in = params.get<Propose::In>();

        if (!consensus)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No consensus available.");
        }

        std::string proposal_id;

        if (consensus->type() == ConsensusType::CFT)
        {
          auto root_at_read = ctx.tx.get_root_at_read_version();
          if (!root_at_read.has_value())
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Proposal failed to bind to state.");
          }

          // caller_identity.request_digest is set when getting the
          // MemberSignatureAuthnIdentity identity. The proposal id is a digest
          // of the root of the state tree at the read version and the request
          // digest.
          std::vector<uint8_t> acc(
            root_at_read.value().h.begin(), root_at_read.value().h.end());
          acc.insert(
            acc.end(),
            caller_identity.request_digest.begin(),
            caller_identity.request_digest.end());
          const crypto::Sha256Hash proposal_digest(acc);
          proposal_id = proposal_digest.hex_str();
        }
        else
        {
          proposal_id = fmt::format(
            "{:02x}", fmt::join(caller_identity.request_digest, ""));
        }

        Proposal proposal(in.script, in.parameter, caller_identity.member_id);
        auto proposals = ctx.tx.rw(this->network.proposals);
        // Introduce a read dependency, so that if identical proposal creations
        // are in-flight and reading at the same version, all except the first
        // conflict and are re-executed. If we ever produce a proposal ID which
        // already exists, we must have a hash collision.
        if (proposals->has(proposal_id))
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Proposal ID collision.");
        }
        proposals->put(proposal_id, proposal);

        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

        return make_success(
          Propose::Out{complete_proposal(ctx.tx, proposal_id, proposal)});
      };
      make_endpoint(
        "proposals", HTTP_POST, json_adapter(propose), member_sig_only)
        .set_auto_schema<Propose>()
        .install();

      auto get_proposal =
        [this](ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          const auto member_id = get_caller_member_id(ctx);
          if (!check_member_active(ctx.tx, member_id))
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is not active.");
          }

          ProposalId proposal_id;
          std::string error;
          if (!get_proposal_id_from_path(
                ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
          }

          auto proposals = ctx.tx.ro(this->network.proposals);
          auto proposal = proposals->get(proposal_id);

          if (!proposal)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
          }

          return make_success(proposal.value());
        };
      make_read_only_endpoint(
        "proposals/{proposal_id}",
        HTTP_GET,
        json_read_only_adapter(get_proposal),
        member_cert_or_sig)
        .set_auto_schema<void, Proposal>()
        .install();

      auto withdraw = [this](EndpointContext& ctx, nlohmann::json&&) {
        const auto& caller_identity =
          ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();
        if (!check_member_active(ctx.tx, caller_identity.member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto proposals = ctx.tx.rw(this->network.proposals);
        auto proposal = proposals->get(proposal_id);

        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
        }

        if (proposal->proposer != caller_identity.member_id)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "Proposal {} can only be withdrawn by proposer {}, not caller "
              "{}.",
              proposal_id,
              proposal->proposer,
              caller_identity.member_id));
        }

        if (proposal->state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotOpen,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can be "
              "withdrawn.",
              proposal_id,
              proposal->state,
              ProposalState::OPEN));
        }

        proposal->state = ProposalState::WITHDRAWN;
        proposals->put(proposal_id, proposal.value());
        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

        return make_success(get_proposal_info(proposal_id, proposal.value()));
      };
      make_endpoint(
        "proposals/{proposal_id}/withdraw",
        HTTP_POST,
        json_adapter(withdraw),
        member_sig_only)
        .set_auto_schema<void, ProposalInfo>()
        .install();

      auto vote = [this](EndpointContext& ctx, nlohmann::json&& params) {
        const auto& caller_identity =
          ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();

        if (!check_member_active(ctx.tx, caller_identity.member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto proposals = ctx.tx.rw(this->network.proposals);
        auto proposal = proposals->get(proposal_id);
        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
        }

        if (proposal->state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotOpen,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can "
              "receive votes.",
              proposal_id,
              proposal->state,
              ProposalState::OPEN));
        }

        const auto vote = params.get<Vote>();
        if (
          proposal->votes.find(caller_identity.member_id) !=
          proposal->votes.end())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::VoteAlreadyExists,
            "Vote already submitted.");
        }
        proposal->votes[caller_identity.member_id] = vote.ballot;
        proposals->put(proposal_id, proposal.value());

        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

        return make_success(
          complete_proposal(ctx.tx, proposal_id, proposal.value()));
      };
      make_endpoint(
        "proposals/{proposal_id}/votes",
        HTTP_POST,
        json_adapter(vote),
        member_sig_only)
        .set_auto_schema<Vote, ProposalInfo>()
        .install();

      auto get_vote = [this](ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
        const auto caller_member_id = get_caller_member_id(ctx);
        if (!check_member_active(ctx.tx, caller_member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
        }

        std::string error;
        ProposalId proposal_id;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        MemberId vote_member_id;
        if (!get_member_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), vote_member_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto proposals = ctx.tx.ro(this->network.proposals);
        auto proposal = proposals->get(proposal_id);
        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
        }

        const auto vote_it = proposal->votes.find(vote_member_id);
        if (vote_it == proposal->votes.end())
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::VoteNotFound,
            fmt::format(
              "Member {} has not voted for proposal {}.",
              vote_member_id,
              proposal_id));
        }

        return make_success(vote_it->second);
      };
      make_read_only_endpoint(
        "proposals/{proposal_id}/votes/{member_id}",
        HTTP_GET,
        json_read_only_adapter(get_vote),
        member_cert_or_sig)
        .set_auto_schema<void, Vote>()
        .install();

      //! A member acknowledges state
      auto ack = [this](EndpointContext& ctx, nlohmann::json&& params) {
        const auto& caller_identity =
          ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();
        const auto& signed_request = caller_identity.signed_request;

        auto mas = ctx.tx.rw(this->network.member_acks);
        auto sig = ctx.tx.rw(this->network.signatures);
        auto members = ctx.tx.rw(this->network.members);

        const auto ma = mas->get(caller_identity.member_id);
        if (!ma)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "No ACK record exists for caller {}.",
              caller_identity.member_id));
        }

        const auto digest = params.get<StateDigest>();
        if (ma->state_digest != digest.state_digest)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::StateDigestMismatch,
            "Submitted state digest is not valid.");
        }

        const auto s = sig->get(0);
        if (!s)
        {
          mas->put(caller_identity.member_id, MemberAck({}, signed_request));
        }
        else
        {
          mas->put(
            caller_identity.member_id, MemberAck(s->root, signed_request));
        }

        // update member status to ACTIVE
        GenesisGenerator g(this->network, ctx.tx);
        try
        {
          g.activate_member(caller_identity.member_id);
        }
        catch (const std::logic_error& e)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format("Error activating new member: {}", e.what()));
        }

        auto service_status = g.get_service_status();
        if (!service_status.has_value())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No service currently available.");
        }

        auto member_info = members->get(caller_identity.member_id);
        if (
          service_status.value() == ServiceStatus::OPEN &&
          member_info->is_recovery())
        {
          // When the service is OPEN and the new active member is a recovery
          // member, all recovery members are allocated new recovery shares
          try
          {
            share_manager.shuffle_recovery_shares(ctx.tx);
          }
          catch (const std::logic_error& e)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format("Error issuing new recovery shares: {}", e.what()));
          }
        }
        return make_success();
      };
      make_endpoint("ack", HTTP_POST, json_adapter(ack), member_sig_only)
        .set_auto_schema<StateDigest, void>()
        .install();

      //! A member asks for a fresher state digest
      auto update_state_digest =
        [this](EndpointContext& ctx, nlohmann::json&&) {
          const auto member_id = get_caller_member_id(ctx);
          auto mas = ctx.tx.rw(this->network.member_acks);
          auto sig = ctx.tx.rw(this->network.signatures);
          auto ma = mas->get(member_id);
          if (!ma)
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              fmt::format("No ACK record exists for caller {}.", member_id));
          }

          auto s = sig->get(0);
          if (s)
          {
            ma->state_digest = s->root.hex_str();
            mas->put(member_id, ma.value());
          }
          nlohmann::json j;
          j["state_digest"] = ma->state_digest;

          return make_success(j);
        };
      make_endpoint(
        "ack/update_state_digest",
        HTTP_POST,
        json_adapter(update_state_digest),
        member_cert_or_sig)
        .set_auto_schema<void, StateDigest>()
        .install();

      auto get_encrypted_recovery_share = [this](
                                            EndpointContext& ctx,
                                            nlohmann::json&&) {
        const auto member_id = get_caller_member_id(ctx);
        if (!check_member_active(ctx.tx, member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Only active members are given recovery shares.");
        }

        auto encrypted_share =
          share_manager.get_encrypted_share(ctx.tx, member_id);

        if (!encrypted_share.has_value())
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format("Recovery share not found for member {}.", member_id));
        }

        return make_success(
          GetRecoveryShare::Out{tls::b64_from_raw(encrypted_share.value())});
      };
      make_endpoint(
        "recovery_share",
        HTTP_GET,
        json_adapter(get_encrypted_recovery_share),
        member_cert_or_sig)
        .set_auto_schema<GetRecoveryShare>()
        .install();

      auto submit_recovery_share = [this](
                                     EndpointContext& ctx,
                                     nlohmann::json&& params) {
        // Only active members can submit their shares for recovery
        const auto member_id = get_caller_member_id(ctx);
        if (!check_member_active(ctx.tx, member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::AuthorizationFailed,
            "Member is not active");
        }

        GenesisGenerator g(this->network, ctx.tx);
        if (
          g.get_service_status() != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::ServiceNotWaitingForRecoveryShares,
            "Service is not waiting for recovery shares");
        }

        if (node.is_reading_private_ledger())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::NodeAlreadyRecovering,
            "Node is already recovering private ledger");
        }

        const auto in = params.get<SubmitRecoveryShare::In>();
        auto raw_recovery_share = tls::raw_from_b64(in.share);

        size_t submitted_shares_count = 0;
        try
        {
          submitted_shares_count = share_manager.submit_recovery_share(
            ctx.tx, member_id, raw_recovery_share);
        }
        catch (const std::exception& e)
        {
          constexpr auto error_msg = "Error submitting recovery shares";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
        }

        if (submitted_shares_count < g.get_recovery_threshold())
        {
          // The number of shares required to re-assemble the secret has not yet
          // been reached
          return make_success(SubmitRecoveryShare::Out{fmt::format(
            "{}/{} recovery shares successfully submitted.",
            submitted_shares_count,
            g.get_recovery_threshold())});
        }

        LOG_DEBUG_FMT(
          "Reached recovery threshold {}", g.get_recovery_threshold());

        try
        {
          node.initiate_private_recovery(ctx.tx);
        }
        catch (const std::exception& e)
        {
          // Clear the submitted shares if combination fails so that members can
          // start over.
          constexpr auto error_msg = "Failed to initiate private recovery";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          share_manager.clear_submitted_recovery_shares(ctx.tx);
          ctx.rpc_ctx->set_apply_writes(true);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
        }

        share_manager.clear_submitted_recovery_shares(ctx.tx);

        return make_success(SubmitRecoveryShare::Out{fmt::format(
          "{}/{} recovery shares successfully submitted. End of recovery "
          "procedure initiated.",
          submitted_shares_count,
          g.get_recovery_threshold())});
      };
      make_endpoint(
        "recovery_share",
        HTTP_POST,
        json_adapter(submit_recovery_share),
        member_cert_or_sig)
        .set_auto_schema<SubmitRecoveryShare>()
        .install();

      auto create = [this](kv::Tx& tx, nlohmann::json&& params) {
        LOG_DEBUG_FMT("Processing create RPC");
        const auto in = params.get<CreateNetworkNodeToNode::In>();

        GenesisGenerator g(this->network, tx);

        // This endpoint can only be called once, directly from the starting
        // node for the genesis transaction to initialise the service
        if (g.is_service_created())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Service is already created.");
        }

        g.init_values();
        g.create_service(in.network_cert);

        for (const auto& info : in.members_info)
        {
          g.add_member(info);
        }

        // Note that it is acceptable to start a network without any member
        // having a recovery share. The service will check that at least one
        // recovery member is added before the service is opened.
        g.init_configuration(in.configuration);

        size_t self = g.add_node({in.node_info_network,
                                  in.node_cert,
                                  {in.quote_info},
                                  in.public_encryption_key,
                                  NodeStatus::TRUSTED});

        LOG_INFO_FMT("Create node id: {}", self);
        if (self != 0)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Starting node ID is not 0.");
        }

#ifdef GET_QUOTE
        CodeDigest node_code_id;
        std::copy_n(
          std::begin(in.code_digest),
          CODE_DIGEST_BYTES,
          std::begin(node_code_id));
        g.trust_node_code_id(node_code_id);
#endif

        for (const auto& wl : default_whitelists)
        {
          g.set_whitelist(wl.first, wl.second);
        }

        g.set_gov_scripts(
          lua::Interpreter().invoke<nlohmann::json>(in.gov_script));

        LOG_INFO_FMT("Created service");
        return make_success(true);
      };
      make_endpoint("create", HTTP_POST, json_adapter(create), no_auth_required)
        .set_openapi_hidden(true)
        .install();

      // Only called from node. See node_state.h.
      auto refresh_jwt_keys = [this](
                                EndpointContext& ctx, nlohmann::json&& body) {
        // All errors are server errors since the client is the server.

        if (!consensus)
        {
          LOG_FAIL_FMT("JWT key auto-refresh: no consensus available");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No consensus available.");
        }

        auto primary_id = consensus->primary();
        auto nodes = ctx.tx.ro(this->network.nodes);
        auto info = nodes->get(primary_id);
        if (!info.has_value())
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: could not find node info of primary");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Could not find node info of primary.");
        }

        auto primary_cert_pem = info.value().cert;
        auto cert_der = ctx.rpc_ctx->session->caller_cert;
        auto caller_cert_pem = tls::cert_der_to_pem(cert_der);
        if (caller_cert_pem != primary_cert_pem)
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: request does not originate from primary");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Request does not originate from primary.");
        }

        SetJwtPublicSigningKeys parsed;
        try
        {
          parsed = body.get<SetJwtPublicSigningKeys>();
        }
        catch (const JsonParseError& e)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Unable to parse body.");
        }

        auto issuers = ctx.tx.rw(this->network.jwt_issuers);
        auto issuer_metadata_ = issuers->get(parsed.issuer);
        if (!issuer_metadata_.has_value())
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: {} is not a valid issuer", parsed.issuer);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("{} is not a valid issuer.", parsed.issuer));
        }
        auto& issuer_metadata = issuer_metadata_.value();

        if (!issuer_metadata.auto_refresh)
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: {} does not have auto_refresh enabled",
            parsed.issuer);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "{} does not have auto_refresh enabled.", parsed.issuer));
        }

        if (!set_jwt_public_signing_keys(
              ctx.tx,
              INVALID_PROPOSAL_ID,
              parsed.issuer,
              issuer_metadata,
              parsed.jwks))
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: error while storing signing keys for issuer "
            "{}",
            parsed.issuer);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Error while storing signing keys for issuer {}.",
              parsed.issuer));
        }

        return make_success(true);
      };
      make_endpoint(
        "jwt_keys/refresh",
        HTTP_POST,
        json_adapter(refresh_jwt_keys),
        {std::make_shared<NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .install();
    }
  };

  class MemberRpcFrontend : public RpcFrontend
  {
  protected:
    MemberEndpoints member_endpoints;
    Members* members;

  public:
    MemberRpcFrontend(
      NetworkState& network,
      AbstractNodeState& node,
      ShareManager& share_manager) :
      RpcFrontend(*network.tables, member_endpoints),
      member_endpoints(network, node, share_manager),
      members(&network.members)
    {}
  };
} // namespace ccf
