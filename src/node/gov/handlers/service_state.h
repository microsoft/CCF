// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/ds/json.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  namespace api
  {
    struct ServiceConfiguration
    {
      size_t recovery_threshold = 0;
      size_t maximum_node_certificate_validity_days = 0;
      size_t maximum_service_certificate_validity_days = 0;
      size_t recent_cose_proposals_window_size = 0;

      bool operator==(const ServiceConfiguration&) const = default;
    };
    DECLARE_JSON_TYPE(ServiceConfiguration);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      ServiceConfiguration,
      recovery_threshold,
      "recoveryThreshold",
      maximum_node_certificate_validity_days,
      "maximumNodeCertificateValidityDays",
      maximum_service_certificate_validity_days,
      "maximumServiceCertificateValidityDays",
      recent_cose_proposals_window_size,
      "recentCoseProposalsWindowSize");

    struct ServiceInfo
    {
      ccf::ServiceStatus status = ccf::ServiceStatus::OPENING;
      std::string certificate;
      size_t recovery_count = 0;
      std::optional<ccf::TxID> creation_transaction_id = std::nullopt;
      std::optional<ccf::TxID> previous_service_creation_transaction_id =
        std::nullopt;
      nlohmann::json service_data = nullptr;
      std::optional<ServiceConfiguration> configuration = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceInfo);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      ServiceInfo,
      status,
      "status",
      certificate,
      "certificate",
      recovery_count,
      "recoveryCount",
      service_data,
      "serviceData");
    DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
      ServiceInfo,
      creation_transaction_id,
      "creationTransactionId",
      previous_service_creation_transaction_id,
      "previousServiceCreationTransactionId",
      configuration,
      "configuration");

    struct JavascriptApp
    {
      nlohmann::json endpoints = nlohmann::json::object();
    };
    DECLARE_JSON_TYPE(JavascriptApp);
    DECLARE_JSON_REQUIRED_FIELDS(JavascriptApp, endpoints);

    enum class JavascriptAppCase : uint8_t
    {
      Original
    };
    DECLARE_JSON_ENUM(
      JavascriptAppCase, {{JavascriptAppCase::Original, "original"}});

    struct JavascriptModule
    {
      std::string module_name;
    };
    DECLARE_JSON_TYPE(JavascriptModule);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      JavascriptModule, module_name, "moduleName");

    struct JavascriptModules
    {
      std::vector<JavascriptModule> value;
    };
    DECLARE_JSON_TYPE(JavascriptModules);
    DECLARE_JSON_REQUIRED_FIELDS(JavascriptModules, value);

    struct BasicJoinPolicy
    {
      std::vector<std::string> measurements;
    };
    DECLARE_JSON_TYPE(BasicJoinPolicy);
    DECLARE_JSON_REQUIRED_FIELDS(BasicJoinPolicy, measurements);

    struct VirtualJoinPolicy
    {
      std::vector<std::string> measurements;
      std::vector<std::string> host_data;
    };
    DECLARE_JSON_TYPE(VirtualJoinPolicy);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      VirtualJoinPolicy, measurements, "measurements", host_data, "hostData");

    struct SnpJoinPolicy
    {
      std::vector<std::string> measurements;
      std::map<std::string, std::string> host_data;
      std::map<ccf::DID, ccf::FeedToEndorsementsDataMap> uvm_endorsements;
      std::map<std::string, pal::snp::TcbVersionPolicy> tcb_versions;
    };
    DECLARE_JSON_TYPE(SnpJoinPolicy);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      SnpJoinPolicy,
      measurements,
      "measurements",
      host_data,
      "hostData",
      uvm_endorsements,
      "uvmEndorsements",
      tcb_versions,
      "tcbVersions");

    struct JoinPolicy
    {
      BasicJoinPolicy sgx;
      VirtualJoinPolicy virtual_;
      SnpJoinPolicy snp;
    };
    DECLARE_JSON_TYPE(JoinPolicy);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      JoinPolicy, sgx, "sgx", virtual_, "virtual", snp, "snp");

    struct JwtIssuer
    {
      bool auto_refresh = false;
      std::optional<std::string> ca_cert_bundle_name = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JwtIssuer);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      JwtIssuer, auto_refresh, "autoRefresh");
    DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
      JwtIssuer, ca_cert_bundle_name, "caCertBundleName");

    struct Jwk
    {
      std::string public_key;
      std::string issuer;
      nlohmann::json constraint = nullptr;
    };
    DECLARE_JSON_TYPE(Jwk);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      Jwk, public_key, "publicKey", issuer, "issuer", constraint, "constraint");

    struct JwkInfo
    {
      std::map<ccf::JwtIssuer, JwtIssuer> issuers;
      std::map<ccf::JwtKeyId, std::vector<Jwk>> keys;
      std::map<std::string, std::string> ca_cert_bundles;
    };
    DECLARE_JSON_TYPE(JwkInfo);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      JwkInfo,
      issuers,
      "issuers",
      keys,
      "keys",
      ca_cert_bundles,
      "caCertBundles");

    struct Member
    {
      ccf::MemberId member_id;
      ccf::MemberStatus status = ccf::MemberStatus::ACCEPTED;
      nlohmann::json member_data = nullptr;
      std::optional<std::string> certificate = std::nullopt;
      std::optional<std::string> public_encryption_key = std::nullopt;
      ccf::MemberRecoveryRole recovery_role =
        ccf::MemberRecoveryRole::NonParticipant;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Member);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      Member,
      member_id,
      "memberId",
      status,
      "status",
      member_data,
      "memberData",
      recovery_role,
      "recoveryRole");
    DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
      Member,
      certificate,
      "certificate",
      public_encryption_key,
      "publicEncryptionKey");

    struct Members
    {
      std::vector<Member> value;
    };
    DECLARE_JSON_TYPE(Members);
    DECLARE_JSON_REQUIRED_FIELDS(Members, value);

    struct User
    {
      ccf::UserId user_id;
      std::string certificate;
      nlohmann::json user_data = nullptr;
    };
    DECLARE_JSON_TYPE(User);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      User,
      user_id,
      "userId",
      certificate,
      "certificate",
      user_data,
      "userData");

    struct Users
    {
      std::vector<User> value;
    };
    DECLARE_JSON_TYPE(Users);
    DECLARE_JSON_REQUIRED_FIELDS(Users, value);

    struct NetworkInterface
    {
      std::string published_address;
      std::optional<std::string> protocol = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NetworkInterface);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      NetworkInterface, published_address, "publishedAddress");
    DECLARE_JSON_OPTIONAL_FIELDS(NetworkInterface, protocol);

    struct Node
    {
      ccf::NodeId node_id;
      ccf::NodeStatus status = ccf::NodeStatus::PENDING;
      nlohmann::json node_data = nullptr;
      std::optional<std::string> certificate = std::nullopt;
      bool retired_committed = false;
      nlohmann::json quote_info = nlohmann::json::object();
      std::map<std::string, NetworkInterface> rpc_interfaces;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Node);
    DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
      Node,
      node_id,
      "nodeId",
      status,
      "status",
      node_data,
      "nodeData",
      retired_committed,
      "retiredCommitted",
      quote_info,
      "quoteInfo",
      rpc_interfaces,
      "rpcInterfaces");
    DECLARE_JSON_OPTIONAL_FIELDS(Node, certificate);

    struct Nodes
    {
      std::vector<Node> value;
    };
    DECLARE_JSON_TYPE(Nodes);
    DECLARE_JSON_REQUIRED_FIELDS(Nodes, value);
  }

  inline api::Member produce_member_description(
    const ccf::MemberId& member_id,
    const ccf::MemberDetails& member_details,
    ccf::MemberCerts::ReadOnlyHandle* member_certs_handle,
    ccf::MemberPublicEncryptionKeys::ReadOnlyHandle* member_enc_keys_handle)
  {
    api::Member member{
      member_id,
      member_details.status,
      member_details.member_data,
      std::nullopt,
      std::nullopt,
      ccf::MemberRecoveryRole::NonParticipant};

    const auto cert = member_certs_handle->get(member_id);
    if (cert.has_value())
    {
      member.certificate = cert.value().str();
    }
    else
    {
      GOV_INFO_FMT("Member {} has no certificate", member_id);
    }

    const auto enc_key = member_enc_keys_handle->get(member_id);
    if (enc_key.has_value())
    {
      member.public_encryption_key = enc_key.value().str();
    }

    ccf::MemberRecoveryRole recovery_role =
      ccf::MemberRecoveryRole::NonParticipant;
    if (member_details.recovery_role.has_value())
    {
      recovery_role = member_details.recovery_role.value();
    }
    else if (enc_key.has_value())
    {
      recovery_role = ccf::MemberRecoveryRole::Participant;
    }

    member.recovery_role = recovery_role;

    return member;
  }

  inline api::User produce_user_description(
    const ccf::UserId& user_id,
    const ccf::crypto::Pem& user_cert,
    ccf::UserInfo::ReadOnlyHandle* user_info_handle)
  {
    const auto user_info = user_info_handle->get(user_id);
    return {
      user_id,
      user_cert.str(),
      user_info.has_value() ? user_info->user_data : nlohmann::json(nullptr)};
  }

  inline api::Node produce_node_description(
    const ccf::NodeId& node_id,
    const ccf::NodeInfo& node_info,
    ccf::NodeEndorsedCertificates::ReadOnlyHandle* node_endorsed_certs_handle)
  {
    api::Node node{
      node_id,
      node_info.status,
      node_info.node_data,
      std::nullopt,
      node_info.retired_committed,
      nlohmann::json::object(),
      {}};

    const auto endorsed_cert = node_endorsed_certs_handle->get(node_id);
    if (endorsed_cert.has_value())
    {
      node.certificate = endorsed_cert.value().str();
    }
    else
    {
      GOV_INFO_FMT("Node {} has no endorsed certificate", node_id);
    }

    auto quote_info = nlohmann::json::object();
    switch (node_info.quote_info.format)
    {
      case ccf::QuoteFormat::oe_sgx_v1:
      {
        quote_info["format"] = "OE_SGX_v1";
        quote_info["quote"] =
          ccf::crypto::b64_from_raw(node_info.quote_info.quote);
        quote_info["endorsements"] =
          ccf::crypto::b64_from_raw(node_info.quote_info.endorsements);
        break;
      }
      case ccf::QuoteFormat::insecure_virtual:
      {
        quote_info["format"] = "Insecure_Virtual";
        quote_info["rawQuote"] = node_info.quote_info.quote;

        {
          const auto details = ccf::parse_json_safe(node_info.quote_info.quote);
          auto j_details = nlohmann::json::object();
          j_details["measurement"] = details["measurement"];
          j_details["reportData"] = details["report_data"];
          j_details["hostData"] = details["host_data"];
          quote_info["details"] = j_details;
        }

        break;
      }
      case ccf::QuoteFormat::amd_sev_snp_v1:
      {
        quote_info["format"] = "AMD_SEV_SNP_v1";
        if (node_info.quote_info.uvm_endorsements.has_value())
        {
          quote_info["uvmEndorsements"] = ccf::crypto::b64_from_raw(
            node_info.quote_info.uvm_endorsements.value());
        }
        if (node_info.quote_info.endorsed_tcb.has_value())
        {
          quote_info["endorsedTcb"] = ccf::crypto::b64_from_raw(
            ds::from_hex(node_info.quote_info.endorsed_tcb.value()));
        }
        break;
      }
    }
    node.quote_info = std::move(quote_info);

    for (const auto& [interface_id, net_interface] : node_info.rpc_interfaces)
    {
      api::NetworkInterface rpc_interface{
        net_interface.published_address, net_interface.app_protocol};
      if (!rpc_interface.protocol.has_value())
      {
        GOV_INFO_FMT("RPC interface {} has no protocol", interface_id);
      }
      node.rpc_interfaces.emplace(interface_id, std::move(rpc_interface));
    }

    return node;
  }

  // NOLINTNEXTLINE(readability-function-cognitive-complexity)
  inline void init_service_state_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_constitution = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          auto constitution_handle =
            ctx.tx.template ro<ccf::Constitution>(ccf::Tables::CONSTITUTION);
          auto constitution = constitution_handle->get();

          if (!constitution.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "Constitution not found");
            return;
          }

          // Return raw JS constitution in body
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(constitution.value()));
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JAVASCRIPT);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/constitution",
        HTTP_GET,
        api_version_adapter(get_constitution),
        no_auth_required)
      .set_auto_schema<void, ds::openapi::Javascript>()
      .set_openapi_summary("Get the service constitution")
      .install();

    auto get_service_info = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          auto service_info_handle =
            ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
          auto service_info = service_info_handle->get();

          if (!service_info.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "Service info not yet available");
            return;
          }

          api::ServiceInfo response_body{
            service_info->status,
            service_info->cert.str(),
            service_info->recovery_count.value_or(0),
            service_info->current_service_create_txid,
            std::nullopt,
            service_info->service_data,
            std::nullopt};

          if (!service_info->current_service_create_txid.has_value())
          {
            GOV_INFO_FMT("No recorded current_service_create_txid");
          }

          if (service_info->previous_service_identity_version.has_value())
          {
            ccf::SeqNo seqno =
              service_info->previous_service_identity_version.value();
            ccf::View view = 0;
            // Note: deliberately ignoring errors. Prefer to return single
            // invalid field than convert entire response to error.
            registry.get_view_for_seqno_v1(seqno, view);
            response_body.previous_service_creation_transaction_id =
              ccf::TxID{.view = view, .seqno = seqno};
          }

          {
            auto config_handle = ctx.tx.template ro<ccf::Configuration>(
              ccf::Tables::CONFIGURATION);

            auto config = config_handle->get();
            if (config.has_value())
            {
              response_body.configuration = api::ServiceConfiguration{
                config->recovery_threshold,
                config->maximum_node_certificate_validity_days.value_or(
                  ccf::default_node_cert_validity_period_days),
                config->maximum_service_certificate_validity_days.value_or(
                  ccf::default_service_cert_validity_period_days),
                config->recent_cose_proposals_window_size.value_or(
                  ccf::default_recent_cose_proposals_window_size)};
            }
            else
            {
              GOV_INFO_FMT("No service configuration available");
            }
          }

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/info",
        HTTP_GET,
        api_version_adapter(get_service_info),
        no_auth_required)
      .set_auto_schema<void, api::ServiceInfo>()
      .set_openapi_summary("Get service information")
      .install();

    auto get_javascript_app = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::JavascriptApp response_body;

          // Describe JS endpoints
          {
            auto endpoints = nlohmann::json::object();

            bool original_case = false;
            {
              const auto parsed_query =
                ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
              std::string error_reason;
              const auto case_opt = ccf::http::get_query_value_opt<std::string>(
                parsed_query, "case", error_reason);

              if (case_opt.has_value())
              {
                if (case_opt.value() != "original")
                {
                  ctx.rpc_ctx->set_error(
                    HTTP_STATUS_BAD_REQUEST,
                    ccf::errors::InvalidQueryParameterValue,
                    "Accepted values for the 'case' query parameter are: "
                    "original");
                  return;
                }

                original_case = true;
              }
            }

            auto js_endpoints_handle =
              ctx.tx.template ro<ccf::endpoints::EndpointsMap>(
                ccf::endpoints::Tables::ENDPOINTS);

            using RawEndpointsMap = ccf::kv::RawCopySerialisedMap<
              ccf::endpoints::EndpointsMap::Key,
              std::vector<uint8_t>>;
            auto raw_js_endpoints_handle = ctx.tx.template ro<RawEndpointsMap>(
              ccf::endpoints::Tables::ENDPOINTS);

            js_endpoints_handle->foreach(
              [&endpoints, &raw_js_endpoints_handle, original_case](
                const ccf::endpoints::EndpointKey& key,
                const ccf::endpoints::EndpointProperties& properties) {
                auto ib =
                  endpoints.emplace(key.uri_path, nlohmann::json::object());
                auto& operations = *ib.first;

                auto operation = nlohmann::json::object();

                if (original_case)
                {
                  const auto raw_value_opt = raw_js_endpoints_handle->get(key);
                  if (!raw_value_opt.has_value())
                  {
                    throw std::runtime_error(
                      "Table inconsistency: Cannot access key via raw handle?");
                  }
                  const auto& raw_value = raw_value_opt.value();
                  operation =
                    ccf::parse_json_safe(raw_value.begin(), raw_value.end());
                }
                else
                {
                  operation["jsModule"] = properties.js_module;
                  operation["jsFunction"] = properties.js_function;
                  operation["forwardingRequired"] =
                    properties.forwarding_required;
                  operation["redirectionStrategy"] =
                    properties.redirection_strategy;

                  auto policies = nlohmann::json::array();
                  for (const auto& policy : properties.authn_policies)
                  {
                    policies.push_back(policy);
                  }
                  operation["authnPolicies"] = policies;

                  operation["mode"] = properties.mode;
                  operation["openApi"] = properties.openapi;
                }

                operations[key.verb.c_str()] = operation;

                return true;
              });

            response_body.endpoints = std::move(endpoints);
          }

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/javascript-app",
        HTTP_GET,
        api_version_adapter(get_javascript_app, ApiVersion::v1),
        no_auth_required)
      .set_auto_schema<void, api::JavascriptApp>()
      .add_query_parameter<api::JavascriptAppCase>(
        "case", ccf::endpoints::QueryParamPresence::OptionalParameter)
      .set_openapi_summary("Get the installed JavaScript application")
      .install();

    auto get_javascript_modules = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::JavascriptModules response_body;
          auto modules_handle =
            ctx.tx.template ro<ccf::Modules>(ccf::Tables::MODULES);
          modules_handle->foreach_key(
            [&response_body](const std::string& module_name) {
              response_body.value.push_back({module_name});
              return true;
            });

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/javascript-modules",
        HTTP_GET,
        api_version_adapter(get_javascript_modules, ApiVersion::v1),
        no_auth_required)
      .set_auto_schema<void, api::JavascriptModules>()
      .set_openapi_summary("List JavaScript modules")
      .install();

    auto get_javascript_module_by_name =
      [&](auto& ctx, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::preview_v1:
          case ApiVersion::v1:
          case ApiVersion::Latest:
          {
            std::string module_name;
            {
              std::string error;
              if (!ccf::endpoints::get_path_param(
                    ctx.rpc_ctx->get_request_path_params(),
                    "moduleName",
                    module_name,
                    error))
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_BAD_REQUEST,
                  ccf::errors::InvalidResourceName,
                  std::move(error));
                return;
              }
            }

            module_name = ::http::url_decode(module_name);

            auto modules_handle =
              ctx.tx.template ro<ccf::Modules>(ccf::Tables::MODULES);
            auto module = modules_handle->get(module_name);

            if (!module.has_value())
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_NOT_FOUND,
                ccf::errors::ResourceNotFound,
                fmt::format("Module {} does not exist.", module_name));
              return;
            }

            // Return raw JS module content in body
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            ctx.rpc_ctx->set_response_body(std::move(module.value()));
            ctx.rpc_ctx->set_response_header(
              ccf::http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::JAVASCRIPT);
            return;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/service/javascript-modules/{moduleName}",
        HTTP_GET,
        api_version_adapter(get_javascript_module_by_name, ApiVersion::v1),
        no_auth_required)
      .set_auto_schema<void, ds::openapi::Javascript>()
      .set_openapi_summary("Get a JavaScript module")
      .install();

    auto get_join_policy = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::JoinPolicy response_body;

          // Describe SGX join policy
          {
            auto code_ids_handle =
              ctx.tx.template ro<ccf::CodeIDs>(ccf::Tables::NODE_CODE_IDS);
            code_ids_handle->foreach(
              [&response_body](
                const ccf::pal::SgxAttestationMeasurement& measurement,
                const ccf::CodeStatus& status) {
                if (status == ccf::CodeStatus::ALLOWED_TO_JOIN)
                {
                  response_body.sgx.measurements.push_back(
                    measurement.hex_str());
                }
                return true;
              });
          }

          // Describe Virtual join policy
          {
            auto measurements_handle =
              ctx.tx.template ro<ccf::VirtualMeasurements>(
                ccf::Tables::NODE_VIRTUAL_MEASUREMENTS);
            measurements_handle->foreach(
              [&response_body](
                const pal::VirtualAttestationMeasurement& measurement,
                const ccf::CodeStatus& status) {
                if (status == ccf::CodeStatus::ALLOWED_TO_JOIN)
                {
                  response_body.virtual_.measurements.push_back(measurement);
                }
                return true;
              });

            auto host_data_handle = ctx.tx.template ro<ccf::VirtualHostDataMap>(
              ccf::Tables::VIRTUAL_HOST_DATA);
            host_data_handle->foreach(
              [&response_body](const HostData& host_data) {
                response_body.virtual_.host_data.push_back(host_data.hex_str());
                return true;
              });
          }

          // Describe SNP join policy
          {
            auto measurements_handle = ctx.tx.template ro<ccf::SnpMeasurements>(
              ccf::Tables::NODE_SNP_MEASUREMENTS);
            measurements_handle->foreach(
              [&response_body](
                const pal::SnpAttestationMeasurement& measurement,
                const ccf::CodeStatus& status) {
                if (status == ccf::CodeStatus::ALLOWED_TO_JOIN)
                {
                  response_body.snp.measurements.push_back(
                    measurement.hex_str());
                }
                return true;
              });

            auto host_data_handle =
              ctx.tx.template ro<ccf::SnpHostDataMap>(ccf::Tables::HOST_DATA);
            host_data_handle->foreach(
              [&response_body](
                const HostData& host_data, const HostDataMetadata& metadata) {
                response_body.snp.host_data.emplace(
                  host_data.hex_str(), metadata);
                return true;
              });

            auto endorsements_handle =
              ctx.tx.template ro<ccf::SNPUVMEndorsements>(
                ccf::Tables::NODE_SNP_UVM_ENDORSEMENTS);
            endorsements_handle->foreach(
              [&response_body](
                const ccf::DID& did,
                const ccf::FeedToEndorsementsDataMap& feed_info) {
                response_body.snp.uvm_endorsements.emplace(did, feed_info);
                return true;
              });

            auto tcb_versions_handle =
              ctx.tx.template ro<ccf::SnpTcbVersionMap>(
                ccf::Tables::SNP_TCB_VERSIONS);

            tcb_versions_handle->foreach(
              [&response_body](
                const std::string& cpuid,
                const pal::snp::TcbVersionPolicy& tcb_policy) {
                response_body.snp.tcb_versions.emplace(cpuid, tcb_policy);
                return true;
              });
          }

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/join-policy",
        HTTP_GET,
        api_version_adapter(get_join_policy),
        no_auth_required)
      .set_auto_schema<void, api::JoinPolicy>()
      .set_openapi_summary("Get the service join policy")
      .install();

    auto get_jwk = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::JwkInfo response_body;

          // Populate issuers field
          {
            auto jwt_issuers_handle =
              ctx.tx.template ro<ccf::JwtIssuers>(ccf::Tables::JWT_ISSUERS);
            jwt_issuers_handle->foreach(
              [&response_body](
                const ccf::JwtIssuer& issuer_id,
                const ccf::JwtIssuerMetadata& metadata) {
                response_body.issuers.emplace(
                  issuer_id,
                  api::JwtIssuer{
                    metadata.auto_refresh, metadata.ca_cert_bundle_name});
                return true;
              });
          }

          // Populate keys field
          {
            auto jwt_keys_handle =
              ctx.tx.template ro<ccf::JwtPublicSigningKeysMetadata>(
                ccf::Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);

            jwt_keys_handle->foreach(
              [&response_body](
                const ccf::JwtKeyId& k,
                const std::vector<OpenIDJWKMetadata>& v) {
                auto& keys_info = response_body.keys[k];
                for (const auto& metadata : v)
                {
                  keys_info.push_back(
                    {ccf::crypto::make_rsa_public_key(metadata.public_key)
                       ->public_key_pem()
                       .str(),
                     metadata.issuer,
                     metadata.constraint.has_value() ?
                       nlohmann::json(metadata.constraint.value()) :
                       nlohmann::json(nullptr)});
                }
                return true;
              });
          }

          // Populate caCertBundles field
          {
            auto cert_bundles_handle =
              ctx.tx.template ro<ccf::CACertBundlePEMs>(
                ccf::Tables::CA_CERT_BUNDLE_PEMS);
            cert_bundles_handle->foreach([&response_body](
                                           const std::string& bundle_name,
                                           const std::string& bundle_value) {
              response_body.ca_cert_bundles.emplace(bundle_name, bundle_value);
              return true;
            });
          }

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/jwk",
        HTTP_GET,
        api_version_adapter(get_jwk),
        no_auth_required)
      .set_auto_schema<void, api::JwkInfo>()
      .set_openapi_summary("Get accepted JWT issuers and keys")
      .install();

    auto get_members = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::Members response_body;
          auto member_info_handle =
            ctx.tx.template ro<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
          auto member_certs_handle =
            ctx.tx.template ro<ccf::MemberCerts>(ccf::Tables::MEMBER_CERTS);
          auto member_enc_keys_handle =
            ctx.tx.template ro<ccf::MemberPublicEncryptionKeys>(
              ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

          member_info_handle->foreach(
            [&response_body, member_certs_handle, member_enc_keys_handle](
              const ccf::MemberId& member_id,
              const ccf::MemberDetails& member_details) {
              response_body.value.push_back(produce_member_description(
                member_id,
                member_details,
                member_certs_handle,
                member_enc_keys_handle));
              return true;
            });

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/members",
        HTTP_GET,
        api_version_adapter(get_members),
        no_auth_required)
      .set_auto_schema<void, api::Members>()
      .set_openapi_summary("List consortium members")
      .install();

    auto get_member_by_id = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          ccf::MemberId member_id;
          if (!detail::try_parse_member_id(ctx.rpc_ctx, member_id))
          {
            return;
          }

          auto member_info_handle =
            ctx.tx.template ro<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
          const auto member_info = member_info_handle->get(member_id);
          if (!member_info.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format("Member {} does not exist.", member_id));
            return;
          }

          auto member_certs_handle =
            ctx.tx.template ro<ccf::MemberCerts>(ccf::Tables::MEMBER_CERTS);
          auto member_enc_keys_handle =
            ctx.tx.template ro<ccf::MemberPublicEncryptionKeys>(
              ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

          const auto member = produce_member_description(
            member_id,
            member_info.value(),
            member_certs_handle,
            member_enc_keys_handle);

          ctx.rpc_ctx->set_response_json(member, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/members/{memberId}",
        HTTP_GET,
        api_version_adapter(get_member_by_id),
        no_auth_required)
      .set_auto_schema<void, api::Member>()
      .set_openapi_summary("Get a consortium member")
      .install();

    auto get_users = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::Users response_body;
          auto user_certs_handle =
            ctx.tx.template ro<ccf::UserCerts>(ccf::Tables::USER_CERTS);
          auto user_info_handle =
            ctx.tx.template ro<ccf::UserInfo>(ccf::Tables::USER_INFO);

          user_certs_handle->foreach(
            [&response_body, user_info_handle](
              const ccf::UserId& user_id, const ccf::crypto::Pem& user_cert) {
              response_body.value.push_back(
                produce_user_description(user_id, user_cert, user_info_handle));
              return true;
            });

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/users",
        HTTP_GET,
        api_version_adapter(get_users),
        no_auth_required)
      .set_auto_schema<void, api::Users>()
      .set_openapi_summary("List application users")
      .install();

    auto get_user_by_id = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          ccf::UserId user_id;
          if (!detail::try_parse_user_id(ctx.rpc_ctx, user_id))
          {
            return;
          }

          auto user_certs_handle =
            ctx.tx.template ro<ccf::UserCerts>(ccf::Tables::USER_CERTS);

          const auto user_cert = user_certs_handle->get(user_id);
          if (!user_cert.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format("User {} does not exist.", user_id));
            return;
          }

          auto user_info_handle =
            ctx.tx.template ro<ccf::UserInfo>(ccf::Tables::USER_INFO);

          const auto user = produce_user_description(
            user_id, user_cert.value(), user_info_handle);

          ctx.rpc_ctx->set_response_json(user, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/users/{userId}",
        HTTP_GET,
        api_version_adapter(get_user_by_id),
        no_auth_required)
      .set_auto_schema<void, api::User>()
      .set_openapi_summary("Get an application user")
      .install();

    auto get_nodes = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          api::Nodes response_body;
          auto node_info_handle =
            ctx.tx.template ro<ccf::Nodes>(ccf::Tables::NODES);
          auto node_endorsed_certs_handle =
            ctx.tx.template ro<ccf::NodeEndorsedCertificates>(
              ccf::Tables::NODE_ENDORSED_CERTIFICATES);

          node_info_handle->foreach(
            [&response_body, node_endorsed_certs_handle](
              const ccf::NodeId& node_id, const ccf::NodeInfo& node_info) {
              response_body.value.push_back(produce_node_description(
                node_id, node_info, node_endorsed_certs_handle));
              return true;
            });

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/nodes",
        HTTP_GET,
        api_version_adapter(get_nodes),
        no_auth_required)
      .set_auto_schema<void, api::Nodes>()
      .set_openapi_summary("List service nodes")
      .install();

    auto get_node_by_id = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        case ApiVersion::Latest:
        {
          ccf::NodeId node_id;
          if (!detail::try_parse_node_id(ctx.rpc_ctx, node_id))
          {
            return;
          }

          auto node_info_handle =
            ctx.tx.template ro<ccf::Nodes>(ccf::Tables::NODES);
          const auto node_info = node_info_handle->get(node_id);
          if (!node_info.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format("Node {} does not exist.", node_id));
            return;
          }

          auto node_endorsed_certs_handle =
            ctx.tx.template ro<ccf::NodeEndorsedCertificates>(
              ccf::Tables::NODE_ENDORSED_CERTIFICATES);
          const auto node = produce_node_description(
            node_id, node_info.value(), node_endorsed_certs_handle);

          ctx.rpc_ctx->set_response_json(node, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/service/nodes/{nodeId}",
        HTTP_GET,
        api_version_adapter(get_node_by_id),
        no_auth_required)
      .set_auto_schema<void, api::Node>()
      .set_openapi_summary("Get a service node")
      .install();
  }
}