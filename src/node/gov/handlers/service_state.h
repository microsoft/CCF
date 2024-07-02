// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  nlohmann::json produce_member_description(
    const ccf::MemberId& member_id,
    const ccf::MemberDetails& member_details,
    ccf::MemberCerts::ReadOnlyHandle* member_certs_handle,
    ccf::MemberPublicEncryptionKeys::ReadOnlyHandle* member_enc_keys_handle)
  {
    auto member = nlohmann::json::object();

    member["memberId"] = member_id;
    member["status"] = member_details.status;
    member["memberData"] = member_details.member_data;

    const auto cert = member_certs_handle->get(member_id);
    if (cert.has_value())
    {
      member["certificate"] = cert.value().str();
    }
    else
    {
      GOV_INFO_FMT("Member {} has no certificate", member_id);
    }

    const auto enc_key = member_enc_keys_handle->get(member_id);
    if (enc_key.has_value())
    {
      member["publicEncryptionKey"] = enc_key.value().str();
    }

    return member;
  }

  nlohmann::json produce_user_description(
    const ccf::UserId& user_id,
    const ccf::crypto::Pem& user_cert,
    ccf::UserInfo::ReadOnlyHandle* user_info_handle)
  {
    auto user = nlohmann::json::object();

    user["userId"] = user_id;
    user["certificate"] = user_cert.str();

    const auto user_info = user_info_handle->get(user_id);
    // For consistency with other *Data fields, we always insert this, even if
    // it iss nullopt (JSON null)
    user["userData"] = user_info;

    return user;
  }

  nlohmann::json produce_node_description(
    const ccf::NodeId& node_id,
    const ccf::NodeInfo& node_info,
    ccf::NodeEndorsedCertificates::ReadOnlyHandle* node_endorsed_certs_handle)
  {
    auto node = nlohmann::json::object();

    node["nodeId"] = node_id;
    node["status"] = node_info.status;
    node["nodeData"] = node_info.node_data;

    const auto endorsed_cert = node_endorsed_certs_handle->get(node_id);
    if (endorsed_cert.has_value())
    {
      node["certificate"] = endorsed_cert.value().str();
    }
    else
    {
      GOV_INFO_FMT("Node {} has no endorsed certificate", node_id);
    }

    node["retiredCommitted"] = node_info.retired_committed;

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
    node["quoteInfo"] = quote_info;

    auto rpc_interfaces = nlohmann::json::object();
    for (const auto& [interface_id, net_interface] : node_info.rpc_interfaces)
    {
      auto rpc_interface = nlohmann::json::object();

      rpc_interface["publishedAddress"] = net_interface.published_address;
      if (net_interface.app_protocol.has_value())
      {
        rpc_interface["protocol"] = net_interface.app_protocol.value();
      }
      else
      {
        GOV_INFO_FMT("RPC interface {} has no protocol", interface_id);
      }
      rpc_interfaces[interface_id] = rpc_interface;
    }

    node["rpcInterfaces"] = rpc_interfaces;

    return node;
  }

  void init_service_state_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_constitution = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
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
      .set_openapi_hidden(true)
      .install();

    auto get_service_info = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

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

          response_body["status"] = service_info->status;
          response_body["certificate"] = service_info->cert.str();
          response_body["recoveryCount"] =
            service_info->recovery_count.value_or(0);

          if (service_info->current_service_create_txid.has_value())
          {
            response_body["creationTransactionId"] =
              service_info->current_service_create_txid.value();
          }
          else
          {
            GOV_INFO_FMT("No recorded current_service_create_txid");
          }

          if (service_info->previous_service_identity_version.has_value())
          {
            ccf::SeqNo seqno =
              service_info->previous_service_identity_version.value();
            ccf::View view;
            // Note: deliberately ignoring errors. Prefer to return single
            // invalid field than convert entire response to error.
            registry.get_view_for_seqno_v1(seqno, view);
            response_body["previousServiceCreationTransactionId"] =
              ccf::TxID{.view = view, .seqno = seqno};
          }

          response_body["serviceData"] = service_info->service_data;

          {
            auto config_handle = ctx.tx.template ro<ccf::Configuration>(
              ccf::Tables::CONFIGURATION);

            auto config = config_handle->get();
            if (config.has_value())
            {
              auto configuration = nlohmann::json::object();
              configuration["recoveryThreshold"] = config->recovery_threshold;
              configuration["maximumNodeCertificateValidityDays"] =
                config->maximum_node_certificate_validity_days.value_or(
                  ccf::default_node_cert_validity_period_days);
              configuration["maximumServiceCertificateValidityDays"] =
                config->maximum_service_certificate_validity_days.value_or(
                  ccf::default_service_cert_validity_period_days);
              configuration["recentCoseProposalsWindowSize"] =
                config->recent_cose_proposals_window_size.value_or(
                  ccf::default_recent_cose_proposals_window_size);
              response_body["configuration"] = configuration;
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
      .set_openapi_hidden(true)
      .install();

    auto get_javascript_app = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

          // Describe JS endpoints
          {
            auto endpoints = nlohmann::json::object();

            auto js_endpoints_handle =
              ctx.tx.template ro<ccf::endpoints::EndpointsMap>(
                ccf::endpoints::Tables::ENDPOINTS);
            js_endpoints_handle->foreach(
              [&endpoints](
                const ccf::endpoints::EndpointKey& key,
                const ccf::endpoints::EndpointProperties& properties) {
                auto ib =
                  endpoints.emplace(key.uri_path, nlohmann::json::object());
                auto& operations = *ib.first;

                auto operation = nlohmann::json::object();

                operation["jsModule"] = properties.js_module;
                operation["jsFunction"] = properties.js_function;
                operation["forwardingRequired"] =
                  properties.forwarding_required;

                auto policies = nlohmann::json::array();
                for (const auto& policy : properties.authn_policies)
                {
                  policies.push_back(policy);
                }
                operation["authnPolicies"] = policies;

                operation["mode"] = properties.mode;
                operation["openApi"] = properties.authn_policies;

                operations[key.verb.c_str()] = operation;

                return true;
              });

            response_body["endpoints"] = endpoints;
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
        api_version_adapter(get_javascript_app),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_join_policy = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

          // Describe SGX join policy
          {
            auto sgx_policy = nlohmann::json::object();

            auto sgx_measurements = nlohmann::json::array();
            auto code_ids_handle =
              ctx.tx.template ro<ccf::CodeIDs>(ccf::Tables::NODE_CODE_IDS);
            code_ids_handle->foreach(
              [&sgx_measurements](
                const ccf::pal::SgxAttestationMeasurement& measurement,
                const ccf::CodeStatus& status) {
                if (status == ccf::CodeStatus::ALLOWED_TO_JOIN)
                {
                  sgx_measurements.push_back(measurement.hex_str());
                }
                return true;
              });
            sgx_policy["measurements"] = sgx_measurements;

            response_body["sgx"] = sgx_policy;
          }

          // Describe SNP join policy
          {
            auto snp_policy = nlohmann::json::object();

            auto snp_measurements = nlohmann::json::array();
            auto measurements_handle = ctx.tx.template ro<ccf::SnpMeasurements>(
              ccf::Tables::NODE_SNP_MEASUREMENTS);
            measurements_handle->foreach(
              [&snp_measurements](
                const pal::SnpAttestationMeasurement& measurement,
                const ccf::CodeStatus& status) {
                if (status == ccf::CodeStatus::ALLOWED_TO_JOIN)
                {
                  snp_measurements.push_back(measurement.hex_str());
                }
                return true;
              });
            snp_policy["measurements"] = snp_measurements;

            auto snp_host_data = nlohmann::json::object();
            auto host_data_handle =
              ctx.tx.template ro<ccf::SnpHostDataMap>(ccf::Tables::HOST_DATA);
            host_data_handle->foreach(
              [&snp_host_data](
                const HostData& host_data, const HostDataMetadata& metadata) {
                snp_host_data[host_data.hex_str()] = metadata;
                return true;
              });
            snp_policy["hostData"] = snp_host_data;

            auto snp_endorsements = nlohmann::json::object();
            auto endorsements_handle =
              ctx.tx.template ro<ccf::SNPUVMEndorsements>(
                ccf::Tables::NODE_SNP_UVM_ENDORSEMENTS);
            endorsements_handle->foreach(
              [&snp_endorsements](
                const ccf::DID& did,
                const ccf::FeedToEndorsementsDataMap& feed_info) {
                snp_endorsements[did] = feed_info;
                return true;
              });
            snp_policy["uvmEndorsements"] = snp_endorsements;

            response_body["snp"] = snp_policy;
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
      .set_openapi_hidden(true)
      .install();

    auto get_jwk = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

          // Populate issuers field
          {
            auto issuers = nlohmann::json::object();

            auto jwt_issuers_handle =
              ctx.tx.template ro<ccf::JwtIssuers>(ccf::Tables::JWT_ISSUERS);
            jwt_issuers_handle->foreach(
              [&issuers](
                const ccf::JwtIssuer& issuer_id,
                const ccf::JwtIssuerMetadata& metadata) {
                auto jwt_issuer = nlohmann::json::object();

                jwt_issuer["keyFilter"] = metadata.key_filter;
                jwt_issuer["autoRefresh"] = metadata.auto_refresh;

                if (metadata.key_policy.has_value())
                {
                  jwt_issuer["keyPolicy"] = metadata.key_policy.value();
                }

                if (metadata.ca_cert_bundle_name.has_value())
                {
                  jwt_issuer["caCertBundleName"] =
                    metadata.ca_cert_bundle_name.value();
                }

                issuers[issuer_id] = jwt_issuer;
                return true;
              });

            response_body["issuers"] = issuers;
          }

          // Populate keys field
          {
            auto keys = nlohmann::json::object();

            auto jwt_keys_handle =
              ctx.tx.template ro<ccf::JwtPublicSigningKeys>(
                ccf::Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);

            jwt_keys_handle->foreach(
              [&keys](
                const ccf::JwtKeyId& k,
                const std::vector<OpenIDJWKMetadata>& v) {
                auto keys_info = nlohmann::json::array();
                for (const auto& metadata : v)
                {
                  auto info = nlohmann::json::object();

                  // cert is stored as DER - convert to PEM for API
                  const auto cert_pem =
                    ccf::crypto::cert_der_to_pem(metadata.cert);
                  info["certificate"] = cert_pem.str();

                  info["issuer"] = metadata.issuer;
                  info["constraint"] = metadata.constraint;

                  keys_info.push_back(info);
                }

                keys[k] = keys_info;
                return true;
              });

            response_body["keys"] = keys;
          }

          // Populate caCertBundles field
          {
            auto cert_bundles = nlohmann::json::object();

            auto cert_bundles_handle =
              ctx.tx.template ro<ccf::CACertBundlePEMs>(
                ccf::Tables::CA_CERT_BUNDLE_PEMS);
            cert_bundles_handle->foreach([&cert_bundles](
                                           const std::string& bundle_name,
                                           const std::string& bundle_value) {
              cert_bundles[bundle_name] = bundle_value;
              return true;
            });

            response_body["caCertBundles"] = cert_bundles;
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
      .set_openapi_hidden(true)
      .install();

    auto get_members = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

          {
            auto member_list = nlohmann::json::array();

            auto member_info_handle =
              ctx.tx.template ro<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
            auto member_certs_handle =
              ctx.tx.template ro<ccf::MemberCerts>(ccf::Tables::MEMBER_CERTS);
            auto member_enc_keys_handle =
              ctx.tx.template ro<ccf::MemberPublicEncryptionKeys>(
                ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

            member_info_handle->foreach(
              [&member_list, member_certs_handle, member_enc_keys_handle](
                const ccf::MemberId& member_id,
                const ccf::MemberDetails& member_details) {
                member_list.push_back(produce_member_description(
                  member_id,
                  member_details,
                  member_certs_handle,
                  member_enc_keys_handle));
                return true;
              });

            response_body["value"] = member_list;
          }

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
      .set_openapi_hidden(true)
      .install();

    auto get_member_by_id = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
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
      .set_openapi_hidden(true)
      .install();

    auto get_users = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

          {
            auto user_list = nlohmann::json::array();

            auto user_certs_handle =
              ctx.tx.template ro<ccf::UserCerts>(ccf::Tables::USER_CERTS);
            auto user_info_handle =
              ctx.tx.template ro<ccf::UserInfo>(ccf::Tables::USER_INFO);

            user_certs_handle->foreach([&user_list, user_info_handle](
                                         const ccf::UserId& user_id,
                                         const ccf::crypto::Pem& user_cert) {
              user_list.push_back(
                produce_user_description(user_id, user_cert, user_info_handle));
              return true;
            });

            response_body["value"] = user_list;
          }

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
      .set_openapi_hidden(true)
      .install();

    auto get_user_by_id = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
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
      .set_openapi_hidden(true)
      .install();

    auto get_nodes = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          auto response_body = nlohmann::json::object();

          {
            auto node_list = nlohmann::json::array();

            auto node_info_handle =
              ctx.tx.template ro<ccf::Nodes>(ccf::Tables::NODES);
            auto node_endorsed_certs_handle =
              ctx.tx.template ro<ccf::NodeEndorsedCertificates>(
                ccf::Tables::NODE_ENDORSED_CERTIFICATES);

            node_info_handle->foreach(
              [&node_list, node_endorsed_certs_handle](
                const ccf::NodeId& node_id, const ccf::NodeInfo& node_info) {
                node_list.push_back(produce_node_description(
                  node_id, node_info, node_endorsed_certs_handle));
                return true;
              });

            response_body["value"] = node_list;
          }

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
      .set_openapi_hidden(true)
      .install();

    auto get_node_by_id = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
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
      .set_openapi_hidden(true)
      .install();
  }
}