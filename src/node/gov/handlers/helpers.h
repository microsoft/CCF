// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/endpoints/authentication/cose_auth.h"
#include "node/rpc/gov_logging.h"

namespace ccf::gov::endpoints::detail
{
  inline AuthnPolicies member_sig_only_policies(const std::string& gov_msg_type)
  {
    return {std::make_shared<MemberCOSESign1AuthnPolicy>(gov_msg_type)};
  }

  inline AuthnPolicies active_member_sig_only_policies(
    const std::string& gov_msg_type)
  {
    return {std::make_shared<ActiveMemberCOSESign1AuthnPolicy>(gov_msg_type)};
  }

  // Wrapper for reporting errors, which both logs them under the [gov] tag
  // and sets the HTTP response
  static void set_gov_error(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    ccf::http_status status,
    const std::string& code,
    std::string&& msg)
  {
    GOV_INFO_FMT(
      "{} {} returning error {}: {}",
      rpc_ctx->get_request_verb().c_str(),
      rpc_ctx->get_request_path(),
      status,
      msg);

    rpc_ctx->set_error(status, code, std::move(msg));
  }

  template <typename EntityType>
  std::optional<EntityType> parse_hex_id(const std::string& s)
  {
    // Entity IDs must be hex encoding of 32 bytes

    // Must be 64 characters in length
    if (s.size() != 64)
    {
      return std::nullopt;
    }

    // Must contain only hex characters
    if (std::any_of(s.begin(), s.end(), [](char c) {
          return (c < '0') || (c > '9' && c < 'A') || (c > 'F' && c < 'a') ||
            (c > 'f');
        }))
    {
      return std::nullopt;
    }

    return EntityType(s);
  }

  // Extract memberId from path parameter, confirm it is a plausible ID
  inline bool try_parse_member_id(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx, ccf::MemberId& member_id)
  {
    // Extract member ID from path parameter
    std::string member_id_str;
    std::string error;
    if (!ccf::endpoints::get_path_param(
          rpc_ctx->get_request_path_params(), "memberId", member_id_str, error))
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        std::move(error));
      return false;
    }

    // Parse member ID from string
    const auto member_id_opt = parse_hex_id<ccf::MemberId>(member_id_str);
    if (!member_id_opt.has_value())
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        fmt::format(
          "'{}' is not a valid hex-encoded member ID", member_id_str));
      return false;
    }

    member_id = member_id_opt.value();
    return true;
  }

  // Like try_parse_member_id, but also confirm that the parsed member ID
  // matches the COSE signer
  inline bool try_parse_signed_member_id(
    const ccf::MemberCOSESign1AuthnIdentity& cose_ident,
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    ccf::MemberId& member_id)
  {
    if (!try_parse_member_id(rpc_ctx, member_id))
    {
      return false;
    }

    if (member_id != cose_ident.member_id)
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        "Authenticated member id does not match URL");
      return false;
    }

    return true;
  }

  // Extract userId from path parameter, confirm it is a plausible ID
  inline bool try_parse_user_id(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx, ccf::UserId& user_id)
  {
    // Extract user ID from path parameter
    std::string user_id_str;
    std::string error;
    if (!ccf::endpoints::get_path_param(
          rpc_ctx->get_request_path_params(), "userId", user_id_str, error))
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        std::move(error));
      return false;
    }

    // Parse user ID from string
    const auto user_id_opt = parse_hex_id<ccf::UserId>(user_id_str);
    if (!user_id_opt.has_value())
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        fmt::format("'{}' is not a valid hex-encoded user ID", user_id_str));
      return false;
    }

    user_id = user_id_opt.value();
    return true;
  }

  // Extract proposalId from path parameter, confirm it is a plausible ID
  inline bool try_parse_proposal_id(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    ccf::ProposalId& proposal_id)
  {
    // Extract proposal ID from path parameter
    std::string proposal_id_str;
    std::string error;
    if (!ccf::endpoints::get_path_param(
          rpc_ctx->get_request_path_params(),
          "proposalId",
          proposal_id_str,
          error))
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        std::move(error));
      return false;
    }

    // Parse proposal ID from string
    const auto proposal_id_opt = parse_hex_id<ccf::ProposalId>(proposal_id_str);
    if (!proposal_id_opt.has_value())
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        fmt::format(
          "'{}' is not a valid hex-encoded proposal ID", proposal_id_str));
      return false;
    }

    proposal_id = proposal_id_opt.value();
    return true;
  }

  // Like try_parse_proposal_id, but also confirm that the parsed proposal ID
  // matches a signed COSE header
  inline bool try_parse_signed_proposal_id(
    const ccf::MemberCOSESign1AuthnIdentity& cose_ident,
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    ccf::ProposalId& proposal_id)
  {
    if (!try_parse_proposal_id(rpc_ctx, proposal_id))
    {
      return false;
    }

    const auto& signed_proposal_id =
      cose_ident.protected_header.gov_msg_proposal_id;
    if (
      !signed_proposal_id.has_value() ||
      signed_proposal_id.value() != proposal_id)
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        "Authenticated proposal id does not match URL");
      return false;
    }

    return true;
  }

  // Extract nodeId from path parameter, confirm it is a plausible ID
  inline bool try_parse_node_id(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx, ccf::NodeId& node_id)
  {
    // Extract node ID from path parameter
    std::string node_id_str;
    std::string error;
    if (!ccf::endpoints::get_path_param(
          rpc_ctx->get_request_path_params(), "nodeId", node_id_str, error))
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        std::move(error));
      return false;
    }

    // Parse node ID from string
    const auto node_id_opt = parse_hex_id<ccf::NodeId>(node_id_str);
    if (!node_id_opt.has_value())
    {
      detail::set_gov_error(
        rpc_ctx,
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidResourceName,
        fmt::format("'{}' is not a valid hex-encoded node ID", node_id_str));
      return false;
    }

    node_id = node_id_opt.value();
    return true;
  }
}
