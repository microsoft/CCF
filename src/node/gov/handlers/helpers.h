// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/endpoints/authentication/cose_auth.h"
#include "node/rpc/gov_logging.h"

namespace ccf::gov::endpoints
{
  namespace detail
  {
    AuthnPolicies member_sig_only_policies(const std::string& gov_msg_type)
    {
      return {std::make_shared<MemberCOSESign1AuthnPolicy>(gov_msg_type)};
    }

    AuthnPolicies active_member_sig_only_policies(
      const std::string& gov_msg_type)
    {
      return {std::make_shared<ActiveMemberCOSESign1AuthnPolicy>(gov_msg_type)};
    }

    // Wrapper for reporting errors, which both logs them under the [gov] tag
    // and sets the HTTP response
    static void set_gov_error(
      const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
      http_status status,
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
  }
}
