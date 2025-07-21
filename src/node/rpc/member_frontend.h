// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/crypto/base64.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/sha256.h"
#include "ccf/ds/nonstd.h"
#include "ccf/http_query.h"
#include "ccf/js/common_context.h"
#include "ccf/json_handler.h"
#include "ccf/node/quote.h"
#include "ccf/service/tables/gov.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/tcb_verification.h"
#include "frontend.h"
#include "js/extensions/ccf/network.h"
#include "js/extensions/ccf/node.h"
#include "node/gov/gov_endpoint_registry.h"
#include "node/rpc/call_types.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/gov_logging.h"
#include "node/rpc/node_operation_interface.h"
#include "node/rpc/serialization.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "service/internal_tables_access.h"
#include "service/tables/config.h"
#include "service/tables/endpoints.h"

#include <charconv>
#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <openssl/crypto.h>
#include <set>
#include <sstream>

namespace ccf
{
  class MemberRpcFrontend : public RpcFrontend
  {
  protected:
    GovEndpointRegistry member_endpoints;

  public:
    MemberRpcFrontend(
      NetworkState& network, ccf::AbstractNodeContext& context) :
      RpcFrontend(*network.tables, member_endpoints, context),
      member_endpoints(network, context)
    {}
  };
} // namespace ccf
