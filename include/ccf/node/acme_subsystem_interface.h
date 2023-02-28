// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/http_header_map.h"
#include "ccf/http_status.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/service/acme_client_config.h"
#include "ccf/service/node_info_network.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  class ACMESubsystemInterface : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~ACMESubsystemInterface() = default;

    static char const* get_subsystem_name()
    {
      return "ACME";
    }

    virtual std::optional<const ccf::ACMEClientConfig*> config(
      const NodeInfoNetwork::RpcInterfaceID& id) = 0;

    virtual crypto::Pem network_cert() = 0;

    virtual void install_challenge_handler(
      const ccf::NodeInfoNetwork::RpcInterfaceID& interface_id,
      std::shared_ptr<ACMEChallengeHandler> h) = 0;

    virtual void make_http_request(
      const std::string& method,
      const std::string& url,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body,
      std::function<bool(
        const http_status& http_status,
        const http::HeaderMap&,
        const std::vector<uint8_t>&)> callback,
      const std::vector<std::string>& ca_certs = {},
      ccf::ApplicationProtocol app_protocol = ccf::ApplicationProtocol::HTTP1,
      bool use_node_client_certificate = false) = 0;
  };
}
