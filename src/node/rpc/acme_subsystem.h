// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_header_map.h"
#include "ccf/http_status.h"
#include "ccf/node/acme_subsystem_interface.h"
#include "ccf/rest_verb.h"
#include "ccf/service/node_info_network.h"
#include "http/http_parser.h"
#include "node/rpc/node_interface.h"

#include <optional>

namespace ccf
{
  class ACMESubsystem : public ACMESubsystemInterface
  {
  protected:
    AbstractNodeState& node_state;

  public:
    ACMESubsystem(AbstractNodeState& node_state_) : node_state(node_state_) {}

    virtual void install_challenge_handler(
      const ccf::NodeInfoNetwork::RpcInterfaceID& interface_id,
      std::shared_ptr<ACMEChallengeHandler> h) override
    {
      node_state.install_custom_acme_challenge_handler(interface_id, h);
    };

    virtual std::optional<const ccf::ACMEClientConfig*> config(
      const NodeInfoNetwork::RpcInterfaceID& id) override
    {
      const auto& acme_cfgs =
        node_state.get_node_config().network.acme->configurations;
      const auto& cfgit = acme_cfgs.find(id);
      if (cfgit == acme_cfgs.end())
      {
        return std::nullopt;
      }
      else
      {
        return &cfgit->second;
      }
    }

    virtual crypto::Pem network_cert() override
    {
      return node_state.get_network_cert();
    }

    // make_http_request is just a convenient way to offer https requests to
    // custom challenge handlers. This will be removed in the future, when there
    // are other, equally convenient ways.
    virtual void make_http_request(
      const std::string& method,
      const std::string& url,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body,
      std::function<bool(
        const http_status&,
        const http::HeaderMap&,
        const std::vector<uint8_t>&)> callback,
      const std::vector<std::string>& ca_certs = {},
      ccf::ApplicationProtocol app_protocol = ccf::ApplicationProtocol::HTTP1,
      bool use_node_client_certificate = false) override
    {
      llhttp_method_t m = http_method_from_str(method.c_str());
      http::URL urlobj = http::parse_url_full(url);
      http::Request r(urlobj.path, m);
      if (!body.empty())
      {
        r.set_body(&body);
      }
      for (const auto& [k, v] : headers)
      {
        r.set_header(k, v);
      }
      node_state.make_http_request(
        urlobj,
        std::move(r),
        callback,
        ca_certs,
        app_protocol,
        use_node_client_certificate);
    }
  };
}
