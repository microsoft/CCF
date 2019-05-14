// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpcsessions.h"
#include "node/nodetonode.h"

namespace ccf
{
  class Forwarder
  {
  private:
    enclave::RPCSessions& rpcsessions;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<enclave::RpcMap> rpc_map;

  public:
    Forwarder(
      enclave::RPCSessions& rpcsessions,
      std::shared_ptr<NodeToNode> n2n_channels) :
      rpcsessions(rpcsessions),
      n2n_channels(n2n_channels)
    {}

    void initialize(std::shared_ptr<enclave::RpcMap> rpc_map_)
    {
      rpc_map = rpc_map_;
    }

    void recv_message(const uint8_t* data, size_t size)
    {
      serialized::skip(data, size, sizeof(ccf::NodeMsgType));

      switch (serialized::peek<ccf::FrontendMsg>(data, size))
      {
        case ccf::FrontendMsg::forwarded_cmd:
        {
          if (rpc_map)
          {
            LOG_DEBUG << "Forwarded RPC: " << ccf::Actors::USERS << std::endl;
            rpc_map->at(std::string(ccf::Actors::USERS))
              ->process_forwarded(data, size);
          }
          break;
        }

        case ccf::FrontendMsg::forwarded_reply:
        {
          LOG_DEBUG << "Forwarded RPC reply" << std::endl;

          auto rep = n2n_channels->recv_forwarded_response(data, size);

          LOG_FAIL << "Sending forwarded response to session" << rep.first
                   << std::endl;

          // TODO: Find sessions in rpcsessions and reply to client
          rpcsessions.reply_forwarded(rep.first, rep.second);
          break;
        }

        default:
        {
          LOG_FAIL << "Unknown frontend msg type" << std::endl;
          break;
        }
      }
    }
  };
}