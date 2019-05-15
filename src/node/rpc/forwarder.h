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

    bool forward(
      enclave::RpcContext& rpc_ctx,
      NodeId from,
      NodeId to,
      CallerId caller_id,
      const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(
        sizeof(caller_id) + sizeof(rpc_ctx.session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, rpc_ctx.session_id);
      serialized::write(data_, size_, data.data(), data.size());

      FrontendHeader msg = {FrontendMsg::forwarded_cmd, from};

      LOG_FAIL << "Sending forwarded cmd" << std::endl;
      return n2n_channels->send_encrypted(to, plain, msg);
    }

    // TODO: Move definition of FwdContext to forwarder.h and maybe enhance it?
    bool send_forwarded_response(
      const FwdContext& fwd_ctx, NodeId from, const std::vector<uint8_t>& data)
    {

      // TODO: Use fwd_ctx.caller_id for something?
      std::vector<uint8_t> plain(sizeof(fwd_ctx.session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, fwd_ctx.session_id);
      serialized::write(data_, size_, data.data(), data.size());

      FrontendHeader msg = {FrontendMsg::forwarded_reply, from};

      LOG_FAIL << "node2node: send forwarded response" << std::endl;
      return n2n_channels->send_encrypted(fwd_ctx.forwarder_id, plain, msg);
    }

    void recv_message(const uint8_t* data, size_t size)
    {
      serialized::skip(data, size, sizeof(ccf::NodeMsgType));

      auto frontend_msg = serialized::peek<ccf::FrontendMsg>(data, size);

      switch (frontend_msg)
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

          rpcsessions.reply_forwarded(rep.first, rep.second);
          break;
        }

        default:
        {
          LOG_FAIL << "Unknown frontend msg type: " << frontend_msg
                   << std::endl;
          break;
        }
      }
    }
  };
}