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
      // TODO:
      // 1. Create serialised plaintext
      // 2. Send frontendheader and plaintext and to to
      // n2n_channels->send_encrypted()

      // auto& n2n_channel = channels->get(to);
      // if (n2n_channel.get_status() != ChannelStatus::ESTABLISHED)
      // {
      //   established_channel(to);
      //   return false;
      // }

      std::vector<uint8_t> plain(
        sizeof(caller_id) + sizeof(rpc_ctx.session_id) + data.size());
      // std::vector<uint8_t> cipher(plain.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, rpc_ctx.session_id);
      serialized::write(data_, size_, data.data(), data.size());

      // GcmHdr hdr;
      FrontendHeader msg = {FrontendMsg::forwarded_cmd, from};
      // n2n_channel.encrypt(hdr, asCb(msg), plain, cipher);

      LOG_FAIL << "Sending forwarded cmd" << std::endl;
      return n2n_channels->send_encrypted(to, plain, msg);
      // to_host->write(
      //   node_outbound, to, NodeMsgType::frontend_msg, msg, hdr, cipher);
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