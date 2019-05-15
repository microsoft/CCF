// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpcsessions.h"
#include "node/nodetonode.h"

namespace ccf
{
  struct FwdContext
  {
    size_t session_id;
    NodeId forwarder_id;
    CallerId caller_id;
  };

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

    bool forward_command(
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

      LOG_FAIL << "Sending forwarded command to " << to << std::endl;
      return n2n_channels->send_encrypted(to, plain, msg);
    }

    std::pair<FwdContext, std::vector<uint8_t>> recv_forwarded_command(
      const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<FrontendHeader>(data, size);
      if (msg.msg != forwarded_cmd)
        throw std::logic_error("Invalid forwarded command");

      const auto plain = n2n_channels->recv_encrypted(msg, data, size);
      if (!plain.has_value())
        throw std::logic_error("Forwarded command decryption failed");

      auto data_ = plain->data();
      auto size_ = plain->size();
      auto caller_id = serialized::read<CallerId>(data_, size_);
      auto session_id = serialized::read<size_t>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return {{session_id, msg.from_node, caller_id}, rpc};
    }

    bool send_forwarded_response(
      const FwdContext& fwd_ctx, NodeId from, const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(sizeof(fwd_ctx.session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, fwd_ctx.session_id);
      serialized::write(data_, size_, data.data(), data.size());

      FrontendHeader msg = {FrontendMsg::forwarded_reply, from};

      LOG_FAIL << "Sending forwarded response to " << fwd_ctx.forwarder_id
               << std::endl;
      return n2n_channels->send_encrypted(fwd_ctx.forwarder_id, plain, msg);
    }

    std::pair<size_t, std::vector<uint8_t>> recv_forwarded_response(
      const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<FrontendHeader>(data, size);

      const auto plain = n2n_channels->recv_encrypted(msg, data, size);
      if (!plain.has_value())
        throw std::logic_error("Forwarded response decryption failed");

      auto data_ = plain->data();
      auto size_ = plain->size();
      auto session_id = serialized::read<size_t>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return {session_id, rpc};
    }

    void recv_message(const uint8_t* data, size_t size)
    {
      serialized::skip(data, size, sizeof(ccf::NodeMsgType));

      auto frontend_msg = serialized::peek<ccf::FrontendMsg>(data, size);

      switch (frontend_msg)
      {
        case ccf::FrontendMsg::forwarded_cmd:
        {
          // TODO: All frontends should be able to forward/be forwarded to.
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
          std::pair<size_t, std::vector<uint8_t>> rep;

          try
          {
            rep = recv_forwarded_response(data, size);
          }
          catch (const std::exception& e)
          {
            LOG_FAIL << "Invalid forwarded response" << std::endl;
            break;
          }

          LOG_FAIL << "Sending forwarded response to session: " << rep.first
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