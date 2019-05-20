// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpcsessions.h"
#include "node/nodetonode.h"

namespace ccf
{
  struct FwdContext
  {
    const size_t session_id;
    const NodeId forwarder_id;
    const CallerId caller_id;

    NodeId leader_id;

    FwdContext(size_t session_id_, NodeId forwarder_id_, CallerId caller_id_) :
      session_id(session_id_),
      forwarder_id(forwarder_id_),
      caller_id(caller_id_)
    {}
  };

  class ForwardedRpcHandler
  {
  public:
    virtual ~ForwardedRpcHandler() {}

    virtual std::vector<uint8_t> process_forwarded(
      FwdContext& fwd_ctx, const std::vector<uint8_t>& input) = 0;
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

      ForwardedHeader msg = {ForwardedMsg::forwarded_cmd, from};

      return n2n_channels->send_encrypted(to, plain, msg);
    }

    std::optional<std::pair<FwdContext, std::vector<uint8_t>>>
    recv_forwarded_command(const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<ForwardedHeader>(data, size);
      if (msg.msg != ForwardedMsg::forwarded_cmd)
      {
        LOG_FAIL << "Invalid forwarded message" << std::endl;
        return {};
      }

      std::vector<uint8_t> plain;
      try
      {
        plain = n2n_channels->recv_encrypted(msg, data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL << "Invalid forwarded command: " << err.what() << std::endl;
        return {};
      }

      const auto& plain_ = plain;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto caller_id = serialized::read<CallerId>(data_, size_);
      auto session_id = serialized::read<size_t>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return std::make_pair(
        FwdContext(session_id, msg.from_node, caller_id), std::move(rpc));
    }

    bool send_forwarded_response(
      const FwdContext& fwd_ctx, const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(sizeof(fwd_ctx.session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, fwd_ctx.session_id);
      serialized::write(data_, size_, data.data(), data.size());

      ForwardedHeader msg = {ForwardedMsg::forwarded_response,
                             fwd_ctx.leader_id};

      return n2n_channels->send_encrypted(fwd_ctx.forwarder_id, plain, msg);
    }

    std::optional<std::pair<size_t, std::vector<uint8_t>>>
    recv_forwarded_response(const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<ForwardedHeader>(data, size);
      if (msg.msg != ForwardedMsg::forwarded_response)
      {
        LOG_FAIL << "Invalid forwarded response message" << std::endl;
        return {};
      }

      std::vector<uint8_t> plain;
      try
      {
        plain = n2n_channels->recv_encrypted(msg, data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL << "Invalid forwarded response: " << err.what() << std::endl;
        return {};
      }

      const auto& plain_ = plain;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto session_id = serialized::read<size_t>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return std::make_pair(session_id, rpc);
    }

    void recv_message(const uint8_t* data, size_t size)
    {
      serialized::skip(data, size, sizeof(ccf::NodeMsgType));

      auto forwarded_msg = serialized::peek<ccf::ForwardedMsg>(data, size);

      switch (forwarded_msg)
      {
        case ccf::ForwardedMsg::forwarded_cmd:
        {
          if (rpc_map)
          {
            LOG_DEBUG << "Forwarded RPC: " << ccf::Actors::USERS << std::endl;

            auto fwd = recv_forwarded_command(data, size);
            if (!fwd.has_value())
              return;

            auto fwd_handler = dynamic_cast<ccf::ForwardedRpcHandler*>(
              rpc_map->at(std::string(ccf::Actors::USERS)).get());

            auto rep = fwd_handler->process_forwarded(fwd->first, fwd->second);

            if (!send_forwarded_response(fwd->first, rep))
            {
              LOG_FAIL << "Could not send forwarded response to "
                       << fwd->first.forwarder_id << std::endl;
            }

            LOG_DEBUG << "Sending forwarded response to "
                      << fwd->first.forwarder_id << std::endl;
          }
          break;
        }

        case ccf::ForwardedMsg::forwarded_response:
        {
          auto rep = recv_forwarded_response(data, size);
          if (!rep.has_value())
            return;

          LOG_DEBUG << "Sending forwarded response to RPC endpoint "
                    << rep->first << std::endl;

          try
          {
            rpcsessions.reply_forwarded(rep->first, rep->second);
          }
          catch (const std::logic_error& err)
          {
            LOG_FAIL << err.what() << std::endl;
            return;
          }

          break;
        }

        default:
        {
          LOG_FAIL << "Unknown frontend msg type: " << forwarded_msg
                   << std::endl;
          break;
        }
      }
    }
  };
}