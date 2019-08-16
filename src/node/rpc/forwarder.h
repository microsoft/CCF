// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/enclavetypes.h"
#include "enclave/rpcmap.h"
#include "node/nodetonode.h"

namespace ccf
{
  class ForwardedRpcHandler
  {
  public:
    virtual ~ForwardedRpcHandler() {}

    virtual std::vector<uint8_t> process_forwarded(
      enclave::RPCContext& fwd_ctx, const std::vector<uint8_t>& input) = 0;
  };

  class AbstractForwarder
  {
  public:
    virtual ~AbstractForwarder() {}

    virtual bool forward_command(
      enclave::RPCContext& rpc_ctx,
      NodeId from,
      NodeId to,
      CallerId caller_id,
      const std::vector<uint8_t>& data) = 0;
  };

  class Forwarder : public AbstractForwarder
  {
  private:
    enclave::AbstractRPCResponder& rpcresponder;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<enclave::RpcMap> rpc_map;

  public:
    Forwarder(
      enclave::AbstractRPCResponder& rpcresponder,
      std::shared_ptr<NodeToNode> n2n_channels) :
      rpcresponder(rpcresponder),
      n2n_channels(n2n_channels)
    {}

    void initialize(std::shared_ptr<enclave::RpcMap> rpc_map_)
    {
      rpc_map = rpc_map_;
    }

    bool forward_command(
      enclave::RPCContext& rpc_ctx,
      NodeId from,
      NodeId to,
      CallerId caller_id,
      const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(
        sizeof(caller_id) + sizeof(rpc_ctx.client_session_id) +
        sizeof(rpc_ctx.actor) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, rpc_ctx.client_session_id);
      serialized::write(data_, size_, rpc_ctx.actor);
      serialized::write(data_, size_, data.data(), data.size());

      ForwardedHeader msg = {ForwardedMsg::forwarded_cmd, from};

      return n2n_channels->send_encrypted(to, plain, msg);
    }

    std::optional<std::pair<enclave::RPCContext, std::vector<uint8_t>>>
    recv_forwarded_command(const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<ForwardedHeader>(data, size);
      if (msg.msg != ForwardedMsg::forwarded_cmd)
      {
        LOG_FAIL_FMT("Invalid forwarded message");
        return {};
      }

      std::vector<uint8_t> plain;
      try
      {
        plain = n2n_channels->recv_encrypted(msg, data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Invalid forwarded command: {}", err.what());
        return {};
      }

      const auto& plain_ = plain;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto caller_id = serialized::read<CallerId>(data_, size_);
      auto client_session_id = serialized::read<size_t>(data_, size_);
      auto actor = serialized::read<ccf::ActorsType>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return std::make_pair(
        enclave::RPCContext(client_session_id, msg.from_node, caller_id, actor),
        std::move(rpc));
    }

    bool send_forwarded_response(
      const enclave::RPCContext& ctx, const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(
        sizeof(ctx.fwd->client_session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, ctx.fwd->client_session_id);
      serialized::write(data_, size_, data.data(), data.size());

      ForwardedHeader msg = {ForwardedMsg::forwarded_response,
                             ctx.fwd->primary_id};

      return n2n_channels->send_encrypted(ctx.fwd->from, plain, msg);
    }

    std::optional<std::pair<size_t, std::vector<uint8_t>>>
    recv_forwarded_response(const uint8_t* data, size_t size)
    {
      const auto& msg = serialized::overlay<ForwardedHeader>(data, size);
      if (msg.msg != ForwardedMsg::forwarded_response)
      {
        LOG_FAIL_FMT("Invalid forwarded response message");
        return {};
      }

      std::vector<uint8_t> plain;
      try
      {
        plain = n2n_channels->recv_encrypted(msg, data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Invalid forwarded response: {}", err.what());
        return {};
      }

      const auto& plain_ = plain;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto client_session_id = serialized::read<size_t>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return std::make_pair(client_session_id, rpc);
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
            auto r = recv_forwarded_command(data, size);
            if (!r.has_value())
              return;

            auto handler = rpc_map->find(r->first.actor);
            if (!handler.has_value())
              return;

            auto fwd_handler =
              dynamic_cast<ccf::ForwardedRpcHandler*>(handler.value().get());
            if (!fwd_handler)
              return;

            LOG_DEBUG_FMT("Forwarded RPC: {}", r->first.actor);

            auto rep = fwd_handler->process_forwarded(r->first, r->second);

            if (!send_forwarded_response(r->first, rep))
            {
              LOG_FAIL_FMT(
                "Could not send forwarded response to {}", r->first.fwd->from);
            }

            LOG_DEBUG_FMT(
              "Sending forwarded response to {}", r->first.fwd->from);
          }
          break;
        }

        case ccf::ForwardedMsg::forwarded_response:
        {
          auto rep = recv_forwarded_response(data, size);
          if (!rep.has_value())
            return;

          LOG_DEBUG_FMT(
            "Sending forwarded response to RPC endpoint {}", rep->first);

          if (!rpcresponder.reply_async(rep->first, rep->second))
          {
            return;
          }

          break;
        }

        default:
        {
          LOG_FAIL_FMT("Unknown frontend msg type: {}", forwarded_msg);
          break;
        }
      }
    }
  };
}