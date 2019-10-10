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

  class Forwarder : public enclave::AbstractForwarder
  {
  private:
    std::shared_ptr<enclave::AbstractRPCResponder> rpcresponder;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    NodeId self;

    using IsCallerForwarded = bool;

  public:
    Forwarder(
      std::shared_ptr<enclave::AbstractRPCResponder> rpcresponder,
      std::shared_ptr<NodeToNode> n2n_channels,
      std::shared_ptr<enclave::RPCMap> rpc_map_) :
      rpcresponder(rpcresponder),
      n2n_channels(n2n_channels),
      rpc_map(rpc_map_)
    {}

    void initialize(NodeId self_)
    {
      self = self_;
    }

    bool forward_command(
      enclave::RPCContext& rpc_ctx,
      NodeId from,
      NodeId to,
      CallerId caller_id,
      const std::vector<uint8_t>& data,
      const CBuffer& caller = nullb)
    {
      IsCallerForwarded include_caller = false;
      size_t size = sizeof(caller_id) + sizeof(rpc_ctx.client_session_id) +
        sizeof(rpc_ctx.actor) + sizeof(IsCallerForwarded) + data.size();
      if (caller != nullb)
      {
        size += sizeof(IsCallerForwarded) + sizeof(caller.n) + caller.n;
        include_caller = true;
      }

      std::vector<uint8_t> plain(size);
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, rpc_ctx.client_session_id);
      serialized::write(data_, size_, rpc_ctx.actor);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller.n);
        serialized::write(data_, size_, caller.p, caller.n);
      }
      serialized::write(data_, size_, data.data(), data.size());

      ForwardedHeader msg = {ForwardedMsg::forwarded_cmd, from};

      return n2n_channels->send_encrypted(to, plain, msg);
    }

    std::optional<std::tuple<enclave::RPCContext, NodeId, std::vector<uint8_t>>>
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

      std::optional<std::vector<uint8_t>> caller = std::nullopt;
      const auto& plain_ = plain;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto caller_id = serialized::read<CallerId>(data_, size_);
      auto client_session_id = serialized::read<size_t>(data_, size_);
      auto actor = serialized::read<ActorsType>(data_, size_);
      auto includes_caller = serialized::read<IsCallerForwarded>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller = serialized::read(data_, size_, caller_size);
      }
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);
      LOG_FAIL_FMT("Left to read: {}", size_);

      return std::make_tuple(
        enclave::RPCContext(client_session_id, caller_id, caller, actor),
        msg.from_node,
        std::move(rpc));
    }

    bool send_forwarded_response(
      size_t client_session_id,
      NodeId from_node,
      const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(sizeof(client_session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, client_session_id);
      serialized::write(data_, size_, data.data(), data.size());

      ForwardedHeader msg = {ForwardedMsg::forwarded_response, self};

      return n2n_channels->send_encrypted(from_node, plain, msg);
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
      serialized::skip(data, size, sizeof(NodeMsgType));

      auto forwarded_msg = serialized::peek<ForwardedMsg>(data, size);

      switch (forwarded_msg)
      {
        case ForwardedMsg::forwarded_cmd:
        {
          if (rpc_map)
          {
            auto r = recv_forwarded_command(data, size);
            if (!r.has_value())
              return;

            auto [ctx, from_node, request] = r.value();

            auto handler = rpc_map->find(ctx.actor);
            if (!handler.has_value())
              return;

            auto fwd_handler =
              dynamic_cast<ForwardedRpcHandler*>(handler.value().get());
            if (!fwd_handler)
              return;

            LOG_DEBUG_FMT("Forwarded RPC: {}", ctx.actor);

            if (!send_forwarded_response(
                  ctx.fwd->client_session_id,
                  from_node,
                  fwd_handler->process_forwarded(ctx, request)))
            {
              LOG_FAIL_FMT(
                "Could not send forwarded response to {}", from_node);
            }

            LOG_DEBUG_FMT("Sending forwarded response to {}", from_node);
          }
          break;
        }

        case ForwardedMsg::forwarded_response:
        {
          auto rep = recv_forwarded_response(data, size);
          if (!rep.has_value())
            return;

          LOG_DEBUG_FMT(
            "Sending forwarded response to RPC endpoint {}", rep->first);

          if (!rpcresponder->reply_async(rep->first, rep->second))
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