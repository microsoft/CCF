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

  template <typename ChannelProxy>
  class Forwarder : public enclave::AbstractForwarder
  {
  private:
    std::shared_ptr<enclave::AbstractRPCResponder> rpcresponder;
    std::shared_ptr<ChannelProxy> n2n_channels;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    NodeId self;

    using IsCallerCertForwarded = bool;

  public:
    Forwarder(
      std::shared_ptr<enclave::AbstractRPCResponder> rpcresponder,
      std::shared_ptr<ChannelProxy> n2n_channels,
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
      NodeId to,
      CallerId caller_id,
      const std::vector<uint8_t>& data,
      const std::vector<uint8_t>& caller_cert)
    {
      IsCallerCertForwarded include_caller = false;
      size_t size = sizeof(caller_id) + sizeof(rpc_ctx.client_session_id) +
        sizeof(rpc_ctx.actor) + sizeof(IsCallerCertForwarded) + data.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
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
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, data.data(), data.size());

      ForwardedHeader msg = {ForwardedMsg::forwarded_cmd, self};

      return n2n_channels->send_encrypted(to, plain, msg);
    }

    std::optional<std::tuple<enclave::RPCContext, NodeId, std::vector<uint8_t>>>
    recv_forwarded_command(const uint8_t* data, size_t size)
    {
      std::pair<ForwardedHeader, std::vector<uint8_t>> r;
      try
      {
        r = n2n_channels->template recv_encrypted<ForwardedHeader>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Invalid forwarded command: {}", err.what());
        return {};
      }

      std::vector<uint8_t> caller_cert;
      const auto& plain_ = r.second;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto caller_id = serialized::read<CallerId>(data_, size_);
      auto client_session_id = serialized::read<size_t>(data_, size_);
      auto actor = serialized::read<ActorsType>(data_, size_);
      auto includes_caller =
        serialized::read<IsCallerCertForwarded>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return std::make_tuple(
        enclave::RPCContext(client_session_id, caller_id, actor, caller_cert),
        r.first.from_node,
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
      std::pair<ForwardedHeader, std::vector<uint8_t>> r;
      try
      {
        r = n2n_channels->template recv_encrypted<ForwardedHeader>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Invalid forwarded response: {}", err.what());
        return {};
      }

      const auto& plain_ = r.second;
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