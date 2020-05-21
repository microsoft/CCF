// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/forwarder_types.h"
#include "enclave/rpc_map.h"
#include "http/http_rpc_context.h"
#include "node/node_to_node.h"

namespace ccf
{
  class ForwardedRpcHandler
  {
  public:
    virtual ~ForwardedRpcHandler() {}

    virtual std::vector<uint8_t> process_forwarded(
      std::shared_ptr<enclave::RpcContext> fwd_ctx) = 0;
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
      std::shared_ptr<enclave::RpcContext> rpc_ctx,
      NodeId to,
      CallerId caller_id,
      const std::vector<uint8_t>& caller_cert)
    {
      IsCallerCertForwarded include_caller = false;
      const auto method = rpc_ctx->get_method();
      const auto& raw_request = rpc_ctx->get_serialised_request();
      size_t size = sizeof(caller_id) +
        sizeof(rpc_ctx->session->client_session_id) +
        sizeof(IsCallerCertForwarded) + raw_request.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> plain(size);
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, rpc_ctx->session->client_session_id);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, raw_request.data(), raw_request.size());

      ForwardedHeader msg = {
        ForwardedMsg::forwarded_cmd, self, rpc_ctx->frame_format()};

      return n2n_channels->send_encrypted(
        NodeMsgType::forwarded_msg, to, plain, msg);
    }

    std::optional<std::tuple<std::shared_ptr<enclave::RpcContext>, NodeId>>
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
      auto includes_caller =
        serialized::read<IsCallerCertForwarded>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      std::vector<uint8_t> raw_request = serialized::read(data_, size_, size_);

      auto session = std::make_shared<enclave::SessionContext>(
        client_session_id, caller_id, caller_cert);

      try
      {
        auto context = enclave::make_fwd_rpc_context(
          session, raw_request, r.first.frame_format);
        return std::make_tuple(context, r.first.from_node);
      }
      catch (const std::exception& err)
      {
        LOG_FAIL_FMT("Invalid forwarded request: {}", err.what());
        return std::nullopt;
      }
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

      // frame_format is deliberately unset, the forwarder ignores it
      // and expects the same format they forwarded.
      ForwardedHeader msg = {ForwardedMsg::forwarded_response, self};

      return n2n_channels->send_encrypted(
        NodeMsgType::forwarded_msg, from_node, plain, msg);
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
            {
              LOG_FAIL_FMT("Failed to receive forwarded command");
              return;
            }

            auto [ctx, from_node] = std::move(r.value());

            const auto actor_opt = http::extract_actor(*ctx);
            if (!actor_opt.has_value())
            {
              LOG_FAIL_FMT(
                "Failed to extract actor from forwarded context. Method is "
                "'{}'",
                ctx->get_method());
            }

            const auto& actor_s = actor_opt.value();
            auto actor = rpc_map->resolve(actor_s);
            auto handler = rpc_map->find(actor);
            if (actor == ccf::ActorsType::unknown || !handler.has_value())
            {
              LOG_FAIL_FMT(
                "Failed to process forwarded command: unknown actor {}",
                actor_s);
              return;
            }

            auto fwd_handler =
              dynamic_cast<ForwardedRpcHandler*>(handler.value().get());
            if (!fwd_handler)
            {
              LOG_FAIL_FMT(
                "Failed to process forwarded command: handler is not a "
                "ForwardedRpcHandler");
              return;
            }

            if (!send_forwarded_response(
                  ctx->session->original_caller->client_session_id,
                  from_node,
                  fwd_handler->process_forwarded(ctx)))
            {
              LOG_FAIL_FMT(
                "Could not send forwarded response to {}", from_node);
            }
            else
            {
              LOG_DEBUG_FMT("Sending forwarded response to {}", from_node);
            }
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