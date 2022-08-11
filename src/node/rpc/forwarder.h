// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/ccf_exception.h"
#include "enclave/forwarder_types.h"
#include "enclave/rpc_map.h"
#include "http/http_rpc_context.h"
#include "kv/kv_types.h"
#include "node/node_to_node.h"

namespace ccf
{
  class RpcContextImpl;

  class ForwardedRpcHandler
  {
  public:
    virtual ~ForwardedRpcHandler() {}

    virtual std::vector<uint8_t> process_forwarded(
      std::shared_ptr<ccf::RpcContextImpl> fwd_ctx) = 0;
  };

  template <typename ChannelProxy>
  class Forwarder : public AbstractForwarder
  {
  private:
    std::weak_ptr<ccf::AbstractRPCResponder> rpcresponder;
    std::shared_ptr<ChannelProxy> n2n_channels;
    std::weak_ptr<ccf::RPCMap> rpc_map;
    ConsensusType consensus_type;
    NodeId self;

    using IsCallerCertForwarded = bool;

  public:
    Forwarder(
      std::weak_ptr<ccf::AbstractRPCResponder> rpcresponder,
      std::shared_ptr<ChannelProxy> n2n_channels,
      std::weak_ptr<ccf::RPCMap> rpc_map_,
      ConsensusType consensus_type_) :
      rpcresponder(rpcresponder),
      n2n_channels(n2n_channels),
      rpc_map(rpc_map_),
      consensus_type(consensus_type_)
    {}

    void initialize(const NodeId& self_)
    {
      self = self_;
    }

    bool forward_command(
      std::shared_ptr<ccf::RpcContextImpl> rpc_ctx,
      const NodeId& to,
      const std::vector<uint8_t>& caller_cert) override
    {
      IsCallerCertForwarded include_caller = false;
      const auto method = rpc_ctx->get_method();
      const auto& raw_request = rpc_ctx->get_serialised_request();
      size_t size = sizeof(rpc_ctx->get_session_context()->client_session_id) +
        sizeof(IsCallerCertForwarded) + raw_request.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> plain(size);
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(
        data_, size_, rpc_ctx->get_session_context()->client_session_id);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, raw_request.data(), raw_request.size());

      ForwardedHeader msg = {
        ForwardedMsg::forwarded_cmd, rpc_ctx->frame_format()};

      return n2n_channels->send_encrypted(
        to, NodeMsgType::forwarded_msg, plain, msg);
    }

    std::shared_ptr<http::HttpRpcContext> recv_forwarded_command(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      std::pair<ForwardedHeader, std::vector<uint8_t>> r;
      try
      {
        LOG_TRACE_FMT("Receiving forwarded command of {} bytes", size);
        LOG_TRACE_FMT(" => {:02x}", fmt::join(data, data + size, ""));

        r = n2n_channels->template recv_encrypted<ForwardedHeader>(
          from, data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Invalid forwarded command");
        LOG_DEBUG_FMT("Invalid forwarded command: {}", err.what());
        return nullptr;
      }

      std::vector<uint8_t> caller_cert;
      const auto& plain_ = r.second;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto client_session_id = serialized::read<size_t>(data_, size_);
      auto includes_caller =
        serialized::read<IsCallerCertForwarded>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      std::vector<uint8_t> raw_request = serialized::read(data_, size_, size_);

      auto session =
        std::make_shared<ccf::SessionContext>(client_session_id, caller_cert);
      session->is_forwarded = true;

      try
      {
        return ccf::make_fwd_rpc_context(
          session, raw_request, r.first.frame_format);
      }
      catch (const std::exception& err)
      {
        LOG_FAIL_FMT("Invalid forwarded request");
        LOG_DEBUG_FMT("Invalid forwarded request: {}", err.what());
        return nullptr;
      }
    }

    bool send_forwarded_response(
      size_t client_session_id,
      const NodeId& from_node,
      const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(sizeof(client_session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, client_session_id);
      serialized::write(data_, size_, data.data(), data.size());

      // frame_format is deliberately unset, the forwarder ignores it
      // and expects the same format they forwarded.
      ForwardedHeader msg = {ForwardedMsg::forwarded_response};

      return n2n_channels->send_encrypted(
        from_node, NodeMsgType::forwarded_msg, plain, msg);
    }

    std::optional<std::pair<size_t, std::vector<uint8_t>>>
    recv_forwarded_response(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      std::pair<ForwardedHeader, std::vector<uint8_t>> r;
      try
      {
        LOG_TRACE_FMT("Receiving response of {} bytes", size);
        LOG_TRACE_FMT(" => {:02x}", fmt::join(data, data + size, ""));

        r = n2n_channels->template recv_encrypted<ForwardedHeader>(
          from, data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Invalid forwarded response");
        LOG_DEBUG_FMT("Invalid forwarded response: {}", err.what());
        return std::nullopt;
      }

      const auto& plain_ = r.second;
      auto data_ = plain_.data();
      auto size_ = plain_.size();
      auto client_session_id = serialized::read<size_t>(data_, size_);
      std::vector<uint8_t> rpc = serialized::read(data_, size_, size_);

      return std::make_pair(client_session_id, rpc);
    }

    void recv_message(const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      try
      {
        auto forwarded_msg = serialized::peek<ForwardedMsg>(data, size);
        LOG_TRACE_FMT(
          "recv_message({}, {} bytes) (type={})",
          from,
          size,
          (size_t)forwarded_msg);

        switch (forwarded_msg)
        {
          case ForwardedMsg::forwarded_cmd:
          {
            std::shared_ptr<ccf::RPCMap> rpc_map_shared = rpc_map.lock();
            if (rpc_map_shared)
            {
              auto ctx = recv_forwarded_command(from, data, size);
              if (ctx == nullptr)
              {
                LOG_FAIL_FMT("Failed to receive forwarded command");
                return;
              }

              const auto actor_opt = http::extract_actor(*ctx);
              if (!actor_opt.has_value())
              {
                LOG_FAIL_FMT("Failed to extract actor from forwarded context.");
                LOG_DEBUG_FMT(
                  "Failed to extract actor from forwarded context. Method is "
                  "'{}'",
                  ctx->get_method());
              }

              const auto& actor_s = actor_opt.value();
              auto actor = rpc_map_shared->resolve(actor_s);
              auto handler = rpc_map_shared->find(actor);
              if (actor == ccf::ActorsType::unknown || !handler.has_value())
              {
                LOG_FAIL_FMT(
                  "Failed to process forwarded command: unknown actor");
                LOG_DEBUG_FMT(
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

              // Ignore return value - false only means it is pending
              send_forwarded_response(
                ctx->get_session_context()->client_session_id,
                from,
                fwd_handler->process_forwarded(ctx));
              LOG_DEBUG_FMT("Sending forwarded response to {}", from);
            }
            break;
          }

          case ForwardedMsg::forwarded_response:
          {
            auto rep = recv_forwarded_response(from, data, size);
            if (!rep.has_value())
            {
              return;
            }

            LOG_DEBUG_FMT(
              "Sending forwarded response to RPC endpoint {}", rep->first);

            auto rpc_responder_shared = rpcresponder.lock();
            if (
              rpc_responder_shared &&
              !rpc_responder_shared->reply_async(
                rep->first, std::move(rep->second)))
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
      catch (const std::exception& e)
      {
        LOG_FAIL_EXC(e.what());
        return;
      }
    }
  };
}