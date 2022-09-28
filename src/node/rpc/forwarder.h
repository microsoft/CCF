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

    virtual void process_forwarded(
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

    using ForwardedCommandId = ForwardedHeader_v2::ForwardedCommandId;
    ForwardedCommandId next_command_id = 0;
    std::unordered_map<ForwardedCommandId, threading::Task::TimerEntry>
      timeout_tasks;
    ccf::pal::Mutex timeout_tasks_lock;

    using IsCallerCertForwarded = bool;

    struct SendTimeoutErrorMsg
    {
      SendTimeoutErrorMsg(
        Forwarder<ChannelProxy>* forwarder_,
        const ccf::NodeId& to_,
        size_t client_session_id_,
        const std::chrono::milliseconds& timeout_) :
        forwarder(forwarder_),
        to(to_),
        client_session_id(client_session_id_),
        timeout(timeout_)
      {}

      Forwarder<ChannelProxy>* forwarder;
      ccf::NodeId to;
      size_t client_session_id;
      std::chrono::milliseconds timeout;
    };

    std::unique_ptr<threading::Tmsg<SendTimeoutErrorMsg>>
    create_timeout_error_task(
      const ccf::NodeId& to,
      size_t client_session_id,
      const std::chrono::milliseconds& timeout)
    {
      return std::make_unique<threading::Tmsg<SendTimeoutErrorMsg>>(
        [](std::unique_ptr<threading::Tmsg<SendTimeoutErrorMsg>> msg) {
          msg->data.forwarder->send_timeout_error_response(
            msg->data.to, msg->data.client_session_id, msg->data.timeout);
        },
        this,
        to,
        client_session_id,
        timeout);
    }

    void send_timeout_error_response(
      NodeId to,
      size_t client_session_id,
      const std::chrono::milliseconds& timeout)
    {
      auto rpc_responder_shared = rpcresponder.lock();
      if (rpc_responder_shared)
      {
        auto response = http::Response(HTTP_STATUS_GATEWAY_TIMEOUT);
        auto body = fmt::format(
          "Request was forwarded to node {}, but no response was received "
          "after {}ms",
          to,
          timeout.count());
        response.set_body(body);
        response.set_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        rpc_responder_shared->reply_async(
          client_session_id, response.build_response());
      }
    }

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
      const std::vector<uint8_t>& caller_cert,
      const std::chrono::milliseconds& timeout) override
    {
      IsCallerCertForwarded include_caller = false;
      const auto method = rpc_ctx->get_method();
      const auto& raw_request = rpc_ctx->get_serialised_request();
      auto client_session_id =
        rpc_ctx->get_session_context()->client_session_id;
      size_t size = sizeof(client_session_id) + sizeof(IsCallerCertForwarded) +
        raw_request.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> plain(size);
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, client_session_id);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, raw_request.data(), raw_request.size());

      ForwardedCommandId command_id;
      {
        std::lock_guard<ccf::pal::Mutex> guard(timeout_tasks_lock);
        command_id = next_command_id++;
        timeout_tasks[command_id] =
          threading::ThreadMessaging::thread_messaging.add_task_after(
            create_timeout_error_task(to, client_session_id, timeout), timeout);
      }

      ForwardedHeader_v2 msg = {
        {ForwardedMsg::forwarded_cmd_v2, rpc_ctx->frame_format()}, command_id};

      return n2n_channels->send_encrypted(
        to, NodeMsgType::forwarded_msg, plain, msg);
    }

    template <typename TFwdHdr>
    std::shared_ptr<http::HttpRpcContext> recv_forwarded_command(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      std::pair<TFwdHdr, std::vector<uint8_t>> r;
      try
      {
        LOG_TRACE_FMT("Receiving forwarded command of {} bytes", size);
        LOG_TRACE_FMT(" => {:02x}", fmt::join(data, data + size, ""));

        r = n2n_channels->template recv_encrypted<TFwdHdr>(from, data, size);
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

    template <typename TFwdHdr>
    bool send_forwarded_response(
      size_t client_session_id,
      const NodeId& from_node,
      const TFwdHdr& header,
      const std::vector<uint8_t>& data)
    {
      std::vector<uint8_t> plain(sizeof(client_session_id) + data.size());
      auto data_ = plain.data();
      auto size_ = plain.size();
      serialized::write(data_, size_, client_session_id);
      serialized::write(data_, size_, data.data(), data.size());

      return n2n_channels->send_encrypted(
        from_node, NodeMsgType::forwarded_msg, plain, header);
    }

    using ForwardedResponseResult =
      std::optional<std::pair<size_t, std::vector<uint8_t>>>;

    template <typename TFwdHdr>
    ForwardedResponseResult recv_forwarded_response(
      const NodeId& from, const uint8_t* data, size_t size)
    {
      std::pair<TFwdHdr, std::vector<uint8_t>> r;
      try
      {
        LOG_TRACE_FMT("Receiving response of {} bytes", size);
        LOG_TRACE_FMT(" => {:02x}", fmt::join(data, data + size, ""));

        r = n2n_channels->template recv_encrypted<TFwdHdr>(from, data, size);
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

    std::shared_ptr<ForwardedRpcHandler> get_forwarder_handler(
      const std::shared_ptr<http::HttpRpcContext>& ctx)
    {
      if (ctx == nullptr)
      {
        LOG_FAIL_FMT("Failed to receive forwarded command");
        return nullptr;
      }

      std::shared_ptr<ccf::RPCMap> rpc_map_shared = rpc_map.lock();
      if (rpc_map_shared == nullptr)
      {
        LOG_FAIL_FMT("Failed to obtain RPCMap");
        return nullptr;
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
        LOG_FAIL_FMT("Failed to process forwarded command: unknown actor");
        LOG_DEBUG_FMT(
          "Failed to process forwarded command: unknown actor {}", actor_s);
        return nullptr;
      }

      auto fwd_handler =
        std::dynamic_pointer_cast<ForwardedRpcHandler>(handler.value());
      if (!fwd_handler)
      {
        LOG_FAIL_FMT(
          "Failed to process forwarded command: handler is not a "
          "ForwardedRpcHandler");
        return nullptr;
      }

      return fwd_handler;
    }

    void recv_message(const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      try
      {
        const auto forwarded_hdr_v1 =
          serialized::peek<ForwardedHeader_v1>(data, size);
        const auto forwarded_msg = forwarded_hdr_v1.msg;
        LOG_TRACE_FMT(
          "recv_message({}, {} bytes) (type={})",
          from,
          size,
          (size_t)forwarded_msg);

        switch (forwarded_msg)
        {
          case ForwardedMsg::forwarded_cmd_v1:
          {
            auto ctx =
              recv_forwarded_command<ForwardedHeader_v1>(from, data, size);

            auto fwd_handler = get_forwarder_handler(ctx);
            if (fwd_handler == nullptr)
            {
              return;
            }

            // frame_format is deliberately unset, the forwarder ignores it
            // and expects the same format they forwarded.
            ForwardedHeader_v1 response_header{
              ForwardedMsg::forwarded_response_v1};

            LOG_DEBUG_FMT("Sending forwarded response to {}", from);
            fwd_handler->process_forwarded(ctx);

            // Ignore return value - false only means it is pending
            send_forwarded_response(
              ctx->get_session_context()->client_session_id,
              from,
              response_header,
              ctx->serialise_response());
            break;
          }

          case ForwardedMsg::forwarded_cmd_v2:
          {
            auto ctx =
              recv_forwarded_command<ForwardedHeader_v2>(from, data, size);

            auto fwd_handler = get_forwarder_handler(ctx);
            if (fwd_handler == nullptr)
            {
              return;
            }

            const auto forwarded_hdr_v2 =
              serialized::peek<ForwardedHeader_v2>(data, size);
            const auto cmd_id = forwarded_hdr_v2.id;

            // frame_format is deliberately unset, the forwarder ignores it
            // and expects the same format they forwarded.
            ForwardedHeader_v2 response_header{
              {ForwardedMsg::forwarded_response_v2, {}}, cmd_id};

            LOG_DEBUG_FMT("Sending forwarded response to {}", from);
            fwd_handler->process_forwarded(ctx);

            // Ignore return value - false only means it is pending
            send_forwarded_response(
              ctx->get_session_context()->client_session_id,
              from,
              response_header,
              ctx->serialise_response());
            break;
          }

          case ForwardedMsg::forwarded_response_v2:
          {
            const auto forwarded_hdr_v2 =
              serialized::peek<ForwardedHeader_v2>(data, size);
            const auto cmd_id = forwarded_hdr_v2.id;

            // Cancel and delete the corresponding timeout task, so it will no
            // longer trigger a timeout error
            std::lock_guard<ccf::pal::Mutex> guard(timeout_tasks_lock);
            auto it = timeout_tasks.find(cmd_id);
            if (it != timeout_tasks.end())
            {
              threading::ThreadMessaging::thread_messaging.cancel_timer_task(
                it->second);
              it = timeout_tasks.erase(it);
            }
            else
            {
              LOG_FAIL_FMT(
                "Response for {} received too late - already sent timeout "
                "error to client",
                cmd_id);
              return;
            }
            // Deliberate fall-through
          }

          case ForwardedMsg::forwarded_response_v1:
          {
            ForwardedResponseResult rep;
            if (forwarded_msg == ForwardedMsg::forwarded_response_v2)
            {
              rep =
                recv_forwarded_response<ForwardedHeader_v2>(from, data, size);
            }
            else
            {
              rep =
                recv_forwarded_response<ForwardedHeader_v1>(from, data, size);
            }

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