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

    using ForwardedCommandId = ForwardedHeader::ForwardedCommandId;
    ForwardedCommandId next_command_id = 0;
    // {cmd_id -> (node_id, client_session_id) }
    std::unordered_map<ForwardedCommandId, std::pair<NodeId, size_t>>
      active_commands;
    ccf::pal::Mutex active_commands_lock;

    using IsCallerCertForwarded = bool;

    struct SendTimeoutErrorMsg
    {
      SendTimeoutErrorMsg(
        Forwarder<ChannelProxy>* forwarder_, ForwardedCommandId cmd_id_) :
        forwarder(forwarder_),
        cmd_id(cmd_id_)
      {}

      Forwarder<ChannelProxy>* forwarder;
      ForwardedCommandId cmd_id;
    };

    std::unique_ptr<threading::Tmsg<SendTimeoutErrorMsg>>
    create_timeout_error_task(ForwardedCommandId cmd_id)
    {
      return std::make_unique<threading::Tmsg<SendTimeoutErrorMsg>>(
        [](std::unique_ptr<threading::Tmsg<SendTimeoutErrorMsg>> msg) {
          msg->data.forwarder->check_timeout_error(msg->data.cmd_id);
        },
        this,
        cmd_id);
    }

    void check_timeout_error(ForwardedCommandId cmd_id)
    {
      std::lock_guard<ccf::pal::Mutex> guard(active_commands_lock);
      auto command_it = active_commands.find(cmd_id);
      if (command_it != active_commands.end())
      {
        auto& [to, client_session_id] = command_it->second;
        LOG_INFO_FMT(
          "Request {} (from session) forwarded to node {} timed out",
          cmd_id,
          client_session_id,
          to);
        send_timeout_error_response(to, client_session_id);
        command_it = active_commands.erase(command_it);
      }
    }

    void send_timeout_error_response(NodeId to, size_t client_session_id)
    {
      auto rpc_responder_shared = rpcresponder.lock();
      if (rpc_responder_shared)
      {
        auto response = http::Response(HTTP_STATUS_GATEWAY_TIMEOUT);
        auto body = fmt::format(
          "Request was forwarded to node {}, but no response was received "
          "after {}ms",
          to,
          3000); // TODO: Pass through
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
      const std::vector<uint8_t>& caller_cert) override
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
        std::lock_guard<ccf::pal::Mutex> guard(active_commands_lock);
        command_id = next_command_id++;
        active_commands[command_id] = std::make_pair(to, client_session_id);

        threading::ThreadMessaging::thread_messaging.add_task_after(
          create_timeout_error_task(command_id),
          std::chrono::milliseconds(3'000)); // TODO: Make configurable
      }

      ForwardedHeader msg = {
        ForwardedMsg::forwarded_cmd, rpc_ctx->frame_format(), command_id};

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
      ForwardedHeader msg{
        ForwardedMsg::forwarded_response,
        {},
        0 // TODO
      };

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
        const auto forwarded_hdr =
          serialized::peek<ForwardedHeader>(data, size);
        const auto forwarded_msg = forwarded_hdr.msg;
        LOG_TRACE_FMT(
          "recv_message({}, {} bytes) (type={})",
          from,
          size,
          (size_t)forwarded_msg);

        switch (forwarded_msg)
        {
          case ForwardedMsg::forwarded_cmd:
          {
            {
              // Remove this request from active commands list, so it will no
              // longer trigger a timeout error
              std::lock_guard<ccf::pal::Mutex> guard(active_commands_lock);
              auto deleted = active_commands.erase(forwarded_hdr.id);
              if (deleted == 0)
              {
                LOG_FAIL_FMT(
                  "Response for {} received too late - already sent timeout "
                  "error to client",
                  forwarded_hdr.id);
                return;
              }
            }

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