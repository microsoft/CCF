// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/pbft/libbyz/libbyz.h"
#include "consensus/pbft/libbyz/pbft_assert.h"
#include "enclave/rpchandler.h"
#include "enclave/rpcmap.h"
#include "pbftdeps.h"

namespace pbft
{
  class AbstractPbftConfig
  {
  public:
    static char* service_mem;
    virtual ~AbstractPbftConfig() = default;
    virtual void set_service_mem(char* sm) = 0;
    virtual void set_receiver(IMessageReceiveBase* message_receive_base_) = 0;
    virtual ExecCommand get_exec_command() = 0;
  };

  class PbftConfigCcf : public AbstractPbftConfig
  {
    static constexpr uint32_t max_update_merkle_tree_interval = 50;

  public:
    PbftConfigCcf(std::shared_ptr<enclave::RPCMap> rpc_map_) : rpc_map(rpc_map_)
    {}

    ~PbftConfigCcf() = default;

    void set_service_mem(char* sm) override
    {
      service_mem = sm;
    }

    void set_receiver(IMessageReceiveBase* message_receive_base_) override
    {
      message_receive_base = message_receive_base_;
    }

    ExecCommand get_exec_command() override
    {
      return exec_command;
    }

  private:
    std::shared_ptr<enclave::RPCMap> rpc_map;

    IMessageReceiveBase* message_receive_base;

    struct ExecutionCtx
    {
      ExecutionCtx(
        std::unique_ptr<ExecCommandMsg> msg_,
        ByzInfo& info_,
        PbftConfigCcf* self_) :
        msg(std::move(msg_)),
        info(info_),
        self(self_)
      {}

      std::unique_ptr<ExecCommandMsg> msg;
      ByzInfo& info;
      std::shared_ptr<enclave::RpcHandler> frontend;
      PbftConfigCcf* self;
    };

    static void ExecuteCb(std::unique_ptr<enclave::Tmsg<ExecutionCtx>> c)
    {
      ExecutionCtx& execution_ctx = c->data;
      ByzInfo& info = execution_ctx.info;
      std::shared_ptr<enclave::RpcHandler> frontend = execution_ctx.frontend;

      execution_ctx.msg->cb(*execution_ctx.msg.get(), info);

      --info.pending_cmd_callbacks;

      if (
        info.pending_cmd_callbacks %
          PbftConfigCcf::max_update_merkle_tree_interval ==
        0)
      {
        try
        {
          frontend->update_merkle_tree();
        }
        catch (const std::exception& e)
        {
          LOG_TRACE_FMT("Failed to insert into merkle tree", e.what());
          abort();
        }
      }

      if (info.pending_cmd_callbacks == 0)
      {
        static_assert(
          sizeof(info.replicated_state_merkle_root) ==
          sizeof(crypto::Sha256Hash));
        crypto::Sha256Hash root = frontend->get_merkle_root();
        std::copy(
          std::begin(root.h),
          std::end(root.h),
          std::begin(info.replicated_state_merkle_root));

        if (info.cb != nullptr)
        {
          info.cb(info.cb_ctx);
        }
      }
    }

    static void Execute(std::unique_ptr<enclave::Tmsg<ExecutionCtx>> c)
    {
      ExecutionCtx& execution_ctx = c->data;
      std::unique_ptr<ExecCommandMsg>& msg = execution_ctx.msg;
      PbftConfigCcf* self = execution_ctx.self;
      ByzInfo& info = execution_ctx.info;

      Byz_req* inb = &msg->inb;
      Byz_rep& outb = msg->outb;
      int client = msg->client;
      Request_id rid = msg->rid;
      uint8_t* req_start = msg->req_start;
      size_t req_size = msg->req_size;
      Seqno total_requests_executed = msg->total_requests_executed;
      ccf::Store::Tx* tx = msg->tx;
      int replier = msg->replier;
      uint16_t reply_thread = msg->reply_thread;

      pbft::Request request;
      request.deserialise((uint8_t*)inb->contents, inb->size);

      auto session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, request.caller_id, request.caller_cert);

      auto ctx = enclave::make_rpc_context(
        session, request.raw, {req_start, req_start + req_size});

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error(fmt::format(
          "Failed to extract actor from PBFT request. Method is '{}'",
          ctx->get_method()));
      }

      const auto& actor_s = actor_opt.value();
      const auto actor = self->rpc_map->resolve(actor_s);
      auto handler = self->rpc_map->find(actor);
      if (!handler.has_value())
        throw std::logic_error(
          fmt::format("No frontend associated with actor {}", actor_s));

      auto frontend = handler.value();
      execution_ctx.frontend = frontend;

      enclave::RpcHandler::ProcessPbftResp rep;
      if (tx != nullptr)
      {
        rep = frontend->process_pbft(ctx, *tx, true);
      }
      else
      {
        rep = frontend->process_pbft(ctx);
      }
      info.ctx = rep.version;

      outb.contents = self->message_receive_base->create_response_message(
        client, rid, rep.result.size());

      outb.size = rep.result.size();
      auto outb_ptr = (uint8_t*)outb.contents;
      size_t outb_size = (size_t)outb.size;

      serialized::write(
        outb_ptr, outb_size, rep.result.data(), rep.result.size());

      if (info.cb != nullptr)
      {
        enclave::ThreadMessaging::thread_messaging
          .ChangeTmsgCallback<ExecutionCtx>(c, &ExecuteCb);
        enclave::ThreadMessaging::thread_messaging.add_task<ExecutionCtx>(
          enclave::ThreadMessaging::main_thread, std::move(c));
      }
      else
      {
        ExecuteCb(std::move(c));
      }
    };

    ExecCommand exec_command =
      [this](
        std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>&
          msgs,
        ByzInfo& info,
        uint32_t num_requests) {
        info.pending_cmd_callbacks = num_requests;
        for (uint32_t i = 0; i < num_requests; ++i)
        {
          std::unique_ptr<ExecCommandMsg>& msg = msgs[i];
          uint16_t reply_thread = msg->reply_thread;
          auto execution_ctx = std::make_unique<enclave::Tmsg<ExecutionCtx>>(
            &Execute, std::move(msg), info, this);

          if (info.cb != nullptr)
          {
            int tid = reply_thread;
            enclave::ThreadMessaging::thread_messaging.add_task<ExecutionCtx>(
              tid, std::move(execution_ctx));
          }
          else
          {
            Execute(std::move(execution_ctx));
          }
        }
        return 0;
      };
  };
};