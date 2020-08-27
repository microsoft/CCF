// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/pbft/libbyz/libbyz.h"
#include "ds/ccf_assert.h"
#include "enclave/rpc_handler.h"
#include "enclave/rpc_map.h"
#include "pbft_deps.h"

namespace pbft
{
  struct RequestCtxImpl : public RequestCtx
  {
    std::shared_ptr<enclave::RpcContext> ctx;
    std::shared_ptr<enclave::RpcHandler> frontend;
    bool does_exec_gov_req;

    std::shared_ptr<enclave::RpcContext> get_rpc_context() override
    {
      return ctx;
    }
    std::shared_ptr<enclave::RpcHandler> get_rpc_handler() override
    {
      return frontend;
    }
    bool get_does_exec_gov_req() override
    {
      return does_exec_gov_req;
    }
  };

  class AbstractPbftConfig
  {
  public:
    static char* service_mem;
    virtual ~AbstractPbftConfig() = default;
    virtual void set_service_mem(char* sm) = 0;
    virtual void set_receiver(IMessageReceiveBase* message_receive_base_) = 0;
    virtual ExecCommand get_exec_command() = 0;
    virtual VerifyAndParseCommand get_verify_command() = 0;
  };

  class PbftConfigCcf : public AbstractPbftConfig
  {
    static constexpr uint32_t max_update_merkle_tree_interval = 50;
    static constexpr uint32_t min_update_merkle_tree_interval = 10;

  public:
    PbftConfigCcf(
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<pbft::PbftStore> store_) :
      rpc_map(rpc_map_),
      store(store_)
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

    VerifyAndParseCommand get_verify_command() override
    {
      return verify_and_parse;
    }

  private:
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<pbft::PbftStore> store;

    IMessageReceiveBase* message_receive_base;

    struct ExecutionCtx
    {
      ExecutionCtx(
        std::unique_ptr<ExecCommandMsg> msg_,
        ByzInfo& info_,
        PbftConfigCcf* self_,
        bool is_first_request_,
        uint64_t nonce_) :
        msg(std::move(msg_)),
        info(info_),
        self(self_),
        is_first_request(is_first_request_),
        did_exec_gov_req(false),
        nonce(nonce_)
      {}

      std::unique_ptr<ExecCommandMsg> msg;
      ByzInfo& info;
      kv::Version version;
      std::shared_ptr<enclave::RpcHandler> frontend;
      PbftConfigCcf* self;
      bool is_first_request;
      bool did_exec_gov_req;
      uint64_t nonce;
    };

    static void ExecuteCb(std::unique_ptr<threading::Tmsg<ExecutionCtx>> c)
    {
      ExecutionCtx& execution_ctx = c->data;
      ByzInfo& info = execution_ctx.info;
      std::shared_ptr<enclave::RpcHandler> frontend = execution_ctx.frontend;

      ExecCommandMsg& exec_msg = *execution_ctx.msg.get();

      info.ctx = execution_ctx.version;
      execution_ctx.msg->cb(exec_msg, info);

      --info.pending_cmd_callbacks;

      if (
        info.pending_cmd_callbacks %
            PbftConfigCcf::max_update_merkle_tree_interval ==
          0 ||
        info.pending_cmd_callbacks <
          PbftConfigCcf::min_update_merkle_tree_interval)
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

        info.did_exec_gov_req = execution_ctx.did_exec_gov_req;
        if (info.cb != nullptr)
        {
          info.cb(info.cb_ctx);
        }
      }
    }

    VerifyAndParseCommand verify_and_parse =
      [this](Byz_req* inb, uint8_t* req_start, size_t req_size) {
        auto r_ctx = std::make_unique<RequestCtxImpl>();
        pbft::Request request;
        request.deserialise((uint8_t*)inb->contents, inb->size);

        auto session = std::make_shared<enclave::SessionContext>(
          enclave::InvalidSessionId, request.caller_id, request.caller_cert);

        r_ctx->ctx = enclave::make_fwd_rpc_context(
          session, request.raw, (enclave::FrameFormat)request.frame_format);

        const auto actor_opt = http::extract_actor(*r_ctx->ctx);
        if (!actor_opt.has_value())
        {
          throw std::logic_error(fmt::format(
            "Failed to extract actor from PBFT request. Method is '{}'",
            r_ctx->ctx->get_method()));
        }

        const auto& actor_s = actor_opt.value();
        std::string preferred_actor_s;
        const auto actor = rpc_map->resolve(actor_s, preferred_actor_s);
        auto handler = rpc_map->find(actor);
        if (!handler.has_value())
          throw std::logic_error(
            fmt::format("No frontend associated with actor {}", actor_s));

        r_ctx->frontend = handler.value();
        r_ctx->does_exec_gov_req = r_ctx->frontend->is_members_frontend();

        return r_ctx;
      };

    static void Execute(std::unique_ptr<threading::Tmsg<ExecutionCtx>> c)
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
      kv::Tx* tx = msg->tx;

      std::unique_ptr<RequestCtx>& r_ctx = msg->request_ctx;
      msg->request_ctx->get_rpc_context()->pbft_raw = {req_start,
                                                       req_start + req_size};

      r_ctx->get_rpc_context()->is_create_request = c->data.is_first_request;
      r_ctx->get_rpc_context()->set_apply_writes(true);
      c->data.did_exec_gov_req =
        (r_ctx->get_does_exec_gov_req() || c->data.did_exec_gov_req);

      execution_ctx.frontend = r_ctx->get_rpc_handler();

      enclave::RpcHandler::ProcessPbftResp rep;
      if (tx != nullptr)
      {
        rep = execution_ctx.frontend->process_pbft(
          r_ctx->get_rpc_context(), *tx, true);
      }
      else
      {
        rep = execution_ctx.frontend->process_pbft(r_ctx->get_rpc_context());
      }
      execution_ctx.version = rep.version;

      outb.contents = self->message_receive_base->create_response_message(
        client, rid, rep.result.size(), execution_ctx.nonce);

      outb.size = rep.result.size();
      auto outb_ptr = (uint8_t*)outb.contents;
      size_t outb_size = (size_t)outb.size;

      serialized::write(
        outb_ptr, outb_size, rep.result.data(), rep.result.size());

      if (info.cb != nullptr)
      {
        threading::ThreadMessaging::thread_messaging
          .ChangeTmsgCallback<ExecutionCtx>(c, &ExecuteCb);
        threading::ThreadMessaging::thread_messaging.add_task(
          threading::ThreadMessaging::main_thread, std::move(c));
      }
      else
      {
        ExecuteCb(std::move(c));
      }
    };

    bool is_first_request = true;
    ExecCommand exec_command =
      [this](
        std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>&
          msgs,
        ByzInfo& info,
        uint32_t num_requests,
        uint64_t nonce,
        bool executed_single_threaded,
        View view) {
        info.pending_cmd_callbacks = num_requests;
        info.version_before_execution_start = store->current_version();
        // PBFT views start at 0, where Raft (and therefore CCF, historically)
        // starts at 2
        store->set_view(view + 2);
        for (uint32_t i = 0; i < num_requests; ++i)
        {
          std::unique_ptr<ExecCommandMsg>& msg = msgs[i];
          uint16_t reply_thread = msg->reply_thread;
          auto execution_ctx = std::make_unique<threading::Tmsg<ExecutionCtx>>(
            &Execute, std::move(msg), info, this, is_first_request, nonce);
          is_first_request = false;

          if (info.cb != nullptr)
          {
            int tid = reply_thread;
            if (executed_single_threaded && tid > 1)
            {
              tid = (threading::ThreadMessaging::thread_count - 1);
            }
            threading::ThreadMessaging::thread_messaging.add_task(
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