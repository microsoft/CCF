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

    ExecCommand exec_command = [this](
                                 Byz_req* inb,
                                 Byz_rep& outb,
                                 _Byz_buffer* non_det,
                                 int client,
                                 Request_id rid,
                                 bool ro,
                                 uint8_t* req_start,
                                 size_t req_size,
                                 Seqno total_requests_executed,
                                 ByzInfo& info,
                                 ccf::Store::Tx* tx = nullptr) {
      pbft::Request request;
      request.deserialise({inb->contents, inb->contents + inb->size});
      const enclave::SessionContext session(
        enclave::InvalidSessionId, request.caller_id, request.caller_cert);
      LOG_FAIL_FMT("About to make RPC context");
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
      const auto actor = this->rpc_map->resolve(actor_s);
      auto handler = this->rpc_map->find(actor);
      if (!handler.has_value())
        throw std::logic_error(
          fmt::format("No frontend associated with actor {}", actor_s));

      auto frontend = handler.value();

      LOG_DEBUG_FMT("PBFT exec_command() for frontend {}", actor_s);

      ctx->signed_request = ccf::SignedReq();

      enclave::RpcHandler::ProcessPbftResp rep;
      if (tx != nullptr)
      {
        rep = frontend->process_pbft(ctx, *tx, true, info.include_merkle_roots);
      }
      else
      {
        rep = frontend->process_pbft(ctx, info.include_merkle_roots);
      }

      static_assert(
        sizeof(info.full_state_merkle_root) == sizeof(crypto::Sha256Hash));
      static_assert(
        sizeof(info.replicated_state_merkle_root) ==
        sizeof(crypto::Sha256Hash));
      if (info.include_merkle_roots)
      {
        std::copy(
          std::begin(rep.full_state_merkle_root.h),
          std::end(rep.full_state_merkle_root.h),
          std::begin(info.full_state_merkle_root));
        std::copy(
          std::begin(rep.replicated_state_merkle_root.h),
          std::end(rep.replicated_state_merkle_root.h),
          std::begin(info.replicated_state_merkle_root));
      }
      info.ctx = rep.version;

      outb.contents = message_receive_base->create_response_message(
        client, rid, rep.result.size());

      outb.size = rep.result.size();
      auto outb_ptr = (uint8_t*)outb.contents;
      size_t outb_size = (size_t)outb.size;

      serialized::write(
        outb_ptr, outb_size, rep.result.data(), rep.result.size());

      return 0;
    };
  };
}