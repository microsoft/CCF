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

      LOG_DEBUG_FMT("PBFT exec_command() for frontend {}", request.actor);

      auto handler = this->rpc_map->find(ccf::ActorsType(request.actor));
      if (!handler.has_value())
        throw std::logic_error(
          "No frontend associated with actor " + std::to_string(request.actor));

      auto frontend = handler.value();

      const enclave::SessionContext session(
        enclave::InvalidSessionId, request.caller_id, request.caller_cert);
      auto ctx = enclave::make_rpc_context(
        session, request.raw, {req_start, req_start + req_size});
      ctx->actor = (ccf::ActorsType)request.actor;
      const auto n = ctx->method.find_last_of('/');
      ctx->method = ctx->method.substr(n + 1, ctx->method.size());

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