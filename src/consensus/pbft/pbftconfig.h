// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/pbft/libbyz/libbyz.h"
#include "consensus/pbft/libbyz/pbft_assert.h"
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
    virtual ExecCommand get_exec_command() = 0;
    virtual size_t message_size() = 0;
  };

  struct ccf_req
  {
    uint64_t actor;
    uint64_t caller_id;
    std::vector<uint8_t> caller_cert;
    std::vector<uint8_t> request;

    std::vector<uint8_t> serialise()
    {
      bool include_caller = false;
      size_t size =
        sizeof(actor) + sizeof(caller_id) + sizeof(bool) + request.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> serialized_req(size);
      auto data_ = serialized_req.data();
      auto size_ = serialized_req.size();
      serialized::write(data_, size_, actor);
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, request.data(), request.size());

      return serialized_req;
    }

    void deserialise(const std::vector<uint8_t>& serialized_req)
    {
      auto data_ = serialized_req.data();
      auto size_ = serialized_req.size();

      actor = serialized::read<uint64_t>(data_, size_);
      caller_id = serialized::read<uint64_t>(data_, size_);
      auto includes_caller = serialized::read<bool>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      request = serialized::read(data_, size_, size_);
    }
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

    ExecCommand get_exec_command() override
    {
      return exec_command;
    }

    size_t message_size() override
    {
      return sizeof(ccf_req);
    }

  private:
    std::shared_ptr<enclave::RPCMap> rpc_map;

    ExecCommand exec_command = [this](
                                 Byz_req* inb,
                                 Byz_rep* outb,
                                 _Byz_buffer* non_det,
                                 int client,
                                 bool ro,
                                 Seqno total_requests_executed,
                                 ByzInfo& info) {
      ccf_req request;
      request.deserialise({inb->contents, inb->contents + inb->size});

      LOG_DEBUG_FMT("PBFT exec_command() for frontend {}", request.actor);

      auto handler = this->rpc_map->find(ccf::ActorsType(request.actor));
      if (!handler.has_value())
        throw std::logic_error(
          "No frontend associated with actor " + std::to_string(request.actor));

      auto frontend = handler.value();

      // TODO: Should serialise context directly, rather than reconstructing
      const enclave::SessionContext session(
        enclave::InvalidSessionId, request.caller_id, request.caller_cert);
      auto ctx = enclave::make_rpc_context(session, request.request);
      ctx.actor = (ccf::ActorsType)request.actor;
      const auto n = ctx.method.find_last_of('/');
      ctx.method = ctx.method.substr(n + 1, ctx.method.size());

      auto rep = frontend->process_pbft(ctx);

      static_assert(
        sizeof(info.full_state_merkle_root) == sizeof(crypto::Sha256Hash));
      static_assert(
        sizeof(info.replicated_state_merkle_root) ==
        sizeof(crypto::Sha256Hash));
      std::copy(
        std::begin(rep.full_state_merkle_root.h),
        std::end(rep.full_state_merkle_root.h),
        std::begin(info.full_state_merkle_root));
      std::copy(
        std::begin(rep.replicated_state_merkle_root.h),
        std::end(rep.replicated_state_merkle_root.h),
        std::begin(info.replicated_state_merkle_root));
      info.ctx = rep.version;

      outb->size = rep.result.size();
      auto outb_ptr = (uint8_t*)outb->contents;
      size_t outb_size = (size_t)outb->size;

      serialized::write(
        outb_ptr, outb_size, rep.result.data(), rep.result.size());

      return 0;
    };
  };
}