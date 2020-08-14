// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "request.h"
#include "aft_types.h"
#include "impl/request_message.h"
#include "aft_network.h"

namespace aft
{
  class aft : public kv::Consensus
  {
  public:
    aft(
      kv::NodeId id,
      const std::vector<uint8_t>& cert,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::unique_ptr<IStore> store_,
      std::unique_ptr<consensus::LedgerEnclave> ledger_,
      std::shared_ptr<ccf::NodeToNode> n2n_channels) :
      Consensus(id),
      rpc_sessions(rpc_sessions_),
      rpc_map(rpc_map_),
      store(std::move(store_)),
      ledger(std::move(ledger_))
    {
      network = std::make_shared<EnclaveNetwork>(id, n2n_channels);
      state_machine = create_state_machine(id, cert, *store, network);
    }
    virtual ~aft() = default;

    bool replicate(const kv::BatchVector& entries, View /*view*/) override
    {
      for (auto& [index, data, globally_committable] : entries)
      {
        ledger->put_entry(*data, globally_committable);
      }
      return true;
    }

    std::pair<View, SeqNo> get_committed_txid() override
    {
      throw ccf::ccf_logic_error("Not implemented");
    }

    View get_view(SeqNo seqno) override
    {
      return state_machine->get_view_for_version(seqno);
    }

    View get_view() override
    {
      return state_machine->view();
    }

    SeqNo get_committed_seqno() override
    {
      return state_machine->get_last_committed_version();
    }

    kv::NodeId primary() override
    {
      return state_machine->primary();
    }

    bool is_primary() override
    {
      return state_machine->is_primary();
    }

    bool is_backup() override
    {
      return !state_machine->is_primary();
    }

    INetwork::recv_message_cb cb =
      [this](OArray&& oa, kv::NodeId id) {
        this->state_machine->receive_message(std::move(oa), id);
      };

    void recv_message(OArray&& oa) override
    {
      network->recv_message(std::move(oa), cb);
    }

    void add_configuration(
      SeqNo /*seqno*/, const Configuration::Nodes& config) override
    {
      if (config.size() != 1)
      {
        throw std::logic_error(
          "PBFT configuration should add one node at a time");
      }

      auto new_node_id = config.begin()->first;
      auto new_node_info = config.begin()->second;

      if (new_node_id == local_id)
      {
        return;
      }

      state_machine->add_node(new_node_id, new_node_info.cert.raw());
      LOG_INFO_FMT("PBFT added node, id: {}", new_node_id);
    }

    Configuration::Nodes get_latest_configuration() const override
    {
      throw ccf::ccf_logic_error("Not implemented");
    }

    void set_f(size_t f) override
    {
      LOG_INFO_FMT("Attempting to open network with f set to {}", f);
      state_machine->attempt_to_open_network();
    }
    void emit_signature() override
    {
      //throw ccf::ccf_logic_error("Not implemented");
    }
    ConsensusType type() override
    {
      return ConsensusType::AFT;
    }

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args) override
    {
      Request request = {
        args.caller_id, args.caller_cert, args.request, {}, args.frame_format};
      auto serialized_req = request.serialise();

      auto rep_cb = [&](
                      void* /*owner*/,
                      kv::TxHistory::RequestID caller_rid,
                      int status,
                      std::vector<uint8_t>& data) {
        LOG_DEBUG_FMT("AFT reply callback for {}, status {}", caller_rid, status);

        return rpc_sessions->reply_async(std::get<1>(caller_rid), data);
      };

      auto ctx = create_request_ctx(serialized_req.data(), serialized_req.size());

      auto request_message = std::make_unique<RequestMessage>(
        std::move(serialized_req),
        args.rid,
        std::move(ctx),
        rep_cb
      );

      state_machine->receive_request(std::move(request_message));
      return true;
    }
    void periodic(std::chrono::milliseconds) override
    {
      //throw ccf::ccf_logic_error("Not implemented");
    }
    void periodic_end() override
    {
      //throw ccf::ccf_logic_error("Not implemented");
    }
    Statistics get_statistics() override
    {
      return Statistics();
    }
    void enable_all_domains() override
    {
      throw ccf::ccf_logic_error("Not implemented");
    }

  private:
    std::unique_ptr<IStateMachine> state_machine;
    std::shared_ptr<enclave::RPCSessions> rpc_sessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::unique_ptr<IStore> store;
    std::unique_ptr<consensus::LedgerEnclave> ledger;
    std::shared_ptr<EnclaveNetwork> network;

    std::unique_ptr<RequestCtx> create_request_ctx(
      uint8_t* req_start, size_t req_size)
    {
      auto r_ctx = std::make_unique<RequestCtx>();
      Request request;
      request.deserialise(req_start, req_size);

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
      return r_ctx;
    };
  };

}