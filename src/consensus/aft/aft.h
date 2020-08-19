// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "aft_network.h"
#include "aft_types.h"
#include "ds/ccf_exception.h"
#include "impl/execution_utilities.h"
#include "impl/request_message.h"
#include "kv/kv_types.h"
#include "request.h"

namespace aft
{
  class aft : public kv::Consensus
  {
  public:
    aft(
      kv::NodeId id,
      const std::vector<uint8_t>& cert,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      pbft::RequestsMap& pbft_requests_map,
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
      INetwork::recv_message_cb cb = [this](OArray oa, kv::NodeId from) {
        this->state_machine->receive_message(std::move(oa), from);
      };

      INetwork::recv_message_ae_cb cb_ae =
        [this](OArray oa, AppendEntries ae, kv::NodeId from) {
          this->state_machine->receive_message(std::move(oa), ae, from);
        };

      network = std::make_shared<EnclaveNetwork>(id, n2n_channels, cb, cb_ae);
      state_machine = create_state_machine(
        id, cert, *store, network, rpc_map, pbft_requests_map);
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

    void recv_message(OArray&& oa) override
    {
      network->recv_message(std::move(oa));
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
        LOG_DEBUG_FMT(
          "AFT reply callback for {}, status {}", caller_rid, status);

        return rpc_sessions->reply_async(std::get<1>(caller_rid), data);
      };

      auto ctx = ExecutionUtilities::create_request_ctx(
        serialized_req.data(), serialized_req.size(), rpc_map);

      auto request_message = std::make_unique<RequestMessage>(
        std::move(serialized_req), args.rid, std::move(ctx), rep_cb);

      state_machine->receive_request(std::move(request_message));
      return true;
    }
    void periodic(std::chrono::milliseconds) override
    {
    }
    void periodic_end() override
    {
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
  };
}