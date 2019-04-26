// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consts.h"
#include "ds/buffer.h"
#include "ds/histogram.h"
#include "enclave/rpchandler.h"
#include "jsonrpc.h"
#include "node/certs.h"
#include "node/clientsignatures.h"
#include "node/consensus.h"
#include "node/nodes.h"
#include "node/signatures.h"
#include "nodeinterface.h"
#include "rpcexception.h"
#include "serialization.h"

#include <utility>
#include <vector>

#define HIST_MAX (1 << 17)
#define HIST_MIN 1
#define HIST_BUCKET_GRANULARITY 5

namespace ccf
{
  class RpcFrontend : public enclave::RpcHandler
  {
  public:
    enum ReadWrite
    {
      Read,
      Write,
      MayWrite
    };

  protected:
    Store& tables;

    struct RequestArgs
    {
      Store::Tx& tx;
      CBuffer caller;
      CallerId caller_id;
      const std::string& method;
      const nlohmann::json& params;
    };

  private:
    using HandleFunction =
      std::function<std::pair<bool, nlohmann::json>(RequestArgs& args)>;

    using MinimalHandleFunction = std::function<std::pair<bool, nlohmann::json>(
      Store::Tx& tx, const nlohmann::json& params)>;

    using CallerKey = std::vector<uint8_t>;

    // TODO: replace with an lru map
    std::map<CallerId, std::shared_ptr<tls::Verifier>> verifiers;

    struct Handler
    {
      HandleFunction func;
      ReadWrite rw;
    };

    Nodes* nodes;
    Signatures* signatures;
    ClientSignatures* client_signatures;
    Certs* certs;
    std::optional<Handler> default_handler;
    std::unordered_map<std::string, Handler> handlers;
    Consensus* raft;
    std::shared_ptr<NodeToNode> n2n_channels;
    kv::TxHistory* history;
    size_t sig_max_tx = 1000;
    size_t tx_count = 0;
    using Hist =
      histogram::Histogram<int, HIST_MIN, HIST_MAX, HIST_BUCKET_GRANULARITY>;
    histogram::Global<Hist> global =
      histogram::Global<Hist>("histogram", __FILE__, __LINE__);
    Hist histogram = Hist(global);
    std::chrono::milliseconds sig_max_ms = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    bool can_forward;

    bool request_storing_disabled = false;

    void update_raft()
    {
      if (raft == nullptr)
      {
        auto replicator = tables.get_replicator();
        raft = dynamic_cast<Consensus*>(replicator.get());
      }
    }

    void update_history()
    {
      if (history == nullptr)
        history = tables.get_history().get();
    }

    std::pair<bool, nlohmann::json> unpack_json(
      const std::vector<uint8_t>& input, jsonrpc::Pack pack)
    {
      nlohmann::json rpc;
      try
      {
        rpc = jsonrpc::unpack(input, pack);
        if (!rpc.is_object())
          return {false,
                  jsonrpc::error_response(
                    jsonrpc::ErrorCodes::INVALID_REQUEST, "Non-object.")};
      }
      catch (const std::exception& e)
      {
        return {
          false,
          jsonrpc::error_response(
            jsonrpc::ErrorCodes::INVALID_REQUEST, "Exception during unpack.")};
      }

      return {true, rpc};
    }

    std::optional<CallerId> valid_caller(Store::Tx& tx, const CBuffer& caller)
    {
      if (certs == nullptr)
        return INVALID_ID;

      if (!caller.p)
        return {};

      auto certs_view = tx.get_view(*certs);
      auto caller_id = certs_view->get(std::vector<uint8_t>(caller));

      return caller_id;
    }

    nlohmann::json redirect_json(jsonrpc::SeqNo id, bool is_forwarded = false)
    {
#ifndef RPC_FORWARD_TO_LEADER
      if ((nodes != nullptr) && (raft != nullptr))
      {
        NodeId leader_id = raft->leader();
        Store::Tx tx;
        auto nodes_view = tx.get_view(*nodes);
        auto info = nodes_view->get(leader_id);

        if (info)
        {
          return jsonrpc::error_response(
            id,
            jsonrpc::ErrorCodes::TX_NOT_LEADER,
            info->pubhost + ":" + info->tlsport);
        }
      }

      return jsonrpc::error_response(
        id, jsonrpc::ErrorCodes::TX_NOT_LEADER, "Not leader, leader unknown.");
#else
      if (!is_forwarded && can_forward)
      {
        // If the RPC has not already been forwarded and the frontend is
        // allowed to forward, redirect it to the current leader
        return jsonrpc::error_response(
          id, jsonrpc::RPC_FORWARDED, "RPC forwarded to leader");
      }

      return jsonrpc::error_response(
        id,
        jsonrpc::ErrorCodes::RPC_NOT_FORWARDED,
        "RPC could not be forwarded to leader.");
#endif
    }

  public:
    RpcFrontend(Store& tables_, bool can_forward_) :
      RpcFrontend(tables_, nullptr, nullptr, can_forward_)
    {}

    RpcFrontend(
      Store& tables_,
      ClientSignatures* client_sigs_,
      Certs* certs_,
      bool can_forward_) :
      tables(tables_),
      nodes(tables.get<Nodes>(Tables::NODES)),
      signatures(tables.get<Signatures>(Tables::SIGNATURES)),
      client_signatures(client_sigs_),
      certs(certs_),
      raft(nullptr),
      history(nullptr),
      can_forward(can_forward_)
    {
      auto get_commit = [this](Store::Tx& tx, const nlohmann::json& params) {
        kv::Version commit;

        if (
          params.is_array() && (params.size() > 0) &&
          params[0].is_number_unsigned())
        {
          commit = params[0];
        }
        else
        {
          commit = tables.commit_version();
        }

        update_raft();

        if (raft != nullptr)
        {
          auto term = raft->get_term(commit);
          return jsonrpc::success(GetCommit::Out{term, commit});
        }

        return jsonrpc::error(
          jsonrpc::ErrorCodes::INTERNAL_ERROR,
          "Failed to get commit info from Raft");
      };

      auto get_tx_hist = [this](Store::Tx& tx, const nlohmann::json& params) {
        nlohmann::json result;
        nlohmann::json hist;
        result["low"] = histogram.get_low();
        result["high"] = histogram.get_high();
        result["overflow"] = histogram.get_overflow();
        result["underflow"] = histogram.get_underflow();
        auto range_counts = histogram.get_range_count();
        for (auto const& [range, count] : range_counts)
        {
          hist[range] = count;
        }
        result["histogram"] = hist;
        return jsonrpc::success(GetTxHist::Out{result});
      };

      auto make_signature =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          update_history();

          if (history != nullptr)
          {
            history->emit_signature();
            return jsonrpc::success();
          }

          return jsonrpc::error(
            jsonrpc::ErrorCodes::INTERNAL_ERROR, "Failed to trigger signature");
        };

      auto get_leader_info =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          if ((nodes != nullptr) && (raft != nullptr))
          {
            NodeId leader_id = raft->leader();
            nlohmann::json result;

            auto nodes_view = tx.get_view(*nodes);
            auto info = nodes_view->get(leader_id);

            if (info)
            {
              result["leader_id"] = leader_id;
              result["leader_host"] = info->pubhost;
              result["leader_port"] = info->tlsport;
              return jsonrpc::success(result);
            }
          }

          return jsonrpc::error(
            jsonrpc::ErrorCodes::TX_LEADER_UNKNOWN, "Leader unknown.");
        };

      install(GeneralProcs::GET_COMMIT, get_commit, Read);
      install(GeneralProcs::GET_TX_HIST, get_tx_hist, Read);
      install(GeneralProcs::MK_SIGN, make_signature, Write);
      install(GeneralProcs::GET_LEADER_INFO, get_leader_info, Read);
    }

    void disable_request_storing()
    {
      request_storing_disabled = true;
    }

    void set_sig_intervals(size_t sig_max_tx_, size_t sig_max_ms_)
    {
      sig_max_tx = sig_max_tx_;
      sig_max_ms = std::chrono::milliseconds(sig_max_ms_);
      ms_to_sig = sig_max_ms;
    }

    void set_n2n_channels(std::shared_ptr<NodeToNode> n2n_channels_)
    {
      n2n_channels = n2n_channels_;
    }

    /** Install HandleFunction for method name
     *
     * If an implementation is already installed for that method, it will be
     * replaced.
     *
     * @param method Method name
     * @param f Method implementation
     * @param rw Flag if method will Read, Write, MayWrite
     */
    void install(const std::string& method, HandleFunction f, ReadWrite rw)
    {
      handlers[method] = {f, rw};
    }

    /** Install MinimalHandleFunction for method name
     *
     * For simple app methods which require minimal arguments, this creates a
     * wrapper to reduce handler complexity and repetition.
     *
     * @param method Method name
     * @param f Method implementation
     * @param rw Flag if method will Read, Write, MayWrite
     */
    void install(
      const std::string& method, MinimalHandleFunction f, ReadWrite rw)
    {
      handlers[method] = {
        [f](RequestArgs& args) { return f(args.tx, args.params); }, rw};
    }

    /** Set a default HandleFunction
     *
     * The default HandleFunction is only invoked if no specific HandleFunction
     * was found.
     *
     * @param f Method implementation
     * @param rw Flag if method will Read, Write, MayWrite
     */
    void set_default(HandleFunction f, ReadWrite rw)
    {
      default_handler = {f, rw};
    }

    std::optional<jsonrpc::Pack> detect_pack(const std::vector<uint8_t>& input)
    {
      if (input.size() == 0)
        return {};

      if (input[0] == '{')
        return jsonrpc::Pack::Text;
      else
        return jsonrpc::Pack::MsgPack;
    }

    /** Process a serialised input with the associated caller certificate
     *
     * If a RPC that requires writing to the kv store is processed on a
     * follower, the serialised RPC is forwarded to the current network leader.
     *
     * @param caller Caller certificate
     * @param input Serialised JSON RPC
     */
    std::vector<uint8_t> process(
      CBuffer caller, const std::vector<uint8_t>& input) override
    {
      Store::Tx tx;

      auto pack = detect_pack(input);
      if (!pack.has_value())
        return jsonrpc::pack(
          jsonrpc::error_response(
            0, jsonrpc::ErrorCodes::INVALID_REQUEST, "Empty request."),
          jsonrpc::Pack::Text);

      // Retrieve id of caller
      auto caller_id = valid_caller(tx, caller);
      if (!caller_id.has_value())
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::ErrorCodes::INVALID_CALLER_ID,
            "No corresponding caller entry exists."),
          pack.value());
      }

      auto rpc = unpack_json(input, pack.value());
      if (!rpc.first)
        return jsonrpc::pack(rpc.second, pack.value());

      auto rep = process_json(tx, caller, caller_id.value(), rpc.second, false);

      // If necessary, redirect the RPC to the leader
      if (
        rep.find(jsonrpc::ERR) != rep.end() &&
        rep[jsonrpc::ERR][jsonrpc::CODE] == jsonrpc::RPC_FORWARDED)
      {
        // TODO(#important): If the RPC has been redirected, wait for the
        // reply from the leader before replying to the client
        auto leader_id = raft->leader();
        LOG_DEBUG << "RPC forwarded to leader " << leader_id << std::endl;

        if (
          leader_id != NoNode &&
          !n2n_channels->forward(leader_id, caller_id.value(), input))
        {
          return jsonrpc::pack(
            jsonrpc::error_response(
              rep[jsonrpc::ID],
              jsonrpc::ErrorCodes::RPC_NOT_FORWARDED,
              "RPC could not be forwarded to leader."),
            pack.value());
        }
      }

      return jsonrpc::pack(rep, pack.value());
    }

    /** Process a serialised input that has been forwarded from another node
     *
     * This function assumes that the forwarded message contains the caller id.
     *
     * @param data Pointer to forwarded serialised JSON RPC
     * @param size Size of forwarded serialised JSON RPC
     *
     * @return Serialised reply to send back to forwarder node
     */
    std::vector<uint8_t> process_forwarded(
      const uint8_t* data, size_t size) override
    {
      Store::Tx tx;

      // If the RPC was forwarded by another node, assume that the caller has
      // already been verified
      CBuffer caller;

      std::pair<CallerId, std::vector<uint8_t>> fwd;
      try
      {
        fwd = n2n_channels->recv_forwarded(data, size);
      }
      catch (const std::exception& e)
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::ErrorCodes::INTERNAL_ERROR,
            "Forwarded RPC is malformed."),
          jsonrpc::Pack::Text);
      }

      if (fwd.first == INVALID_ID)
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::ErrorCodes::INVALID_CALLER_ID,
            "No corresponding caller entry exists."),
          jsonrpc::Pack::Text);
      }

      auto pack = detect_pack(fwd.second);
      if (!pack.has_value())
        return jsonrpc::pack(
          jsonrpc::error_response(
            0, jsonrpc::ErrorCodes::INVALID_REQUEST, "Empty request."),
          jsonrpc::Pack::Text);

      auto rpc = unpack_json(fwd.second, pack.value());
      if (!rpc.first)
        return jsonrpc::pack(rpc.second, pack.value());

      // TODO(#important): For now, the return value of this function is
      // ignored. The JSON RPC result of the transaction execution
      // should be returned to the node that forwarded the RPC.
      auto rep = process_json(tx, caller, fwd.first, rpc.second, true);
      return jsonrpc::pack(rep, pack.value());
    }

    nlohmann::json process_json(
      Store::Tx& tx,
      const CBuffer& caller,
      CallerId caller_id,
      const nlohmann::json& full_rpc,
      bool is_forwarded = false)
    {
      auto rpc_ = &full_rpc;
      if (full_rpc.find(jsonrpc::SIG) != full_rpc.end())
      {
        // TODO(#important): Signature should only be verified for a Write
        // RPC
        if (!verify_client_signature(
              tx, caller, caller_id, full_rpc, is_forwarded))
        {
          return jsonrpc::error_response(
            full_rpc[jsonrpc::REQ][jsonrpc::ID],
            jsonrpc::ErrorCodes::INVALID_CLIENT_SIGNATURE,
            "Failed to verify client signature.");
        }
        rpc_ = &full_rpc[jsonrpc::REQ];
      }
      auto& rpc = *rpc_;

      if (rpc[jsonrpc::JSON_RPC] != jsonrpc::RPC_VERSION)
        return jsonrpc::error_response(
          rpc[jsonrpc::ID],
          jsonrpc::ErrorCodes::INVALID_REQUEST,
          "Wrong JSON-RPC version.");

      std::string method = rpc[jsonrpc::METHOD];
      jsonrpc::SeqNo id = rpc[jsonrpc::ID];

      const nlohmann::json params = rpc[jsonrpc::PARAMS];
      if (!params.is_array() && !params.is_object() && !params.is_null())
        return jsonrpc::error_response(
          id, jsonrpc::ErrorCodes::INVALID_REQUEST, "Invalid params.");

      Handler* handler = nullptr;
      auto search = handlers.find(method);
      if (search != handlers.end())
        handler = &search->second;
      else if (default_handler)
        handler = &*default_handler;
      else
        return jsonrpc::error_response(
          id, jsonrpc::ErrorCodes::METHOD_NOT_FOUND, method);

      update_raft();
      update_history();

      bool is_leader = (raft == nullptr) || raft->is_leader();

      if (!is_leader)
      {
        switch (handler->rw)
        {
          case Read:
            break;

          case Write:
            return redirect_json(id, is_forwarded);
            break;

          case MayWrite:
            bool readonly = rpc.value(jsonrpc::READONLY, true);
            if (!readonly)
              return redirect_json(id, is_forwarded);
            break;
        }
      }

      auto func = handler->func;
      auto args = RequestArgs{tx, caller, caller_id, method, params};

      tx_count++;

      while (true)
      {
        try
        {
          auto tx_result = func(args);

          if (!tx_result.first)
            return jsonrpc::error_response(id, tx_result.second);

          switch (tx.commit())
          {
            case kv::CommitSuccess::OK:
            {
              nlohmann::json result =
                jsonrpc::result_response(id, tx_result.second);

              auto cv = tx.commit_version();
              if (cv == 0)
                cv = tx.get_read_version();
              if (cv == kv::NoVersion)
                cv = tables.current_version();
              result[COMMIT] = cv;
              if (raft != nullptr)
              {
                result[TERM] = raft->get_term();
                result[GLOBAL_COMMIT] = raft->get_commit_idx();

                if (
                  history && raft->is_leader() &&
                  (cv % sig_max_tx == sig_max_tx / 2))
                  history->emit_signature();
              }

              return result;
            }

            case kv::CommitSuccess::CONFLICT:
              break;

            case kv::CommitSuccess::NO_REPLICATE:
              return jsonrpc::error_response(
                id,
                jsonrpc::ErrorCodes::TX_FAILED_TO_REPLICATE,
                "Transaction failed to replicate.");
              break;
          }
        }
        catch (const RpcException& e)
        {
          return jsonrpc::error_response(id, e.error_id, e.msg);
        }
        catch (const std::exception& e)
        {
          return jsonrpc::error_response(
            id, jsonrpc::ErrorCodes::INTERNAL_ERROR, e.what());
        }
      }
    }

    bool verify_client_signature(
      Store::Tx& tx,
      const CBuffer& caller,
      const CallerId& caller_id,
      const nlohmann::json& full_rpc,
      bool is_forwarded)
    {
      if (!client_signatures)
        return false;

      SignedReq signed_request(full_rpc);

#ifndef DISABLE_CLIENT_SIGNATURE_VERIFICATION
      // If the RPC is forwarded, assume that the signature has already been
      // verified by the follower
      if (!is_forwarded)
      {
        auto v = verifiers.find(caller_id);
        if (v == verifiers.end())
        {
          CallerKey key(caller);
          verifiers.emplace(
            std::make_pair(caller_id, std::make_shared<tls::Verifier>(key)));
        }
        if (!verifiers[caller_id]->verify(
              signed_request.req, signed_request.sig))
          return false;
      }
#endif

      // TODO(#important): Request should only be stored on the leader
      if (request_storing_disabled)
      {
        signed_request.req.clear();
      }
      auto client_sig_view = tx.get_view(*client_signatures);
      client_sig_view->put(caller_id, signed_request);
      return true;
    }

    std::optional<SignedReq> get_signed_req(const CallerId& caller_id)
    {
      Store::Tx tx;
      auto client_sig_view = tx.get_view(*client_signatures);
      return client_sig_view->get(caller_id);
    }

    void tick(
      std::chrono::system_clock::time_point now,
      std::chrono::milliseconds elapsed) override
    {
      // calculate how many tx/sec we have processed in this tick
      auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() /
        1000.0;
      auto tx_rate = tx_count / duration;
      // reset tx_counter for next tick interval
      tx_count = 0;
      histogram.record(tx_rate);

      // TODO(#refactoring): move this to NodeState::tick
      if ((raft != nullptr) && raft->is_leader())
      {
        if (elapsed < ms_to_sig)
        {
          ms_to_sig -= elapsed;
          return;
        }
        ms_to_sig = sig_max_ms;
        if (history && tables.commit_gap() > 0)
          history->emit_signature();
      }
    }
  };
}
