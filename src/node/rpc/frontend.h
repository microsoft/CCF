// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consts.h"
#include "ds/buffer.h"
#include "enclave/rpchandler.h"
#include "forwarder.h"
#include "jsonrpc.h"
#include "metrics.h"
#include "node/certs.h"
#include "node/clientsignatures.h"
#include "node/consensus.h"
#include "node/nodes.h"
#include "nodeinterface.h"
#include "rpcexception.h"
#include "serialization.h"

#include <utility>
#include <vector>

namespace ccf
{
  class RpcFrontend : public enclave::RpcHandler, public ForwardedRpcHandler
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
    ClientSignatures* client_signatures;
    Certs* certs;
    std::optional<Handler> default_handler;
    std::unordered_map<std::string, Handler> handlers;
    Consensus* raft;
    std::shared_ptr<Forwarder> cmd_forwarder;
    kv::TxHistory* history;
    size_t sig_max_tx = 1000;
    size_t tx_count = 0;
    std::chrono::milliseconds sig_max_ms = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    bool request_storing_disabled = false;
    metrics::Metrics metrics;

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

    std::optional<nlohmann::json> forward_or_redirect_json(
      jsonrpc::SeqNo id, bool is_forwarded = false)
    {
      if (cmd_forwarder && !is_forwarded)
      {
        return {};
      }
      else
      {
        // If this frontend is not allowed to forward or the command has already
        // been forwarded, redirect to the current leader
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
          id,
          jsonrpc::ErrorCodes::TX_NOT_LEADER,
          "Not leader, leader unknown.");
      }
    }

  public:
    RpcFrontend(Store& tables_) : RpcFrontend(tables_, nullptr, nullptr) {}

    RpcFrontend(Store& tables_, ClientSignatures* client_sigs_, Certs* certs_) :
      tables(tables_),
      nodes(tables.get<Nodes>(Tables::NODES)),
      client_signatures(client_sigs_),
      certs(certs_),
      raft(nullptr),
      history(nullptr)
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

      auto get_metrics = [this](Store::Tx& tx, const nlohmann::json& params) {
        auto result = metrics.get_metrics();
        return jsonrpc::success(GetMetrics::Out{result});
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
      install(GeneralProcs::GET_METRICS, get_metrics, Read);
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

    void set_cmd_forwarder(std::shared_ptr<Forwarder> cmd_forwarder_)
    {
      cmd_forwarder = cmd_forwarder_;
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

    /** Process a serialised command with the associated caller certificate
     *
     * If a RPC that requires writing to the kv store is processed on a
     * follower, the serialised RPC is forwarded to the current network leader.
     *
     * @param rpc_ctx Context for this RPC
     * @param input Serialised JSON RPC
     */
    std::vector<uint8_t> process(
      enclave::RpcContext& rpc_ctx, const std::vector<uint8_t>& input) override
    {
      Store::Tx tx;

      auto pack = detect_pack(input);
      if (!pack.has_value())
        return jsonrpc::pack(
          jsonrpc::error_response(
            0, jsonrpc::ErrorCodes::INVALID_REQUEST, "Empty request."),
          jsonrpc::Pack::Text);

      // Retrieve id of caller
      auto caller_id = valid_caller(tx, rpc_ctx.caller);
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

      auto rep =
        process_json(tx, rpc_ctx.caller, caller_id.value(), rpc.second, false);

      // If necessary, forward the RPC to the current leader
      if (!rep.has_value())
      {
        auto leader_id = raft->leader();
        auto local_id = raft->id();

        if (
          leader_id != NoNode &&
          !cmd_forwarder->forward_command(
            rpc_ctx, local_id, leader_id, caller_id.value(), input))
        {
          return jsonrpc::pack(
            jsonrpc::error_response(
              rep->at(jsonrpc::ID),
              jsonrpc::ErrorCodes::RPC_NOT_FORWARDED,
              "RPC could not be forwarded to leader."),
            pack.value());
        }
        else
        {
          // Indicate that the RPC has been forwarded to leader
          LOG_DEBUG << "RPC forwarded to leader " << leader_id << std::endl;
          rpc_ctx.is_forwarded = true;
          return {};
        }
      }

      return jsonrpc::pack(rep.value(), pack.value());
    }

    /** Process a serialised input that has been forwarded from another node
     *
     * This function assumes that fwd_ctx contains the caller_id as read by the
     * forwarding follower.
     *
     * @param fwd_ctx Context for this forwarded RPC
     * @param input Serialised JSON RPC
     *
     * @return Serialised reply to send back to forwarder node
     */
    std::vector<uint8_t> process_forwarded(
      FwdContext& fwd_ctx, const std::vector<uint8_t>& input) override
    {
      Store::Tx tx;

      // For forwarded command, caller is empty and caller_id should be used
      // instead.
      CBuffer caller;

      update_raft();
      fwd_ctx.leader_id = raft->id();

      // If the RPC was forwarded, assume that the caller has already been
      // verified
      if (fwd_ctx.caller_id == INVALID_ID)
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::ErrorCodes::INVALID_CALLER_ID,
            "No corresponding caller entry exists (forwarded)."),
          jsonrpc::Pack::Text);
      }

      auto pack = detect_pack(input);
      if (!pack.has_value())
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::ErrorCodes::INVALID_REQUEST,
            "Empty forwarded request."),
          jsonrpc::Pack::Text);

      auto rpc = unpack_json(input, pack.value());
      if (!rpc.first)
        return jsonrpc::pack(rpc.second, pack.value());

      auto rep = process_json(tx, caller, fwd_ctx.caller_id, rpc.second, true);
      if (!rep.has_value())
      {
        // This should never be called when process_json is called with
        // is_forwarded = True
        throw std::logic_error("Forwarded RPC cannot be forwarded");
      }

      return jsonrpc::pack(rep.value(), pack.value());
    }

    std::optional<nlohmann::json> process_json(
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
            return forward_or_redirect_json(id, is_forwarded);
            break;

          case MayWrite:
            bool readonly = rpc.value(jsonrpc::READONLY, true);
            if (!readonly)
              return forward_or_redirect_json(id, is_forwarded);
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

    void tick(std::chrono::milliseconds elapsed) override
    {
      metrics.track_tx_rates(elapsed, tx_count);
      // reset tx_counter for next tick interval
      tx_count = 0;
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
