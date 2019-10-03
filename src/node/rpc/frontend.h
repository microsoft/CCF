// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consts.h"
#include "ds/buffer.h"
#include "ds/histogram.h"
#include "ds/json_schema.h"
#include "enclave/rpchandler.h"
#include "forwarder.h"
#include "jsonrpc.h"
#include "metrics.h"
#include "node/certs.h"
#include "node/clientsignatures.h"
#include "node/consensustypes.h"
#include "node/nodes.h"
#include "nodeinterface.h"
#include "rpcexception.h"
#include "serialization.h"

#include <fmt/format_header_only.h>
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

    enum class Forwardable
    {
      CanForward,
      DoNotForward
    };

    struct RequestArgs
    {
      enclave::RPCContext& rpc_ctx;
      Store::Tx& tx;
      CallerId caller_id;
      const std::string& method;
      const nlohmann::json& params;
      const SignedReq& signed_request;
    };

  protected:
    Store& tables;

  private:
    using HandleFunction =
      std::function<std::pair<bool, nlohmann::json>(RequestArgs& args)>;

    using MinimalHandleFunction = std::function<std::pair<bool, nlohmann::json>(
      Store::Tx& tx, const nlohmann::json& params)>;

    using CallerKey = std::vector<uint8_t>;

    // TODO: replace with an lru map
    std::map<CallerId, tls::VerifierPtr> verifiers;

    struct Handler
    {
      HandleFunction func;
      ReadWrite rw;
      nlohmann::json params_schema;
      nlohmann::json result_schema;
      Forwardable forwardable;
    };

    Nodes* nodes;
    ClientSignatures* client_signatures;
    Certs* certs;
    std::optional<Handler> default_handler;
    std::unordered_map<std::string, Handler> handlers;
    kv::Consensus* consensus;
    std::shared_ptr<AbstractForwarder> cmd_forwarder;
    kv::TxHistory* history;

    size_t sig_max_tx = 1000;
    size_t tx_count = 0;
    std::chrono::milliseconds sig_max_ms = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    bool request_storing_disabled = false;
    metrics::Metrics metrics;

    void update_consensus()
    {
      if (consensus != tables.get_consensus().get())
      {
        consensus = tables.get_consensus().get();
      }
    }

    void update_history()
    {
      // TODO: removed for now because frontend needs access to history
      // during recovery, on RPC, when not primary. Can be changed back once
      // frontend calls into Consensus.
      // if (history == nullptr)
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
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_REQUEST,
            fmt::format("RPC payload is a not a valid object: {}", rpc.dump()));
      }
      catch (const std::exception& e)
      {
        return jsonrpc::error(
          jsonrpc::StandardErrorCodes::INVALID_REQUEST,
          fmt::format("Exception during unpack: {}", e.what()));
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
      enclave::RPCContext& ctx, Forwardable forwardable)
    {
      if (
        cmd_forwarder && forwardable == Forwardable::CanForward &&
        !ctx.fwd.has_value())
      {
        return {};
      }
      else
      {
        // If this frontend is not allowed to forward or the command has already
        // been forwarded, redirect to the current primary
        if ((nodes != nullptr) && (consensus != nullptr))
        {
          NodeId primary_id = consensus->primary();
          Store::Tx tx;
          auto nodes_view = tx.get_view(*nodes);
          auto info = nodes_view->get(primary_id);

          if (info)
          {
            return jsonrpc::error_response(
              ctx.req.seq_no,
              jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY,
              info->pubhost + ":" + info->rpcport);
          }
        }
        return jsonrpc::error_response(
          ctx.req.seq_no,
          jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY,
          "Not primary, primary unknown.");
      }
    }

  public:
    RpcFrontend(Store& tables_) : RpcFrontend(tables_, nullptr, nullptr) {}

    RpcFrontend(Store& tables_, ClientSignatures* client_sigs_, Certs* certs_) :
      tables(tables_),
      nodes(tables.get<Nodes>(Tables::NODES)),
      client_signatures(client_sigs_),
      certs(certs_),
      consensus(nullptr),
      history(nullptr)

    {
      auto get_commit = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto in = params.get<GetCommit::In>();

        kv::Version commit = in.commit.value_or(tables.commit_version());

        update_consensus();

        if (consensus != nullptr)
        {
          auto term = consensus->get_view(commit);
          return jsonrpc::success(GetCommit::Out{term, commit});
        }

        return jsonrpc::error(
          jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
          "Failed to get commit info from Consensus");
      };

      auto get_metrics = [this](Store::Tx& tx, const nlohmann::json& params) {
        auto result = metrics.get_metrics();
        return jsonrpc::success(result);
      };

      auto make_signature =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          update_history();

          if (history != nullptr)
          {
            history->emit_signature();
            return jsonrpc::success(true);
          }

          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "Failed to trigger signature");
        };

      auto get_primary_info =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          if ((nodes != nullptr) && (consensus != nullptr))
          {
            NodeId primary_id = consensus->primary();

            auto nodes_view = tx.get_view(*nodes);
            auto info = nodes_view->get(primary_id);

            if (info)
            {
              GetPrimaryInfo::Out out;
              out.primary_id = primary_id;
              out.primary_host = info->pubhost;
              out.primary_port = info->rpcport;
              return jsonrpc::success(out);
            }
          }

          return jsonrpc::error(
            jsonrpc::CCFErrorCodes::TX_PRIMARY_UNKNOWN, "Primary unknown.");
        };

      auto get_network_info =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          GetNetworkInfo::Out out;
          if (consensus != nullptr)
          {
            out.primary_id = consensus->primary();
          }

          auto nodes_view = tx.get_view(*nodes);
          nodes_view->foreach([&out](const NodeId& nid, const NodeInfo& ni) {
            if (ni.status == ccf::NodeStatus::TRUSTED)
            {
              out.nodes.push_back({nid, ni.pubhost, ni.rpcport});
            }
            return true;
          });

          return jsonrpc::success(out);
        };

      auto list_methods = [this](Store::Tx& tx, const nlohmann::json& params) {
        ListMethods::Out out;

        for (const auto& handler : handlers)
        {
          out.methods.push_back(handler.first);
        }

        std::sort(out.methods.begin(), out.methods.end());

        return jsonrpc::success(out);
      };

      auto get_schema = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto in = params.get<GetSchema::In>();

        const auto it = handlers.find(in.method);
        if (it == handlers.end())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format("Method {} not recognised", in.method));
        }

        const GetSchema::Out out{it->second.params_schema,
                                 it->second.result_schema};

        return jsonrpc::success(out);
      };

      install_with_auto_schema<GetCommit>(
        GeneralProcs::GET_COMMIT, get_commit, Read);
      install_with_auto_schema<void, GetMetrics::Out>(
        GeneralProcs::GET_METRICS, get_metrics, Read);
      install_with_auto_schema<void, bool>(
        GeneralProcs::MK_SIGN, make_signature, Write);
      install_with_auto_schema<void, GetPrimaryInfo::Out>(
        GeneralProcs::GET_PRIMARY_INFO, get_primary_info, Read);
      install_with_auto_schema<void, GetNetworkInfo::Out>(
        GeneralProcs::GET_NETWORK_INFO, get_network_info, Read);
      install_with_auto_schema<void, ListMethods::Out>(
        GeneralProcs::LIST_METHODS, list_methods, Read);
      install_with_auto_schema<GetSchema>(
        GeneralProcs::GET_SCHEMA, get_schema, Read);
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

    void set_cmd_forwarder(std::shared_ptr<AbstractForwarder> cmd_forwarder_)
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
     * @param params_schema JSON schema for params object in requests
     * @param result_schema JSON schema for result object in responses
     * @param forwardable Allow method to be forwarded to primary
     */
    void install(
      const std::string& method,
      HandleFunction f,
      ReadWrite rw,
      const nlohmann::json& params_schema = nlohmann::json::object(),
      const nlohmann::json& result_schema = nlohmann::json::object(),
      Forwardable forwardable = Forwardable::CanForward)
    {
      handlers[method] = {f, rw, params_schema, result_schema, forwardable};
    }

    void install(
      const std::string& method,
      HandleFunction f,
      ReadWrite rw,
      Forwardable forwardable)
    {
      install(
        method,
        f,
        rw,
        nlohmann::json::object(),
        nlohmann::json::object(),
        forwardable);
    }

    /** Install MinimalHandleFunction for method name
     *
     * For simple app methods which require minimal arguments, this creates a
     * wrapper to reduce handler complexity and repetition.
     *
     * @param method Method name
     * @param f Method implementation
     */
    template <typename... Ts>
    void install(const std::string& method, MinimalHandleFunction f, Ts&&... ts)
    {
      install(
        method,
        [f](RequestArgs& args) { return f(args.tx, args.params); },
        std::forward<Ts>(ts)...);
    }

    template <typename In, typename Out, typename F>
    void install_with_auto_schema(
      const std::string& method,
      F&& f,
      ReadWrite rw,
      Forwardable forwardable = Forwardable::CanForward)
    {
      auto params_schema = nlohmann::json::object();
      if constexpr (!std::is_same_v<In, void>)
      {
        params_schema = ds::json::build_schema<In>(method + "/params");
      }

      auto result_schema = nlohmann::json::object();
      if constexpr (!std::is_same_v<Out, void>)
      {
        result_schema = ds::json::build_schema<Out>(method + "/result");
      }

      install(
        method,
        std::forward<F>(f),
        rw,
        params_schema,
        result_schema,
        forwardable);
    }

    template <typename T, typename... Ts>
    void install_with_auto_schema(const std::string& method, Ts&&... ts)
    {
      install_with_auto_schema<typename T::In, typename T::Out>(
        method, std::forward<Ts>(ts)...);
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

    /** Process a serialised command with the associated RPC context
     *
     * If an RPC that requires writing to the kv store is processed on a
     * backup, the serialised RPC is forwarded to the current network primary.
     *
     * @param ctx Context for this RPC
     * @param input Serialised JSON RPC
     */
    std::vector<uint8_t> process(
      enclave::RPCContext& ctx, const std::vector<uint8_t>& input) override
    {
      Store::Tx tx;

      ctx.pack = detect_pack(input);
      if (!ctx.pack.has_value())
        return jsonrpc::pack(
          jsonrpc::error_response(
            0, jsonrpc::StandardErrorCodes::INVALID_REQUEST, "Empty request."),
          jsonrpc::Pack::Text);

      // Retrieve id of caller
      auto caller_id = valid_caller(tx, ctx.caller_cert);
      if (!caller_id.has_value())
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
            "No corresponding caller entry exists."),
          ctx.pack.value());
      }
      auto rpc = unpack_json(input, ctx.pack.value());

      if (!rpc.first)
        return jsonrpc::pack(rpc.second, ctx.pack.value());

      auto rpc_ = &rpc.second;
      SignedReq signed_request(rpc.second);
      if (rpc_->find(jsonrpc::SIG) != rpc_->end())
      {
        auto& req = rpc_->at(jsonrpc::REQ);

        if (!verify_client_signature(
              tx,
              ctx.caller_cert,
              caller_id.value(),
              *rpc_,
              ctx.fwd.has_value(),
              signed_request))
        {
          return jsonrpc::pack(
            jsonrpc::error_response(
              req.at(jsonrpc::ID),
              jsonrpc::CCFErrorCodes::INVALID_CLIENT_SIGNATURE,
              "Failed to verify client signature."),
            ctx.pack.value());
        }
        rpc_ = &req;
      }
      auto& unsigned_rpc = *rpc_;

#ifdef PBFT
      kv::TxHistory::RequestID reqid;

      update_history();
      size_t jsonrpc_id = unsigned_rpc[jsonrpc::ID];
      reqid = {caller_id.value(), ctx.client_session_id, jsonrpc_id};
      if (history)
      {
        if (!history->add_request(
              reqid, ctx.actor, caller_id.value(), ctx.caller_cert, input))
        {
          LOG_FAIL_FMT("Adding request {} failed", jsonrpc_id);
          return jsonrpc::pack(
            jsonrpc::error_response(
              jsonrpc_id,
              jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
              "PBFT could not process request."),
            ctx.pack.value());
        }
        tx.set_req_id(reqid);
        ctx.is_pending = true;
      }
      else
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            jsonrpc_id,
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "PBFT is not yet ready."),
          ctx.pack.value());
      }
      return {};
#else
      auto rep =
        process_json(ctx, tx, caller_id.value(), unsigned_rpc, signed_request);

      // If necessary, forward the RPC to the current primary
      if (!rep.has_value())
      {
        if (consensus != nullptr)
        {
          auto primary_id = consensus->primary();
          auto local_id = consensus->id();

          if (
            primary_id != NoNode &&
            cmd_forwarder->forward_command(
              ctx, local_id, primary_id, caller_id.value(), input))
          {
            // Indicate that the RPC has been forwarded to primary
            LOG_DEBUG_FMT("RPC forwarded to primary {}", primary_id);
            ctx.is_pending = true;
            return {};
          }
        }
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::CCFErrorCodes::RPC_NOT_FORWARDED,
            "RPC could not be forwarded to primary."),
          ctx.pack.value());
      }

      auto rv = jsonrpc::pack(rep.value(), ctx.pack.value());

      return rv;
#endif
    }

    /** Process a serialised command with the associated RPC context via PBFT
     *
     * @param ctx Context for this RPC
     * @param input Serialised JSON RPC
     */
    ProcessPbftResp process_pbft(
      enclave::RPCContext& ctx, const std::vector<uint8_t>& input) override
    {
      // TODO(#PBFT): Refactor this with process_forwarded().
      Store::Tx tx;
      crypto::Sha256Hash merkle_root;

      auto pack = detect_pack(input);
      if (!pack.has_value())
        return {jsonrpc::pack(
                  jsonrpc::error_response(
                    0,
                    jsonrpc::StandardErrorCodes::INVALID_REQUEST,
                    "Empty PBFT request."),
                  jsonrpc::Pack::Text),
                merkle_root};

      auto rpc = unpack_json(input, pack.value());
      if (!rpc.first)
        return {jsonrpc::pack(rpc.second, pack.value()), merkle_root};

      // Strip signature
      auto rpc_ = &rpc.second;
      SignedReq signed_request(rpc.second);
      if (rpc_->find(jsonrpc::SIG) != rpc_->end())
      {
        auto& req = rpc_->at(jsonrpc::REQ);
        rpc_ = &req;
      }
      auto& unsigned_rpc = *rpc_;
      bool has_updated_merkle_root = false;

      auto cb = [&merkle_root, &has_updated_merkle_root](
                  kv::TxHistory::ResultCallbackArgs args) -> bool {
        merkle_root = args.merkle_root;
        has_updated_merkle_root = true;
        return true;
      };
      history->register_on_result(cb);

      auto rep =
        process_json(ctx, tx, ctx.fwd->caller_id, unsigned_rpc, signed_request);

      history->clear_on_result();

      if (!has_updated_merkle_root)
      {
        merkle_root = history->get_root();
      }

      // TODO(#PBFT): Add RPC response to history based on Request ID
      // if (history)
      //   history->add_response(reqid, rv);

      return {jsonrpc::pack(rep.value(), pack.value()), merkle_root};
    }

    /** Process a serialised input forwarded from another node
     *
     * This function assumes that ctx contains the caller_id as read by the
     * forwarding backup.
     *
     * @param ctx Context for this forwarded RPC
     * @param input Serialised JSON RPC
     *
     * @return Serialised reply to send back to forwarder node
     */
    std::vector<uint8_t> process_forwarded(
      enclave::RPCContext& ctx, const std::vector<uint8_t>& input) override
    {
      if (!ctx.fwd.has_value())
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");

      Store::Tx tx;

      // For forwarded command, caller is empty and caller_id should be used
      // instead.
      CBuffer caller;

      update_consensus();
      ctx.fwd->primary_id = consensus->id();

      auto pack = detect_pack(input);
      if (!pack.has_value())
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::StandardErrorCodes::INVALID_REQUEST,
            "Empty forwarded request."),
          jsonrpc::Pack::Text);

      // If the RPC was forwarded, assume that the caller has already been
      // verified
      if (certs && ctx.fwd->caller_id == INVALID_ID)
      {
        return jsonrpc::pack(
          jsonrpc::error_response(
            0,
            jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
            "No corresponding caller entry exists (forwarded)."),
          pack.value());
      }

      auto rpc = unpack_json(input, pack.value());
      if (!rpc.first)
        return jsonrpc::pack(rpc.second, pack.value());

      // Unwrap signed request if necessary
      auto rpc_ = &rpc.second;
      SignedReq signed_request(rpc.second);

      if (rpc_->find(jsonrpc::SIG) != rpc_->end())
      {
        auto& req = rpc_->at(jsonrpc::REQ);
        rpc_ = &req;
      }
      auto& unsigned_rpc = *rpc_;

      auto rep =
        process_json(ctx, tx, ctx.fwd->caller_id, unsigned_rpc, signed_request);
      if (!rep.has_value())
      {
        // This should never be called when process_json is called with a
        // forwarded RPC context
        throw std::logic_error("Forwarded RPC cannot be forwarded");
      }

      return jsonrpc::pack(rep.value(), pack.value());
    }

    std::optional<nlohmann::json> process_json(
      enclave::RPCContext& ctx,
      Store::Tx& tx,
      CallerId caller_id,
      const nlohmann::json& rpc,
      const SignedReq& signed_request)
    {
      std::string method = rpc.at(jsonrpc::METHOD);
      ctx.req.seq_no = rpc.at(jsonrpc::ID);

      const auto rpc_version = rpc.at(jsonrpc::JSON_RPC);
      if (rpc_version != jsonrpc::RPC_VERSION)
      {
        return jsonrpc::error_response(
          ctx.req.seq_no,
          jsonrpc::StandardErrorCodes::INVALID_REQUEST,
          fmt::format(
            "Unexpected JSON-RPC version. Must be string \"{}\", received {}",
            jsonrpc::RPC_VERSION,
            rpc_version.dump()));
      }

      const auto params_it = rpc.find(jsonrpc::PARAMS);
      if (
        params_it != rpc.end() &&
        (!params_it->is_array() && !params_it->is_object()))
      {
        return jsonrpc::error_response(
          ctx.req.seq_no,
          jsonrpc::StandardErrorCodes::INVALID_REQUEST,
          fmt::format(
            "If present, parameters must be an array or object. Received: {}",
            params_it->dump()));
      }

      const auto& params =
        params_it == rpc.end() ? nlohmann::json(nullptr) : *params_it;

      Handler* handler = nullptr;
      auto search = handlers.find(method);
      if (search != handlers.end())
        handler = &search->second;
      else if (default_handler)
        handler = &*default_handler;
      else
        return jsonrpc::error_response(
          ctx.req.seq_no,
          jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
          method);

      update_consensus();
      update_history();

      bool is_primary = (consensus == nullptr) || consensus->is_primary();

      if (!is_primary)
      {
        switch (handler->rw)
        {
          case Read:
            break;

          case Write:
            return forward_or_redirect_json(ctx, handler->forwardable);
            break;

          case MayWrite:
            bool readonly = rpc.value(jsonrpc::READONLY, true);
            if (!readonly)
              return forward_or_redirect_json(ctx, handler->forwardable);
            break;
        }
      }

      auto func = handler->func;
      auto args =
        RequestArgs{ctx, tx, caller_id, method, params, signed_request};

      tx_count++;

      while (true)
      {
        try
        {
          auto tx_result = func(args);

          if (!tx_result.first)
            return jsonrpc::error_response(ctx.req.seq_no, tx_result.second);

          switch (tx.commit())
          {
            case kv::CommitSuccess::OK:
            {
              nlohmann::json result =
                jsonrpc::result_response(ctx.req.seq_no, tx_result.second);

              auto cv = tx.commit_version();
              if (cv == 0)
                cv = tx.get_read_version();
              if (cv == kv::NoVersion)
                cv = tables.current_version();
              result[COMMIT] = cv;
              if (consensus != nullptr)
              {
                result[TERM] = consensus->get_view();
                result[GLOBAL_COMMIT] = consensus->get_commit_seqno();

                if (
                  history && consensus->is_primary() &&
                  (cv % sig_max_tx == sig_max_tx / 2))
                  history->emit_signature();
              }

              return result;
            }

            case kv::CommitSuccess::CONFLICT:
              break;

            case kv::CommitSuccess::NO_REPLICATE:
              return jsonrpc::error_response(
                ctx.req.seq_no,
                jsonrpc::CCFErrorCodes::TX_FAILED_TO_REPLICATE,
                "Transaction failed to replicate.");
              break;
          }
        }
        catch (const RpcException& e)
        {
          return jsonrpc::error_response(
            ctx.req.seq_no,
            static_cast<jsonrpc::CCFErrorCodes>(e.error_id),
            e.msg);
        }
        catch (JsonParseError& e)
        {
          e.pointer_elements.push_back(jsonrpc::PARAMS);
          const auto err = fmt::format("At {}:\n\t{}", e.pointer(), e.what());
          return jsonrpc::error_response(
            ctx.req.seq_no, jsonrpc::StandardErrorCodes::PARSE_ERROR, err);
        }
        catch (const kv::KvSerialiserException& e)
        {
          // If serialising the committed transaction fails, there is no way to
          // recover safely (https://github.com/microsoft/CCF/issues/338).
          // Better to abort.
          LOG_FATAL_FMT(e.what());
        }
        catch (const std::exception& e)
        {
          return jsonrpc::error_response(
            ctx.req.seq_no,
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            e.what());
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
      SignedReq signed_request;
      return verify_client_signature(
        tx, caller, caller_id, full_rpc, is_forwarded, signed_request);
    }

    bool verify_client_signature(
      Store::Tx& tx,
      const CBuffer& caller,
      const CallerId& caller_id,
      const nlohmann::json& full_rpc,
      bool is_forwarded,
      SignedReq& signed_request)
    {
#ifdef HTTP
      return true; // TODO: use Authorize header
#endif

      if (!client_signatures)
        return false;

      signed_request = full_rpc;

      // If the RPC is forwarded, assume that the signature has already been
      // verified by the backup
      if (!is_forwarded)
      {
        auto v = verifiers.find(caller_id);
        if (v == verifiers.end())
        {
          CallerKey caller_cert(caller);
          verifiers.emplace(
            std::make_pair(caller_id, tls::make_verifier(caller_cert)));
        }
        if (!verifiers[caller_id]->verify(
              signed_request.req, signed_request.sig))
          return false;
      }

      // TODO(#important): Request should only be stored on the primary
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
      update_consensus();
      if ((consensus != nullptr) && consensus->is_primary())
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
