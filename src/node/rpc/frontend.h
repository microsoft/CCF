// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consts.h"
#include "ds/buffer.h"
#include "ds/histogram.h"
#include "ds/json_schema.h"
#include "ds/spinlock.h"
#include "enclave/rpchandler.h"
#include "forwarder.h"
#include "jsonrpc.h"
#include "node/certs.h"
#include "node/clientsignatures.h"
#include "node/nodes.h"
#include "nodeinterface.h"
#include "rpcexception.h"
#include "serialization.h"

#include <fmt/format_header_only.h>
#include <mutex>
#include <utility>
#include <vector>

namespace ccf
{
  struct RequestArgs
  {
    const enclave::RpcContext& rpc_ctx;
    Store::Tx& tx;
    CallerId caller_id;
    const std::string& method;
    const nlohmann::json& params;
  };

  using HandleFunction = std::function<void(RequestArgs& args)>;

  static enclave::RpcResponse make_success(nlohmann::json&& result_payload)
  {
    return enclave::RpcResponse{std::move(result_payload)};
  }

  static enclave::RpcResponse make_success(const nlohmann::json& result_payload)
  {
    return enclave::RpcResponse{result_payload};
  }

  static enclave::RpcResponse make_error(int code, const std::string& msg = "")
  {
    return enclave::RpcResponse{enclave::ErrorDetails{code, msg}};
  }

  template <typename CT = void>
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

  protected:
    Store& tables;

    void disable_request_storing()
    {
      request_storing_disabled = true;
    }

    virtual std::string invalid_caller_error_message() const
    {
      return "Could not find matching actor certificate";
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
      Forwardable forwardable = Forwardable::CanForward,
      bool execute_locally = false)
    {
      handlers[method] = {
        f, rw, params_schema, result_schema, forwardable, execute_locally};
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

    template <typename In, typename Out, typename F>
    void install_with_auto_schema(
      const std::string& method,
      F&& f,
      ReadWrite rw,
      Forwardable forwardable = Forwardable::CanForward,
      bool execute_locally = false)
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
        forwardable,
        execute_locally);
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

    /** Populate out with all supported methods
     *
     * This is virtual since the default handler may do its own dispatch
     * internally, so derived implementations must be able to populate the list
     * with the supported methods however it constructs them.
     */
    virtual void list_methods(Store::Tx& tx, ListMethods::Out& out)
    {
      for (const auto& handler : handlers)
      {
        out.methods.push_back(handler.first);
      }
    }

    kv::Consensus* get_consensus() const
    {
      return consensus;
    }

    kv::TxHistory* get_history() const
    {
      return history;
    }

  private:
    // TODO: replace with an lru map
    std::map<CallerId, tls::VerifierPtr> verifiers;
    SpinLock lock;
    bool is_open_ = false;

    struct Handler
    {
      HandleFunction func;
      ReadWrite rw;
      nlohmann::json params_schema;
      nlohmann::json result_schema;
      Forwardable forwardable;
      bool execute_locally = false;
    };

    Nodes* nodes;
    ClientSignatures* client_signatures;
    Certs* certs;
    CT* callers;
    pbft::RequestsMap* pbft_requests_map;
    std::optional<Handler> default_handler;
    std::unordered_map<std::string, Handler> handlers;
    kv::Consensus* consensus;
    std::shared_ptr<enclave::AbstractForwarder> cmd_forwarder;
    kv::TxHistory* history;

    size_t sig_max_tx = 1000;
    std::chrono::milliseconds sig_max_ms = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    bool request_storing_disabled = false;

    void update_consensus()
    {
      auto c = tables.get_consensus().get();

      if (consensus != c)
      {
        consensus = c;
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

    std::optional<CallerId> valid_caller(
      Store::Tx& tx, const std::vector<uint8_t>& caller)
    {
      if (certs == nullptr)
      {
        return INVALID_ID;
      }

      if (caller.empty())
      {
        return {};
      }

      auto certs_view = tx.get_view(*certs);
      auto caller_id = certs_view->get(caller);

      return caller_id;
    }

    std::optional<nlohmann::json> forward_or_redirect_json(
      const enclave::RpcContext& ctx, Forwardable forwardable)
    {
      if (
        cmd_forwarder && forwardable == Forwardable::CanForward &&
        !ctx.session.fwd.has_value())
      {
        return std::nullopt;
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
            return ctx.error_response(
              (int)jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY,
              info->pubhost + ":" + info->rpcport);
          }
        }

        return ctx.error_response(
          (int)jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY,
          "Not primary, primary unknown.");
      }
    }

    void record_client_signature(
      Store::Tx& tx, CallerId caller_id, const SignedReq& signed_request)
    {
      auto client_sig_view = tx.get_view(*client_signatures);
      if (request_storing_disabled)
      {
        SignedReq no_req;
        no_req.sig = signed_request.sig;
        client_sig_view->put(caller_id, no_req);
      }
      else
      {
        client_sig_view->put(caller_id, signed_request);
      }
    }

    bool verify_client_signature(
      const std::vector<uint8_t>& caller,
      const CallerId caller_id,
      const SignedReq& signed_request)
    {
      if (!client_signatures)
      {
        return false;
      }

      auto v = verifiers.find(caller_id);
      if (v == verifiers.end())
      {
        std::vector<uint8_t> caller_cert(caller);
        verifiers.emplace(
          std::make_pair(caller_id, tls::make_verifier(caller_cert)));
      }
      if (!verifiers[caller_id]->verify(
            signed_request.req, signed_request.sig, signed_request.md))
      {
        return false;
      }

      return true;
    }

  public:
    RpcFrontend(Store& tables_) :
      RpcFrontend(tables_, nullptr, nullptr, nullptr)
    {}

    RpcFrontend(
      Store& tables_,
      ClientSignatures* client_sigs_,
      Certs* certs_,
      CT* callers_) :
      tables(tables_),
      nodes(tables.get<Nodes>(Tables::NODES)),
      client_signatures(client_sigs_),
      certs(certs_),
      callers(callers_),
      pbft_requests_map(
        tables.get<pbft::RequestsMap>(pbft::Tables::PBFT_REQUESTS)),
      consensus(nullptr),
      history(nullptr)
    {}

    void set_sig_intervals(size_t sig_max_tx_, size_t sig_max_ms_) override
    {
      sig_max_tx = sig_max_tx_;
      sig_max_ms = std::chrono::milliseconds(sig_max_ms_);
      ms_to_sig = sig_max_ms;
    }

    void set_cmd_forwarder(
      std::shared_ptr<enclave::AbstractForwarder> cmd_forwarder_) override
    {
      cmd_forwarder = cmd_forwarder_;
    }

    void open() override
    {
      std::lock_guard<SpinLock> mguard(lock);
      is_open_ = true;
    }

    bool is_open() override
    {
      std::lock_guard<SpinLock> mguard(lock);
      return is_open_;
    }

    /** Process a serialised command with the associated RPC context
     *
     * If an RPC that requires writing to the kv store is processed on a
     * backup, the serialised RPC is forwarded to the current network primary.
     *
     * @param ctx Context for this RPC
     * @returns nullopt if the result is pending (to be forwarded, or still
     * to-be-executed by consensus), else the response (may contain error)
     */
    std::optional<std::vector<uint8_t>> process(
      const enclave::RpcContext& ctx) override
    {
      update_consensus();

      Store::Tx tx;

      // Retrieve id of caller
      std::optional<CallerId> caller_id;
      if (ctx.is_create_request)
      {
        caller_id = INVALID_ID;
      }
      else
      {
        caller_id = valid_caller(tx, ctx.session.caller_cert);
      }

      if (!caller_id.has_value())
      {
        return ctx.error_response(
          (int)jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
          invalid_caller_error_message());
      }

      if (ctx.signed_request.has_value())
      {
        if (
          !ctx.is_create_request &&
          !verify_client_signature(
            ctx.session.caller_cert,
            caller_id.value(),
            ctx.signed_request.value()))
        {
          return ctx.error_response(
            (int)jsonrpc::CCFErrorCodes::INVALID_CLIENT_SIGNATURE,
            "Failed to verify client signature.");
        }

        // Client signature is only recorded on the primary
        if (
          consensus == nullptr || consensus->is_primary() ||
          ctx.is_create_request)
        {
          record_client_signature(
            tx, caller_id.value(), ctx.signed_request.value());
        }
      }

#ifdef PBFT
      auto rep = process_if_local_node_rpc(ctx, tx, caller_id.value());
      if (rep.has_value())
      {
        return rep.value();
      }
      kv::TxHistory::RequestID reqid;

      update_history();
      reqid = {caller_id.value(), ctx.session.client_session_id, ctx.seq_no};
      if (history)
      {
        if (!history->add_request(
              reqid,
              ctx.actor,
              caller_id.value(),
              ctx.session.caller_cert,
              ctx.raw))
        {
          LOG_FAIL_FMT("Adding request {} failed", ctx.seq_no);
          return ctx.error_response(
            (int)jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "PBFT could not process request.");
        }
        tx.set_req_id(reqid);
        return std::nullopt;
      }
      else
      {
        return ctx.error_response(
          (int)jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
          "PBFT is not yet ready.");
      }
#else
      auto rep = process_command(ctx, tx, caller_id.value());

      // If necessary, forward the RPC to the current primary
      if (!rep.has_value())
      {
        if (consensus != nullptr)
        {
          auto primary_id = consensus->primary();

          // Only forward caller certificate if frontend cannot retrieve caller
          // cert from caller id
          std::vector<uint8_t> forwarded_caller_cert;
          if constexpr (std::is_same_v<CT, void>)
          {
            forwarded_caller_cert = ctx.session.caller_cert;
          }

          if (
            primary_id != NoNode && cmd_forwarder &&
            cmd_forwarder->forward_command(
              ctx, primary_id, caller_id.value(), forwarded_caller_cert))
          {
            // Indicate that the RPC has been forwarded to primary
            LOG_DEBUG_FMT("RPC forwarded to primary {}", primary_id);
            return std::nullopt;
          }
        }

        return ctx.error_response(
          (int)jsonrpc::CCFErrorCodes::RPC_NOT_FORWARDED,
          "RPC could not be forwarded to primary.");
      }

      return rep.value();
#endif
    }

    /** Process a serialised command with the associated RPC context via PBFT
     *
     * @param ctx Context for this RPC
     */
    ProcessPbftResp process_pbft(enclave::RpcContext& ctx) override
    {
      // TODO(#PBFT): Refactor this with process_forwarded().
      Store::Tx tx;
      crypto::Sha256Hash full_state_merkle_root;
      crypto::Sha256Hash replicated_state_merkle_root;
      kv::Version version = kv::NoVersion;

      update_consensus();

      bool has_updated_merkle_roots = false;

      auto cb = [&full_state_merkle_root,
                 &replicated_state_merkle_root,
                 &version,
                 &has_updated_merkle_roots](
                  kv::TxHistory::ResultCallbackArgs args) -> bool {
        full_state_merkle_root = args.full_state_merkle_root;
        replicated_state_merkle_root = args.replicated_state_merkle_root;
        if (args.version != kv::NoVersion)
        {
          version = args.version;
        }
        has_updated_merkle_roots = true;
        return true;
      };

      if (history == nullptr)
      {
        update_history();
      }

      history->register_on_result(cb);

      auto req_view = tx.get_view(*pbft_requests_map);
      req_view->put(
        0,
        {ctx.actor,
         ctx.session.fwd.value().caller_id,
         ctx.session.caller_cert,
         ctx.raw});

      auto rep = process_command(ctx, tx, ctx.session.fwd->caller_id);

      history->clear_on_result();

      if (!has_updated_merkle_roots)
      {
        full_state_merkle_root = history->get_full_state_root();
        replicated_state_merkle_root = history->get_replicated_state_root();
      }

      // TODO(#PBFT): Add RPC response to history based on Request ID
      // if (history)
      //   history->add_response(reqid, rv);

      return {rep.value(),
              full_state_merkle_root,
              replicated_state_merkle_root,
              version};
    }

    /** Process a serialised input forwarded from another node
     *
     * This function assumes that ctx contains the caller_id as read by the
     * forwarding backup.
     *
     * @param ctx Context for this forwarded RPC
     *
     * @return Serialised reply to send back to forwarder node
     */
    std::vector<uint8_t> process_forwarded(enclave::RpcContext& ctx) override
    {
      if (!ctx.session.fwd.has_value())
      {
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");
      }

      Store::Tx tx;

      if constexpr (!std::is_same_v<CT, void>)
      {
        // For frontends with valid callers (user and member frontends), lookup
        // the caller certificate from the forwarded caller id
        auto callers_view = tx.get_view(*callers);
        auto caller = callers_view->get(ctx.session.fwd->caller_id);
        if (!caller.has_value())
        {
          return ctx.error_response(
            (int)jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
            invalid_caller_error_message());
        }
        ctx.session.caller_cert = caller.value().cert;
      }

      // Store client signature. It is assumed that the forwarder node has
      // already verified the client signature.
      if (ctx.signed_request.has_value())
      {
        record_client_signature(
          tx, ctx.session.fwd->caller_id, ctx.signed_request.value());
      }

      auto rep = process_command(ctx, tx, ctx.session.fwd->caller_id);
      if (!rep.has_value())
      {
        // This should never be called when process_command is called with a
        // forwarded RPC context
        throw std::logic_error("Forwarded RPC cannot be forwarded");
      }

      return rep.value();
    }

    std::optional<nlohmann::json> process_if_local_node_rpc(
      const enclave::RpcContext& ctx, Store::Tx& tx, CallerId caller_id)
    {
      Handler* handler = nullptr;
      auto search = handlers.find(ctx.method);
      if (search != handlers.end() && search->second.execute_locally)
      {
        return process_command(ctx, tx, caller_id);
      }
      return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> process_command(
      const enclave::RpcContext& ctx, Store::Tx& tx, CallerId caller_id)
    {
      const auto rpc_version = ctx.unpacked_rpc.at(jsonrpc::JSON_RPC);
      if (rpc_version != jsonrpc::RPC_VERSION)
      {
        return ctx.error_response(
          (int)jsonrpc::StandardErrorCodes::INVALID_REQUEST,
          fmt::format(
            "Unexpected JSON-RPC version. Must be string \"{}\", received {}",
            jsonrpc::RPC_VERSION,
            rpc_version.dump()));
      }

      const auto params_it = ctx.unpacked_rpc.find(jsonrpc::PARAMS);
      if (
        params_it != ctx.unpacked_rpc.end() &&
        (!params_it->is_array() && !params_it->is_object()))
      {
        return ctx.error_response(
          (int)jsonrpc::StandardErrorCodes::INVALID_REQUEST,
          fmt::format(
            "If present, parameters must be an array or object. Received: {}",
            params_it->dump()));
      }

      const auto& params = params_it == ctx.unpacked_rpc.end() ?
        nlohmann::json(nullptr) :
        *params_it;

      Handler* handler = nullptr;
      auto search = handlers.find(ctx.method);
      if (search != handlers.end())
      {
        handler = &search->second;
      }
      else if (default_handler)
      {
        handler = &default_handler.value();
      }
      else
      {
        return ctx.error_response(
          (int)jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND, ctx.method);
      }

      update_history();
      update_consensus();

#ifndef PBFT
      bool is_primary = (consensus == nullptr) || consensus->is_primary() ||
        ctx.is_create_request;

      if (!is_primary)
      {
        switch (handler->rw)
        {
          case Read:
          {
            break;
          }

          case Write:
          {
            return forward_or_redirect_json(ctx, handler->forwardable);
            break;
          }

          case MayWrite:
          {
            bool readonly = ctx.unpacked_rpc.value(jsonrpc::READONLY, true);
            if (!readonly)
            {
              return forward_or_redirect_json(ctx, handler->forwardable);
            }
            break;
          }
        }
      }
#endif

      auto func = handler->func;
      auto args = RequestArgs{ctx, tx, caller_id, ctx.method, params};

      while (true)
      {
        try
        {
          func(args);

          if (ctx.response_is_error())
          {
            return ctx.serialise_response();
          }

          switch (tx.commit())
          {
            case kv::CommitSuccess::OK:
            {
              auto serialised = ctx.serialise_response();

              // TODO: How do we inject these fields into response of unknown
              // format?
              const auto& json_context =
                dynamic_cast<const enclave::JsonRpcContext&>(ctx);

              nlohmann::json result =
                jsonrpc::unpack(serialised, json_context.pack_format.value());

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
                {
                  if (consensus->type() == ConsensusType::Raft)
                  {
                    history->emit_signature();
                  }
                  else
                  {
                    consensus->emit_signature();
                  }
                }
              }

              return jsonrpc::pack(result, json_context.pack_format.value());
            }

            case kv::CommitSuccess::CONFLICT:
            {
              break;
            }

            case kv::CommitSuccess::NO_REPLICATE:
            {
              return ctx.error_response(
                (int)jsonrpc::CCFErrorCodes::TX_FAILED_TO_REPLICATE,
                "Transaction failed to replicate.");
            }
          }
        }
        catch (const RpcException& e)
        {
          return ctx.error_response((int)e.error_id, e.msg);
        }
        catch (JsonParseError& e)
        {
          e.pointer_elements.push_back(jsonrpc::PARAMS);
          const auto err = fmt::format("At {}:\n\t{}", e.pointer(), e.what());
          return ctx.error_response(
            (int)jsonrpc::StandardErrorCodes::PARSE_ERROR, err);
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
          return ctx.error_response(
            (int)jsonrpc::StandardErrorCodes::INTERNAL_ERROR, e.what());
        }
      }
    }

    void tick(std::chrono::milliseconds elapsed) override
    {
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
        {
          if (consensus->type() == ConsensusType::Raft)
          {
            history->emit_signature();
          }
          else
          {
            consensus->emit_signature();
          }
        }
      }
    }
  };
}
