// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "commonhandlerregistry.h"
#include "consts.h"
#include "ds/buffer.h"
#include "ds/spinlock.h"
#include "enclave/rpchandler.h"
#include "forwarder.h"
#include "jsonrpc.h"
#include "node/clientsignatures.h"
#include "node/nodes.h"
#include "nodeinterface.h"
#include "rpcexception.h"
#include "tls/verifier.h"

#include <fmt/format_header_only.h>
#include <mutex>
#include <utility>
#include <vector>

namespace ccf
{
  class RpcFrontend : public enclave::RpcHandler, public ForwardedRpcHandler
  {
  protected:
    Store& tables;
    HandlerRegistry& handlers;

    void disable_request_storing()
    {
      request_storing_disabled = true;
    }

    virtual std::string invalid_caller_error_message() const
    {
      return "Could not find matching actor certificate";
    }

  private:
    std::map<CallerId, tls::VerifierPtr> verifiers;
    SpinLock lock;
    bool is_open_ = false;

    Nodes* nodes;
    ClientSignatures* client_signatures;
    pbft::RequestsMap* pbft_requests_map;
    kv::Consensus* consensus;
    std::shared_ptr<enclave::AbstractForwarder> cmd_forwarder;
    kv::TxHistory* history;

    size_t sig_max_tx = 1000;
    std::atomic<size_t> tx_count = 0;
    std::chrono::milliseconds sig_max_ms = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    bool request_storing_disabled = false;

    void update_consensus()
    {
      auto c = tables.get_consensus().get();

      if (consensus != c)
      {
        consensus = c;
        handlers.set_consensus(consensus);
      }
    }

    void update_history()
    {
      history = tables.get_history().get();
      handlers.set_history(history);
    }

    std::optional<nlohmann::json> forward_or_redirect_json(
      std::shared_ptr<enclave::RpcContext> ctx,
      HandlerRegistry::Forwardable forwardable)
    {
      if (
        cmd_forwarder &&
        forwardable == HandlerRegistry::Forwardable::CanForward &&
        !ctx->session.fwd.has_value())
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
            return ctx->error_response(
              jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY,
              info->pubhost + ":" + info->rpcport);
          }
        }

        return ctx->error_response(
          jsonrpc::CCFErrorCodes::TX_NOT_PRIMARY,
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
    RpcFrontend(
      Store& tables_,
      HandlerRegistry& handlers_,
      ClientSignatures* client_sigs_ = nullptr) :
      tables(tables_),
      nodes(tables.get<Nodes>(Tables::NODES)),
      client_signatures(client_sigs_),
      handlers(handlers_),
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

      handlers.init_handlers(tables);
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
      std::shared_ptr<enclave::RpcContext> ctx) override
    {
      update_consensus();

      Store::Tx tx;

      // Retrieve id of caller
      std::optional<CallerId> caller_id;
      if (ctx->is_create_request)
      {
        caller_id = INVALID_ID;
      }
      else
      {
        caller_id = handlers.valid_caller(tx, ctx->session.caller_cert);
      }

      if (!caller_id.has_value())
      {
        return ctx->error_response(
          jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
          invalid_caller_error_message());
      }

      const auto signed_request = ctx->get_signed_request();
      if (signed_request.has_value())
      {
        if (
          !ctx->is_create_request &&
          !verify_client_signature(
            ctx->session.caller_cert,
            caller_id.value(),
            signed_request.value()))
        {
          return ctx->error_response(
            jsonrpc::CCFErrorCodes::INVALID_CLIENT_SIGNATURE,
            "Failed to verify client signature.");
        }

        // Client signature is only recorded on the primary
        if (
          consensus == nullptr || consensus->is_primary() ||
          ctx->is_create_request)
        {
          record_client_signature(
            tx, caller_id.value(), signed_request.value());
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
      reqid = {caller_id.value(),
               ctx->session.client_session_id,
               ctx->get_request_index()};
      if (history)
      {
        if (!history->add_request(
              reqid,
              caller_id.value(),
              ctx->session.caller_cert,
              ctx->get_serialised_request()))
        {
          LOG_FAIL_FMT(
            "Adding request failed: {}, {}, {}",
            std::get<0>(reqid),
            std::get<1>(reqid),
            std::get<2>(reqid));
          return ctx->error_response(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "PBFT could not process request.");
        }
        tx.set_req_id(reqid);
        return std::nullopt;
      }
      else
      {
        return ctx->error_response(
          jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
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

          if (
            primary_id != NoNode && cmd_forwarder &&
            cmd_forwarder->forward_command(
              ctx, primary_id, caller_id.value(), get_cert_to_forward(ctx)))
          {
            // Indicate that the RPC has been forwarded to primary
            LOG_DEBUG_FMT("RPC forwarded to primary {}", primary_id);
            return std::nullopt;
          }
        }

        return ctx->error_response(
          jsonrpc::CCFErrorCodes::RPC_NOT_FORWARDED,
          "RPC could not be forwarded to primary.");
      }

      return rep.value();
#endif
    }

    virtual std::vector<uint8_t> get_cert_to_forward(
      std::shared_ptr<enclave::RpcContext> ctx)
    {
      return ctx->session.caller_cert;
    }

    /** Process a serialised command with the associated RPC context via PBFT
     *
     * @param ctx Context for this RPC
     */
    ProcessPbftResp process_pbft(
      std::shared_ptr<enclave::RpcContext> ctx,
      bool include_merkle_roots) override
    {
      Store::Tx tx;
      return process_pbft(ctx, tx, false, include_merkle_roots);
    }

    ProcessPbftResp process_pbft(
      std::shared_ptr<enclave::RpcContext> ctx,
      Store::Tx& tx,
      bool playback,
      bool include_merkle_roots) override
    {
      crypto::Sha256Hash replicated_state_merkle_root;
      kv::Version version = kv::NoVersion;

      update_consensus();

      bool has_updated_merkle_roots = false;

      if (!playback)
      {
        auto req_view = tx.get_view(*pbft_requests_map);
        req_view->put(
          0,
          {ctx->session.fwd.value().caller_id,
           ctx->session.caller_cert,
           ctx->get_serialised_request(),
           ctx->pbft_raw});
      }

      auto rep = process_command(ctx, tx, ctx->session.fwd->caller_id);

      version = tx.get_version();
      if (include_merkle_roots)
      {
        replicated_state_merkle_root = history->get_replicated_state_root();
      }

      return {rep.value(), replicated_state_merkle_root, version};
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
    std::vector<uint8_t> process_forwarded(
      std::shared_ptr<enclave::RpcContext> ctx) override
    {
      if (!ctx->session.fwd.has_value())
      {
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");
      }

      Store::Tx tx;

      if (!lookup_forwarded_caller_cert(ctx, tx))
      {
        return ctx->error_response(
          jsonrpc::CCFErrorCodes::INVALID_CALLER_ID,
          invalid_caller_error_message());
      }

      // Store client signature. It is assumed that the forwarder node has
      // already verified the client signature.
      const auto signed_request = ctx->get_signed_request();
      if (signed_request.has_value())
      {
        record_client_signature(
          tx, ctx->session.fwd->caller_id, signed_request.value());
      }

      auto rep = process_command(ctx, tx, ctx->session.fwd->caller_id);
      if (!rep.has_value())
      {
        // This should never be called when process_command is called with a
        // forwarded RPC context
        throw std::logic_error("Forwarded RPC cannot be forwarded");
      }

      return rep.value();
    }

    std::optional<nlohmann::json> process_if_local_node_rpc(
      std::shared_ptr<enclave::RpcContext> ctx,
      Store::Tx& tx,
      CallerId caller_id)
    {
      const auto method = ctx->get_method();
      const auto local_method = method.substr(method.find_first_not_of('/'));
      auto handler = handlers.find_handler(local_method);
      if (handler != nullptr && handler->execute_locally)
      {
        return process_command(ctx, tx, caller_id);
      }
      return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> process_command(
      std::shared_ptr<enclave::RpcContext> ctx,
      Store::Tx& tx,
      CallerId caller_id)
    {
      const auto method = ctx->get_method();
      const auto local_method = method.substr(method.find_first_not_of('/'));
      auto handler = handlers.find_handler(local_method);
      if (handler == nullptr)
      {
        return ctx->error_response(
          jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND, method);
      }

      update_history();
      update_consensus();

#ifndef PBFT
      bool is_primary = (consensus == nullptr) || consensus->is_primary() ||
        ctx->is_create_request;

      if (!is_primary)
      {
        switch (handler->rw)
        {
          case HandlerRegistry::Read:
          {
            break;
          }

          case HandlerRegistry::Write:
          {
            return forward_or_redirect_json(ctx, handler->forwardable);
            break;
          }

          case HandlerRegistry::MayWrite:
          {
            if (!ctx->read_only_hint)
            {
              return forward_or_redirect_json(ctx, handler->forwardable);
            }
            break;
          }
        }
      }
#endif

      auto func = handler->func;
      auto args = RequestArgs{ctx, tx, caller_id};

      tx_count++;

      while (true)
      {
        try
        {
          func(args);

          if (ctx->response_is_error())
          {
            return ctx->serialise_response();
          }

          switch (tx.commit())
          {
            case kv::CommitSuccess::OK:
            {
              auto cv = tx.commit_version();
              if (cv == 0)
                cv = tx.get_read_version();
              if (cv == kv::NoVersion)
                cv = tables.current_version();
              ctx->set_response_headers(COMMIT, cv);
              if (consensus != nullptr)
              {
                ctx->set_response_headers(TERM, consensus->get_view());
                ctx->set_response_headers(
                  GLOBAL_COMMIT, consensus->get_commit_seqno());

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

              return ctx->serialise_response();
            }

            case kv::CommitSuccess::CONFLICT:
            {
              break;
            }

            case kv::CommitSuccess::NO_REPLICATE:
            {
              return ctx->error_response(
                jsonrpc::CCFErrorCodes::TX_FAILED_TO_REPLICATE,
                "Transaction failed to replicate.");
            }
          }
        }
        catch (const RpcException& e)
        {
          return ctx->error_response((int)e.error_id, e.msg);
        }
        catch (JsonParseError& e)
        {
          e.pointer_elements.push_back(jsonrpc::PARAMS);
          const auto err = fmt::format("At {}:\n\t{}", e.pointer(), e.what());
          return ctx->error_response(
            jsonrpc::StandardErrorCodes::PARSE_ERROR, err);
        }
        catch (const kv::KvSerialiserException& e)
        {
          // If serialising the committed transaction fails, there is no way to
          // recover safely (https://github.com/microsoft/CCF/issues/338).
          // Better to abort.
          LOG_FATAL_FMT("Failed to serialise: {}", e.what());
          abort();
        }
        catch (const std::exception& e)
        {
          return ctx->error_response(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR, e.what());
        }
      }
    }

    void tick(std::chrono::milliseconds elapsed) override
    {
      update_consensus();

      handlers.tick(elapsed, tx_count);

      // reset tx_counter for next tick interval
      tx_count = 0;

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

    // Return false if frontend believes it should be able to look up caller
    // certs, but couldn't find caller. Default behaviour is that there are no
    // caller certs, so nothing is changed but we return true
    virtual bool lookup_forwarded_caller_cert(
      std::shared_ptr<enclave::RpcContext> ctx, Store::Tx& tx)
    {
      return true;
    }
  };
}
