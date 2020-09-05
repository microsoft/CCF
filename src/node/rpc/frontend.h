// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "common_endpoint_registry.h"
#include "consensus/aft/request.h"
#include "consensus/pbft/pbft_tables.h"
#include "ds/buffer.h"
#include "ds/spin_lock.h"
#include "enclave/rpc_handler.h"
#include "forwarder.h"
#include "node/client_signatures.h"
#include "node/nodes.h"
#include "rpc_exception.h"
#include "tls/verifier.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <mutex>
#include <utility>
#include <vector>

namespace ccf
{
  class RpcFrontend : public enclave::RpcHandler, public ForwardedRpcHandler
  {
  protected:
    kv::Store& tables;
    EndpointRegistry& endpoints;

    void disable_request_storing()
    {
      request_storing_disabled = true;
    }

    virtual std::string invalid_caller_error_message() const
    {
      return "Could not find matching actor certificate";
    }

  private:
    SpinLock verifiers_lock;
    std::map<CallerId, tls::VerifierPtr> verifiers;

    SpinLock open_lock;
    bool is_open_ = false;

    Nodes* nodes;
    ClientSignatures* client_signatures;
    aft::RequestsMap* pbft_requests_map;
    kv::Consensus* consensus;
    std::shared_ptr<enclave::AbstractForwarder> cmd_forwarder;
    kv::TxHistory* history;

    size_t sig_tx_interval = 5000;
    std::atomic<size_t> tx_count = 0;
    std::chrono::milliseconds sig_ms_interval = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    bool request_storing_disabled = false;

    using PreExec = std::function<void(
      kv::Tx& tx, enclave::RpcContext& ctx, RpcFrontend& frontend)>;

    void update_consensus()
    {
      auto c = tables.get_consensus().get();

      if (consensus != c)
      {
        consensus = c;
        endpoints.set_consensus(consensus);
      }
    }

    void update_history()
    {
      history = tables.get_history().get();
      endpoints.set_history(history);
    }

    void update_metrics(
      const std::shared_ptr<enclave::RpcContext> ctx,
      EndpointRegistry::Metrics& m)
    {
      int cat = ctx->get_response_status() / 100;
      switch (cat)
      {
        case 4:
          m.errors++;
          return;
        case 5:
          m.failures++;
          return;
      }
    }

    std::vector<uint8_t> get_cert_to_forward(
      std::shared_ptr<enclave::RpcContext> ctx,
      EndpointRegistry::Endpoint* endpoint = nullptr)
    {
      // Only forward the certificate if the certificate cannot be looked up
      // from the caller ID on the receiving frontend or if the endpoint does
      // not require a known client identity
      if (
        !endpoints.has_certs() ||
        (endpoint != nullptr && !endpoint->require_client_identity))
      {
        return ctx->session->caller_cert;
      }

      return {};
    }

    std::optional<std::vector<uint8_t>> forward_or_redirect_json(
      std::shared_ptr<enclave::RpcContext> ctx,
      EndpointRegistry::Endpoint* endpoint,
      CallerId caller_id)
    {
      if (cmd_forwarder && !ctx->session->original_caller.has_value())
      {
        if (consensus != nullptr)
        {
          auto primary_id = consensus->primary();

          if (
            primary_id != NoNode &&
            cmd_forwarder->forward_command(
              ctx, primary_id, caller_id, get_cert_to_forward(ctx, endpoint)))
          {
            // Indicate that the RPC has been forwarded to primary
            LOG_TRACE_FMT("RPC forwarded to primary {}", primary_id);
            return std::nullopt;
          }
        }
        ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        ctx->set_response_body(
          "RPC could not be forwarded to unknown primary.");
        update_metrics(ctx, endpoint->metrics);
        return ctx->serialise_response();
      }
      else
      {
        // If this frontend is not allowed to forward or the command has already
        // been forwarded, redirect to the current primary
        ctx->set_response_status(HTTP_STATUS_TEMPORARY_REDIRECT);
        if ((nodes != nullptr) && (consensus != nullptr))
        {
          NodeId primary_id = consensus->primary();
          kv::Tx tx;
          auto nodes_view = tx.get_view(*nodes);
          auto info = nodes_view->get(primary_id);

          if (info)
          {
            ctx->set_response_header(
              http::headers::LOCATION,
              fmt::format("{}:{}", info->pubhost, info->rpcport));
          }
        }

        update_metrics(ctx, endpoint->metrics);
        return ctx->serialise_response();
      }
    }

    void record_client_signature(
      kv::Tx& tx, CallerId caller_id, const SignedReq& signed_request)
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

      tls::VerifierPtr verifier;
      {
        std::lock_guard<SpinLock> mguard(verifiers_lock);
        auto v = verifiers.find(caller_id);
        if (v == verifiers.end())
        {
          verifiers.emplace(
            std::make_pair(caller_id, tls::make_verifier(caller)));
        }
        verifier = verifiers[caller_id];
      }

      return verifier->verify(
        signed_request.req, signed_request.sig, signed_request.md);
    }

    void set_response_unauthorized(
      std::shared_ptr<enclave::RpcContext>& ctx,
      std::string&& msg = "Failed to verify client signature") const
    {
      ctx->set_response_status(HTTP_STATUS_UNAUTHORIZED);
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
      ctx->set_response_body(std::move(msg));
    }

    std::optional<std::vector<uint8_t>> process_if_local_node_rpc(
      std::shared_ptr<enclave::RpcContext> ctx, kv::Tx& tx, CallerId caller_id)
    {
      auto endpoint = endpoints.find_endpoint(*ctx);
      if (endpoint != nullptr && endpoint->execute_locally)
      {
        return process_command(ctx, tx, caller_id);
      }
      return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> process_command(
      std::shared_ptr<enclave::RpcContext> ctx,
      kv::Tx& tx,
      CallerId caller_id,
      PreExec pre_exec = {})
    {
      LOG_INFO_FMT("5. DDDDDDD");
      const auto endpoint = endpoints.find_endpoint(*ctx);
      if (endpoint == nullptr)
      {
        const auto allowed_verbs = endpoints.get_allowed_verbs(*ctx);
        if (allowed_verbs.empty())
        {
          ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          ctx->set_response_body(
            fmt::format("Unknown path: {}", ctx->get_method()));
          return ctx->serialise_response();
        }
        else
        {
          ctx->set_response_status(HTTP_STATUS_METHOD_NOT_ALLOWED);
          std::vector<char const*> allowed_verb_strs;
          for (auto verb : allowed_verbs)
          {
            allowed_verb_strs.push_back(verb.c_str());
          }
          const std::string allow_header_value =
            fmt::format("{}", fmt::join(allowed_verb_strs, ", "));
          // List allowed methods in 2 places:
          // - ALLOW header for standards compliance + machine parsing
          // - Body for visiblity + human readability
          ctx->set_response_header(http::headers::ALLOW, allow_header_value);
          ctx->set_response_body(fmt::format(
            "Allowed methods for '{}' are: {}",
            ctx->get_method(),
            allow_header_value));
          return ctx->serialise_response();
        }
      }

      LOG_INFO_FMT("6. DDDDDDD");
      // Note: calls that could not be dispatched (cases handled above)
      // are not counted against any particular endpoint.
      endpoint->metrics.calls++;

      if (endpoint->require_client_identity && endpoints.has_certs())
      {
        // Only if endpoint requires client identity.
        // If a request is forwarded, check that the caller is known. Otherwise,
        // only check that the caller id is valid.
        if (
          (ctx->session->original_caller.has_value() &&
           !lookup_forwarded_caller_cert(ctx, tx)) ||
          caller_id == INVALID_ID)
        {
          ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
          ctx->set_response_body(invalid_caller_error_message());
          update_metrics(ctx, endpoint->metrics);
          return ctx->serialise_response();
        }
      }

      bool is_primary = (consensus == nullptr) || consensus->is_primary() ||
        ctx->is_create_request;

      const auto signed_request = ctx->get_signed_request();
      if (endpoint->require_client_signature && !signed_request.has_value())
      {
        set_response_unauthorized(
          ctx, fmt::format("'{}' RPC must be signed", ctx->get_method()));
        update_metrics(ctx, endpoint->metrics);
        return ctx->serialise_response();
      }

      // By default, signed requests are verified and recorded, even on
      // endpoints that do not require client signatures
      bool should_record_client_signature = false;
      if (signed_request.has_value())
      {
        // For forwarded requests (raft only), skip verification as it is
        // assumed that the verification was done by the forwarder node.
        if (
          (!ctx->is_create_request &&
           (!(consensus != nullptr &&
              consensus->type() == ConsensusType::RAFT) ||
            !ctx->session->original_caller.has_value())) &&
          !verify_client_signature(
            ctx->session->caller_cert, caller_id, signed_request.value()))
        {
          set_response_unauthorized(ctx);
          update_metrics(ctx, endpoint->metrics);
          return ctx->serialise_response();
        }

        if (is_primary)
        {
          should_record_client_signature = true;
        }
      }

      update_history();

      if(ctx != nullptr)
      {
      LOG_INFO_FMT(
        "7. DDDDDDD is_primary:{}, exec_on_node:{}",
        is_primary,
        ctx->execute_on_node);
      }
      else
      {
      LOG_INFO_FMT(
        "7. DDDDDDD is_primary:{}, exec_on_node:nullptr",
        is_primary);
      }
      
      //if (!is_primary && consensus->type() == ConsensusType::RAFT)
      if (
        (!is_primary && consensus->type() == ConsensusType::RAFT) ||
        (consensus != nullptr && consensus->type() != ConsensusType::RAFT && !ctx->execute_on_node))
      {
        LOG_INFO_FMT("7.0 DDDDDDD");
        switch (endpoint->forwarding_required)
        {
          case ForwardingRequired::Never:
          {
            LOG_INFO_FMT("7.1 DDDDDDD");
            break;
          }

          case ForwardingRequired::Sometimes:
          {
            if (
              (ctx->session->is_forwarding && consensus->type() == ConsensusType::RAFT) ||
               (consensus->type() != ConsensusType::RAFT && !ctx->execute_on_node))
            {
            LOG_INFO_FMT("7.2 DDDDDDD");
            ctx->session->is_forwarding = true;
              return forward_or_redirect_json(ctx, endpoint, caller_id);
            }
            LOG_INFO_FMT("7.3 DDDDDDD");
            break;
          }

          case ForwardingRequired::Always:
          {
            LOG_INFO_FMT("7.4 DDDDDDD");
            ctx->session->is_forwarding = true;
            return forward_or_redirect_json(ctx, endpoint, caller_id);
          }
        }
      }
      LOG_INFO_FMT("8. DDDDDDD");

      auto func = endpoint->func;
      auto args = EndpointContext{ctx, tx, caller_id};

      tx_count++;

      while (true)
      {
        try
        {
          if (pre_exec)
          {
            pre_exec(tx, *ctx.get(), *this);
          }

          if (should_record_client_signature)
          {
            record_client_signature(tx, caller_id, signed_request.value());
          }

          func(args);

          if (!ctx->should_apply_writes())
          {
            update_metrics(ctx, endpoint->metrics);
            return ctx->serialise_response();
          }

          switch (tx.commit())
          {
            case kv::CommitSuccess::OK:
            {
              auto cv = tx.commit_version();
              if (cv == 0)
                cv = tx.get_read_version();
              if (consensus != nullptr)
              {
                if (cv != kv::NoVersion)
                {
                  ctx->set_seqno(cv);
                  ctx->set_view(tx.commit_term());
                }
                // Deprecated, this will be removed in future releases
                ctx->set_global_commit(consensus->get_committed_seqno());

                if (
                  history && consensus->is_primary() &&
                  (cv % sig_tx_interval == sig_tx_interval / 2))
                {
                  if (consensus->type() == ConsensusType::RAFT)
                  {
                    history->emit_signature();
                  }
                  else
                  {
                    consensus->emit_signature();
                  }
                }
              }

              update_metrics(ctx, endpoint->metrics);
              return ctx->serialise_response();
            }

            case kv::CommitSuccess::CONFLICT:
            {
              break;
            }

            case kv::CommitSuccess::NO_REPLICATE:
            {
              ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
              ctx->set_response_body("Transaction failed to replicate.");
              update_metrics(ctx, endpoint->metrics);
              return ctx->serialise_response();
            }
          }
        }
        catch (const RpcException& e)
        {
          ctx->set_response_status(e.status);
          ctx->set_response_body(e.what());
          update_metrics(ctx, endpoint->metrics);
          return ctx->serialise_response();
        }
        catch (JsonParseError& e)
        {
          auto err = fmt::format("At {}:\n\t{}", e.pointer(), e.what());
          ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          ctx->set_response_body(std::move(err));
          update_metrics(ctx, endpoint->metrics);
          return ctx->serialise_response();
        }
        catch (const kv::KvSerialiserException& e)
        {
          // If serialising the committed transaction fails, there is no way
          // to recover safely (https://github.com/microsoft/CCF/issues/338).
          // Better to abort.
          LOG_DEBUG_FMT("Failed to serialise: {}", e.what());
          LOG_FATAL_FMT("Failed to serialise");
          abort();
        }
        catch (const std::exception& e)
        {
          ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx->set_response_body(e.what());
          update_metrics(ctx, endpoint->metrics);
          return ctx->serialise_response();
        }
      }
    }

  public:
    RpcFrontend(
      kv::Store& tables_,
      EndpointRegistry& handlers_,
      ClientSignatures* client_sigs_ = nullptr) :
      tables(tables_),
      endpoints(handlers_),
      nodes(tables.get<Nodes>(Tables::NODES)),
      client_signatures(client_sigs_),
      pbft_requests_map(
        tables.get<aft::RequestsMap>(pbft::Tables::PBFT_REQUESTS)),
      consensus(nullptr),
      history(nullptr)
    {}

    void set_sig_intervals(
      size_t sig_tx_interval_, size_t sig_ms_interval_) override
    {
      sig_tx_interval = sig_tx_interval_;
      sig_ms_interval = std::chrono::milliseconds(sig_ms_interval_);
      ms_to_sig = sig_ms_interval;
    }

    void set_cmd_forwarder(
      std::shared_ptr<enclave::AbstractForwarder> cmd_forwarder_) override
    {
      cmd_forwarder = cmd_forwarder_;
    }

    void open() override
    {
      std::lock_guard<SpinLock> mguard(open_lock);
      if (!is_open_)
      {
        is_open_ = true;
        endpoints.init_handlers(tables);
      }
    }

    bool is_open() override
    {
      std::lock_guard<SpinLock> mguard(open_lock);
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
      LOG_INFO_FMT("AAAAAAA");

      auto tx = tables.create_tx();

      auto caller_id = endpoints.get_caller_id(tx, ctx->session->caller_cert);

      if (
        consensus != nullptr && consensus->type() == ConsensusType::PBFT &&
        (ctx->execute_on_node || consensus->is_primary()))
      //if ( consensus != nullptr && consensus->type() == ConsensusType::PBFT)
      {
        LOG_INFO_FMT("BBBBBBB, exec_on_node:{}, is_primary", ctx->execute_on_node, consensus->is_primary());
        //if (consensus->is_backup())
        //{
          //throw std::logic_error("foo");
        //  throw ccf::ccf_logic_error("ksldjf");
        //}

        auto rep = process_if_local_node_rpc(ctx, tx, caller_id);
        if (rep.has_value())
        {
          return rep;
        }
        kv::TxHistory::RequestID reqid;

        update_history();
        reqid = {
          caller_id, ctx->session->client_session_id, ctx->get_request_index()};
        if (history)
        {
          if (!history->add_request(
                reqid,
                caller_id,
                get_cert_to_forward(ctx),
                ctx->get_serialised_request(),
                ctx->frame_format()))
          {
            LOG_FAIL_FMT("Adding request failed");
            LOG_DEBUG_FMT(
              "Adding request failed: {}, {}, {}",
              std::get<0>(reqid),
              std::get<1>(reqid),
              std::get<2>(reqid));
            ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
            ctx->set_response_body("PBFT could not process request.");
            return ctx->serialise_response();
          }
          tx.set_req_id(reqid);
          return std::nullopt;
        }
        else
        {
          ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx->set_response_body("PBFT is not yet ready.");
          return ctx->serialise_response();
        }
      }
      else
      {
        LOG_INFO_FMT("CCCCCCC");
        return process_command(ctx, tx, caller_id);
      }
    }

    /** Process a serialised command with the associated RPC context via PBFT
     *
     * @param ctx Context for this RPC
     */
    ProcessPbftResp process_pbft(
      std::shared_ptr<enclave::RpcContext> ctx) override
    {
      auto tx = tables.create_tx();
      return process_pbft(ctx, tx, false);
    }

    ProcessPbftResp process_pbft(
      std::shared_ptr<enclave::RpcContext> ctx,
      kv::Tx& tx,
      bool playback) override
    {
      kv::Version version = kv::NoVersion;

      update_consensus();

      PreExec fn = {};

      if (!playback)
      {
        fn = [](kv::Tx& tx, enclave::RpcContext& ctx, RpcFrontend& frontend) {
          auto req_view = tx.get_view(*frontend.pbft_requests_map);
          req_view->put(
            0,
            {ctx.session->original_caller.value().caller_id,
             tx.get_req_id(),
             ctx.session->caller_cert,
             ctx.get_serialised_request()});
        };
      }

      auto rep =
        process_command(ctx, tx, ctx->session->original_caller->caller_id, fn);

      version = tx.get_version();
      return {std::move(rep.value()), version};
    }

    crypto::Sha256Hash get_merkle_root() override
    {
      return history->get_replicated_state_root();
    }

    void update_merkle_tree() override
    {
      history->flush_pending();
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
      if (!ctx->session->original_caller.has_value())
      {
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");
      }

      update_consensus();

      auto tx = tables.create_tx();

      auto rep =
        process_command(ctx, tx, ctx->session->original_caller->caller_id);
      if (!rep.has_value())
      {
        // This should never be called when process_command is called with a
        // forwarded RPC context
        throw std::logic_error("Forwarded RPC cannot be forwarded");
      }

      return rep.value();
    }

    void tick(std::chrono::milliseconds elapsed) override
    {
      update_consensus();

      kv::Consensus::Statistics stats;

      if (consensus != nullptr)
      {
        stats = consensus->get_statistics();
      }
      stats.tx_count = tx_count;

      endpoints.tick(elapsed, stats);

      // reset tx_counter for next tick interval
      tx_count = 0;

      if ((consensus != nullptr) && consensus->is_primary())
      {
        if (elapsed < ms_to_sig)
        {
          ms_to_sig -= elapsed;
          return;
        }

        ms_to_sig = sig_ms_interval;
        if (history && tables.commit_gap() > 0)
        {
          if (consensus->type() == ConsensusType::RAFT)
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
      std::shared_ptr<enclave::RpcContext>, kv::Tx&)
    {
      return true;
    }

    virtual bool is_members_frontend() override
    {
      return false;
    }
  };
}
