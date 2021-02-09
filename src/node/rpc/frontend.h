// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "common_endpoint_registry.h"
#include "consensus/aft/request.h"
#include "ds/buffer.h"
#include "ds/spin_lock.h"
#include "enclave/rpc_handler.h"
#include "forwarder.h"
#include "http/http_jwt.h"
#include "node/client_signatures.h"
#include "node/jwt.h"
#include "node/nodes.h"
#include "node/service.h"
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

  private:
    SpinLock open_lock;
    bool is_open_ = false;

    kv::Consensus* consensus;
    std::shared_ptr<enclave::AbstractForwarder> cmd_forwarder;
    kv::TxHistory* history;

    size_t sig_tx_interval = 5000;
    std::atomic<size_t> tx_count = 0;
    std::chrono::milliseconds sig_ms_interval = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    tls::Pem* service_identity = nullptr;

    using PreExec = std::function<void(kv::Tx& tx, enclave::RpcContext& ctx)>;

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

    std::optional<std::vector<uint8_t>> forward_or_redirect_json(
      std::shared_ptr<enclave::RpcContext> ctx,
      const EndpointDefinitionPtr& endpoint)
    {
      auto& metrics = endpoints.get_metrics(endpoint);

      if (cmd_forwarder && !ctx->session->is_forwarded)
      {
        if (consensus != nullptr)
        {
          auto primary_id = consensus->primary();

          if (
            primary_id != NoNode &&
            cmd_forwarder->forward_command(
              ctx,
              primary_id,
              endpoint->properties.execute_outside_consensus ==
                  ExecuteOutsideConsensus::Never ?
                consensus->active_nodes() :
                std::set<NodeId>(),
              ctx->session->caller_cert))
          {
            // Indicate that the RPC has been forwarded to primary
            LOG_TRACE_FMT("RPC forwarded to primary {}", primary_id);
            return std::nullopt;
          }
        }
        ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "RPC could not be forwarded to unknown primary.");
        update_metrics(ctx, metrics);
        return ctx->serialise_response();
      }
      else
      {
        // If this frontend is not allowed to forward or the command has already
        // been forwarded, redirect to the current primary
        ctx->set_response_status(HTTP_STATUS_TEMPORARY_REDIRECT);
        if (consensus != nullptr)
        {
          NodeId primary_id = consensus->primary();
          auto tx = tables.create_tx();
          auto nodes = tx.ro<Nodes>(Tables::NODES);
          auto info = nodes->get(primary_id);

          if (info)
          {
            ctx->set_response_header(
              http::headers::LOCATION,
              fmt::format("{}:{}", info->pubhost, info->pubport));
          }
        }

        update_metrics(ctx, metrics);
        return ctx->serialise_response();
      }
    }

    std::optional<std::vector<uint8_t>> process_command(
      std::shared_ptr<enclave::RpcContext> ctx,
      kv::Tx& tx,
      const PreExec& pre_exec = {})
    {
      const auto endpoint = endpoints.find_endpoint(tx, *ctx);
      if (endpoint == nullptr)
      {
        const auto allowed_verbs = endpoints.get_allowed_verbs(*ctx);
        if (allowed_verbs.empty())
        {
          ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format("Unknown path: {}.", ctx->get_method()));
          return ctx->serialise_response();
        }
        else
        {
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
          ctx->set_error(
            HTTP_STATUS_METHOD_NOT_ALLOWED,
            ccf::errors::UnsupportedHttpVerb,
            fmt::format(
              "Allowed methods for '{}' are: {}.",
              ctx->get_method(),
              allow_header_value));
          return ctx->serialise_response();
        }
      }

      // Note: calls that could not be dispatched (cases handled above)
      // are not counted against any particular endpoint.
      auto& metrics = endpoints.get_metrics(endpoint);
      metrics.calls++;

      std::unique_ptr<AuthnIdentity> identity = nullptr;

      // If any auth policy was required, check that at least one is accepted
      if (!endpoint->authn_policies.empty())
      {
        std::string auth_error_reason;
        for (const auto& policy : endpoint->authn_policies)
        {
          identity = policy->authenticate(tx, ctx, auth_error_reason);
          if (identity != nullptr)
          {
            break;
          }
        }

        if (identity == nullptr)
        {
          // If none were accepted, let the last set an error
          endpoint->authn_policies.back()->set_unauthenticated_error(
            ctx, std::move(auth_error_reason));
          update_metrics(ctx, metrics);
          return ctx->serialise_response();
        }
      }

      update_history();

      const bool is_primary = (consensus == nullptr) ||
        consensus->is_primary() || ctx->is_create_request;
      const bool forwardable = (consensus != nullptr) &&
        (consensus->type() == ConsensusType::CFT ||
         (consensus->type() != ConsensusType::CFT && !ctx->execute_on_node));

      if (!is_primary && forwardable)
      {
        switch (endpoint->properties.forwarding_required)
        {
          case ForwardingRequired::Never:
          {
            break;
          }

          case ForwardingRequired::Sometimes:
          {
            if (
              (ctx->session->is_forwarding &&
               consensus->type() == ConsensusType::CFT) ||
              (consensus->type() != ConsensusType::CFT &&
               !ctx->execute_on_node &&
               (endpoint == nullptr ||
                (endpoint != nullptr &&
                 endpoint->properties.execute_outside_consensus !=
                   ExecuteOutsideConsensus::Locally))))
            {
              ctx->session->is_forwarding = true;
              return forward_or_redirect_json(ctx, endpoint);
            }
            break;
          }

          case ForwardingRequired::Always:
          {
            ctx->session->is_forwarding = true;
            return forward_or_redirect_json(ctx, endpoint);
          }
        }
      }

      auto args = EndpointContext(ctx, std::move(identity), tx);

      tx_count++;

      size_t attempts = 0;
      constexpr auto max_attempts = 30;

      while (attempts < max_attempts)
      {
        ++attempts;

        try
        {
          if (pre_exec)
          {
            pre_exec(tx, *ctx.get());
          }

          endpoints.execute_endpoint(endpoint, args);

          if (!ctx->should_apply_writes())
          {
            update_metrics(ctx, metrics);
            return ctx->serialise_response();
          }

          switch (tx.commit())
          {
            case kv::CommitResult::SUCCESS:
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

                if (history != nullptr && consensus->is_primary())
                {
                  history->try_emit_signature();
                }
              }

              update_metrics(ctx, metrics);
              return ctx->serialise_response();
            }

            case kv::CommitResult::FAIL_CONFLICT:
            {
              set_root_on_proposals(*ctx, tx);
              metrics.retries++;
              break;
            }

            case kv::CommitResult::FAIL_NO_REPLICATE:
            {
              ctx->set_error(
                HTTP_STATUS_SERVICE_UNAVAILABLE,
                ccf::errors::TransactionReplicationFailed,
                "Transaction failed to replicate.");
              update_metrics(ctx, metrics);
              return ctx->serialise_response();
            }
          }
        }
        catch (const kv::CompactedVersionConflict& e)
        {
          // The executing transaction failed because of a conflicting
          // compaction. Reset and retry
          LOG_DEBUG_FMT(
            "Transaction execution conflicted with compaction: {}", e.what());
          tx.reset();
          continue;
        }
        catch (RpcException& e)
        {
          ctx->set_error(std::move(e.error));
          update_metrics(ctx, metrics);
          return ctx->serialise_response();
        }
        catch (JsonParseError& e)
        {
          ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            fmt::format("At {}: {}", e.pointer(), e.what()));
          update_metrics(ctx, metrics);
          return ctx->serialise_response();
        }
        catch (const nlohmann::json::exception& e)
        {
          ctx->set_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, e.what());
          update_metrics(ctx, metrics);
          return ctx->serialise_response();
        }
        catch (const UrlQueryParseError& e)
        {
          ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            e.what());
          update_metrics(ctx, metrics);
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
          ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            e.what());
          update_metrics(ctx, metrics);
          return ctx->serialise_response();
        }
      }

      ctx->set_error(
        HTTP_STATUS_SERVICE_UNAVAILABLE,
        ccf::errors::TransactionCommitAttemptsExceedLimit,
        fmt::format(
          "Transaction continued to conflict after {} attempts. Retry later.",
          max_attempts));
      static constexpr size_t retry_after_seconds = 3;
      ctx->set_response_header(http::headers::RETRY_AFTER, retry_after_seconds);
      return ctx->serialise_response();
    }

  public:
    RpcFrontend(kv::Store& tables_, EndpointRegistry& handlers_) :
      tables(tables_),
      endpoints(handlers_),
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

    void open(std::optional<tls::Pem*> identity = std::nullopt) override
    {
      std::lock_guard<SpinLock> mguard(open_lock);
      // open() without an identity unconditionally opens the frontend.
      // If an identity is passed, the frontend must instead wait for
      // the KV to read that this is identity is present and open,
      // see is_open()
      if (identity.has_value())
      {
        service_identity = identity.value();
      }
      else
      {
        if (!is_open_)
        {
          is_open_ = true;
          endpoints.init_handlers();
        }
      }
    }

    bool is_open(kv::Tx& tx) override
    {
      std::lock_guard<SpinLock> mguard(open_lock);
      if (!is_open_)
      {
        auto service = tx.ro<Service>(Tables::SERVICE);
        auto s = service->get_globally_committed(0);
        if (
          s.has_value() && s.value().status == ServiceStatus::OPEN &&
          service_identity != nullptr && s.value().cert == *service_identity)
        {
          LOG_INFO_FMT(
            "Service state is OPEN, now accepting user transactions");
          is_open_ = true;
          endpoints.init_handlers();
        }
      }
      return is_open_;
    }

    void set_root_on_proposals(const enclave::RpcContext& ctx, kv::Tx& tx)
    {
      if (ctx.get_request_path() == "/gov/proposals")
      {
        update_history();
        if (history)
        {
          const auto& [txid, root] =
            history->get_replicated_state_txid_and_root();
          tx.set_read_version_and_term(txid.version, txid.term);
          tx.set_root_at_read_version(root);
        }
      }
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

      auto tx = tables.create_tx();
      set_root_on_proposals(*ctx, tx);

      if (!is_open(tx))
      {
        ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::FrontendNotOpen,
          "Frontend is not open.");
        return ctx->serialise_response();
      }

      auto endpoint = endpoints.find_endpoint(tx, *ctx);

      const bool is_bft =
        consensus != nullptr && consensus->type() == ConsensusType::BFT;
      const bool is_local = endpoint != nullptr &&
        endpoint->properties.execute_outside_consensus !=
          ccf::endpoints::ExecuteOutsideConsensus::Never;
      const bool should_bft_distribute = is_bft && !is_local &&
        (ctx->execute_on_node || consensus->is_primary());

      // This decision is based on several things read from the KV
      // (request->is_local) which are true _now_ but may not
      // be true when this is actually received/executed. We should revisit this
      // once we have general KV-defined dispatch, to ensure this is safe. For
      // forwarding we will need to pass a digest of the endpoint definition,
      // and that should also work here
      if (should_bft_distribute)
      {
        update_history();
        if (history)
        {
          const kv::TxHistory::RequestID reqid = {
            ctx->session->client_session_id, ctx->get_request_index()};
          if (!history->add_request(
                reqid,
                ctx->session->caller_cert,
                ctx->get_serialised_request(),
                ctx->frame_format()))
          {
            LOG_FAIL_FMT("Adding request failed");
            LOG_DEBUG_FMT(
              "Adding request failed: {}, {}",
              std::get<0>(reqid),
              std::get<1>(reqid));
            ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Could not process request.");
            return ctx->serialise_response();
          }
          tx.set_req_id(reqid);
          return std::nullopt;
        }
        else
        {
          ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Consensus is not yet ready.");
          return ctx->serialise_response();
        }
      }

      return process_command(ctx, tx);
    }

    ProcessBftResp process_bft(
      std::shared_ptr<enclave::RpcContext> ctx) override
    {
      auto tx = tables.create_tx();
      return process_bft(ctx, tx);
    }

    /** Process a serialised command with the associated RPC context via BFT
     *
     * @param ctx Context for this RPC
     */
    ProcessBftResp process_bft(
      std::shared_ptr<enclave::RpcContext> ctx, kv::Tx& tx) override
    {
      // Note: this can only happen if the primary is malicious,
      // and has executed a user transaction when the service wasn't
      // open. The backup should ideally trigger a view change here.
      if (!is_open(tx))
      {
        throw std::logic_error("Transaction failed");
      }

      kv::Version version = kv::NoVersion;

      update_consensus();

      PreExec fn = [](kv::Tx& tx, enclave::RpcContext& ctx) {
        auto aft_requests = tx.rw<aft::RequestsMap>(ccf::Tables::AFT_REQUESTS);
        aft_requests->put(
          0,
          {tx.get_req_id(),
           ctx.session->caller_cert,
           ctx.get_serialised_request(),
           ctx.frame_format()});
      };

      auto rep = process_command(ctx, tx, fn);

      version = tx.get_version();
      return {std::move(rep.value()), version};
    }

    /** Process a serialised input forwarded from another node
     *
     * @param ctx Context for this forwarded RPC
     *
     * @return Serialised reply to send back to forwarder node
     */
    std::vector<uint8_t> process_forwarded(
      std::shared_ptr<enclave::RpcContext> ctx) override
    {
      if (!ctx->session->is_forwarded)
      {
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");
      }

      update_consensus();
      auto tx = tables.create_tx();

      const auto endpoint = endpoints.find_endpoint(tx, *ctx);
      if (
        consensus->type() == ConsensusType::CFT ||
        (endpoint != nullptr &&
         endpoint->properties.execute_outside_consensus ==
           ExecuteOutsideConsensus::Primary &&
         (consensus != nullptr && consensus->is_primary())))
      {
        auto rep = process_command(ctx, tx);
        if (!rep.has_value())
        {
          // This should never be called when process_command is called with a
          // forwarded RPC context
          throw std::logic_error("Forwarded RPC cannot be forwarded");
        }

        return rep.value();
      }
      else
      {
        auto rep = process_bft(ctx, tx);
        return rep.result;
      }
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
    }
  };
}
