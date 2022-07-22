// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_registry.h"
#include "ccf/http_status.h"
#include "ccf/node_context.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/signed_req.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "common/configuration.h"
#include "consensus/aft/request.h"
#include "enclave/rpc_handler.h"
#include "forwarder.h"
#include "http/http_jwt.h"
#include "kv/compacted_version_conflict.h"
#include "kv/store.h"
#include "node/node_configuration_subsystem.h"
#include "rpc_exception.h"

#define FMT_HEADER_ONLY
#include "ccf/ds/pal.h"

#include <fmt/format.h>
#include <utility>
#include <vector>

namespace ccf
{
  class RpcFrontend : public RpcHandler, public ForwardedRpcHandler
  {
  protected:
    kv::Store& tables;
    endpoints::EndpointRegistry& endpoints;
    ccfapp::AbstractNodeContext& node_context;

  private:
    ccf::Pal::Mutex open_lock;
    bool is_open_ = false;

    kv::Consensus* consensus;
    std::shared_ptr<AbstractForwarder> cmd_forwarder;
    kv::TxHistory* history;

    size_t sig_tx_interval = 5000;
    std::chrono::milliseconds sig_ms_interval = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);
    crypto::Pem* service_identity = nullptr;

    std::shared_ptr<NodeConfigurationSubsystem> node_configuration_subsystem =
      nullptr;

    using PreExec =
      std::function<void(kv::CommittableTx& tx, ccf::RpcContextImpl& ctx)>;

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
      const std::shared_ptr<ccf::RpcContextImpl>& ctx,
      const endpoints::EndpointDefinitionPtr& endpoint)
    {
      int cat = ctx->get_response_status() / 100;
      switch (cat)
      {
        case 4:
          endpoints.increment_metrics_errors(endpoint);
          return;
        case 5:
          endpoints.increment_metrics_failures(endpoint);
          return;
      }
    }

    std::optional<std::vector<uint8_t>> forward(
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      kv::ReadOnlyTx& tx,
      const endpoints::EndpointDefinitionPtr& endpoint)
    {
      if (!cmd_forwarder || !consensus)
      {
        ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "No consensus or forwarder to forward request.");
        update_metrics(ctx, endpoint);
        return ctx->serialise_response();
      }

      if (ctx->get_session_context()->is_forwarded)
      {
        // If the request was already forwarded, return an error to prevent
        // daisy chains.
        ctx->set_error(
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::RequestAlreadyForwarded,
          "RPC was already forwarded.");
        update_metrics(ctx, endpoint);
        return ctx->serialise_response();
      }

      auto primary_id = consensus->primary();
      if (!primary_id.has_value())
      {
        ctx->set_error(
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::InternalError,
          "RPC could not be forwarded to unknown primary.");
        update_metrics(ctx, endpoint);
        return ctx->serialise_response();
      }

      // Ignore return value - false only means it is pending
      cmd_forwarder->forward_command(
        ctx, primary_id.value(), ctx->get_session_context()->caller_cert);

      LOG_TRACE_FMT("RPC forwarded to primary {}", primary_id.value());

      // Indicate that the RPC has been forwarded to primary
      return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> process_command(
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      kv::CommittableTx& tx,
      const PreExec& pre_exec = {},
      kv::Version prescribed_commit_version = kv::NoVersion,
      ccf::View replicated_view = ccf::VIEW_UNKNOWN)
    {
      auto sctx = ctx->get_session_context();
      auto interface_id = sctx->interface_id;

      const auto endpoint = endpoints.find_endpoint(tx, *ctx);
      if (endpoint == nullptr)
      {
        const auto allowed_verbs = endpoints.get_allowed_verbs(tx, *ctx);
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
          allowed_verb_strs.push_back(llhttp_method_name(HTTP_OPTIONS));
          for (auto verb : allowed_verbs)
          {
            allowed_verb_strs.push_back(verb.c_str());
          }
          const std::string allow_header_value =
            fmt::format("{}", fmt::join(allowed_verb_strs, ", "));
          // List allowed methods in 2 places:
          // - ALLOW header for standards compliance + machine parsing
          // - Body for visiblity + human readability (unless this was an
          // OPTIONS request, which returns a 204 No Content)
          ctx->set_response_header(http::headers::ALLOW, allow_header_value);
          if (ctx->get_request_verb() == HTTP_OPTIONS)
          {
            ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
          else
          {
            ctx->set_error(
              HTTP_STATUS_METHOD_NOT_ALLOWED,
              ccf::errors::UnsupportedHttpVerb,
              fmt::format(
                "Allowed methods for '{}' are: {}.",
                ctx->get_method(),
                allow_header_value));
          }
          return ctx->serialise_response();
        }
      }

      if (consensus && interface_id)
      {
        if (!node_configuration_subsystem)
        {
          node_configuration_subsystem =
            node_context.get_subsystem<NodeConfigurationSubsystem>();
          if (!node_configuration_subsystem)
          {
            ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
            return ctx->serialise_response();
          }
        }

        auto& ncs = node_configuration_subsystem->get();
        auto rit = ncs.rpc_interface_regexes.find(*interface_id);

        if (rit != ncs.rpc_interface_regexes.end())
        {
          bool ok = false;
          for (const auto& re : rit->second)
          {
            std::smatch m;
            if (std::regex_match(endpoint->full_uri_path, m, re))
            {
              ok = true;
              break;
            }
          }
          if (!ok)
          {
            ctx->set_response_status(HTTP_STATUS_SERVICE_UNAVAILABLE);
            return ctx->serialise_response();
          }
        }
        else
        {
          auto icfg = ncs.node_config.network.rpc_interfaces.at(*interface_id);
          if (icfg.endorsement->authority == Authority::UNSECURED)
          {
            // Unsecured interfaces are opt-in only.
            LOG_FAIL_FMT(
              "Request for {} rejected because the interface is unsecured and "
              "no accepted_endpoints have been configured.",
              endpoint->full_uri_path);
            ctx->set_response_status(HTTP_STATUS_SERVICE_UNAVAILABLE);
            return ctx->serialise_response();
          }
        }
      }
      else
      {
        // internal or forwarded: OK because they have been checked by the
        // forwarder (forward() happens further down).
      }

      // Note: calls that could not be dispatched (cases handled above)
      // are not counted against any particular endpoint.
      endpoints.increment_metrics_calls(endpoint);

      try
      {
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
            update_metrics(ctx, endpoint);
            return ctx->serialise_response();
          }
        }

        update_history();

        const bool is_primary = (consensus == nullptr) ||
          consensus->can_replicate() || ctx->is_create_request;
        const bool forwardable = (consensus != nullptr) &&
          (consensus->type() == ConsensusType::CFT ||
           (consensus->type() != ConsensusType::CFT && !ctx->execute_on_node));

        if (!is_primary && forwardable)
        {
          switch (endpoint->properties.forwarding_required)
          {
            case endpoints::ForwardingRequired::Never:
            {
              break;
            }

            case endpoints::ForwardingRequired::Sometimes:
            {
              if (
                (ctx->get_session_context()->is_forwarding &&
                 consensus->type() == ConsensusType::CFT) ||
                (consensus->type() != ConsensusType::CFT &&
                 !ctx->execute_on_node))
              {
                ctx->get_session_context()->is_forwarding = true;
                return forward(ctx, tx, endpoint);
              }
              break;
            }

            case endpoints::ForwardingRequired::Always:
            {
              ctx->get_session_context()->is_forwarding = true;
              return forward(ctx, tx, endpoint);
            }
          }
        }

        auto args = endpoints::EndpointContext(ctx, std::move(identity), tx);

        size_t attempts = 0;
        constexpr auto max_attempts = 30;

        while (attempts < max_attempts)
        {
          if (attempts > 0)
          {
            // If the endpoint has already been executed, the effects of its
            // execution should be dropped
            tx = tables.create_tx();
            ctx->reset_response();
            set_root_on_proposals(*ctx, tx);
            endpoints.increment_metrics_retries(endpoint);
          }

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
              update_metrics(ctx, endpoint);
              return ctx->serialise_response();
            }

            kv::CommitResult result;
            bool track_read_versions =
              (consensus != nullptr && consensus->type() == ConsensusType::BFT);
            if (prescribed_commit_version != kv::NoVersion)
            {
              CCF_ASSERT(
                consensus->type() == ConsensusType::BFT,
                "Wrong consensus type");
              auto version_resolver = [&](bool) {
                tables.next_version();
                return std::make_tuple(
                  prescribed_commit_version, kv::NoVersion);
              };
              tx.set_view(replicated_view);
              result =
                tx.commit(ctx->claims, track_read_versions, version_resolver);
            }
            else
            {
              result = tx.commit(ctx->claims, track_read_versions);
            }

            switch (result)
            {
              case kv::CommitResult::SUCCESS:
              {
                auto tx_id = tx.get_txid();
                if (tx_id.has_value() && consensus != nullptr)
                {
                  // Only transactions that acquired one or more map handles
                  // have a TxID, while others (e.g. unauthenticated commands)
                  // don't. Also, only report a TxID if the consensus is set, as
                  // the consensus is required to verify that a TxID is valid.
                  ctx->set_tx_id(tx_id.value());
                }

                if (
                  consensus != nullptr && consensus->can_replicate() &&
                  history != nullptr)
                {
                  history->try_emit_signature();
                }

                update_metrics(ctx, endpoint);
                return ctx->serialise_response();
              }

              case kv::CommitResult::FAIL_CONFLICT:
              {
                break;
              }

              case kv::CommitResult::FAIL_NO_REPLICATE:
              {
                ctx->set_error(
                  HTTP_STATUS_SERVICE_UNAVAILABLE,
                  ccf::errors::TransactionReplicationFailed,
                  "Transaction failed to replicate.");
                update_metrics(ctx, endpoint);
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
            continue;
          }
          catch (RpcException& e)
          {
            ctx->set_error(std::move(e.error));
            update_metrics(ctx, endpoint);
            return ctx->serialise_response();
          }
          catch (const JsonParseError& e)
          {
            ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              fmt::format("At {}: {}", e.pointer(), e.what()));
            update_metrics(ctx, endpoint);
            return ctx->serialise_response();
          }
          catch (const nlohmann::json::exception& e)
          {
            ctx->set_error(
              HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, e.what());
            update_metrics(ctx, endpoint);
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

          ctx->set_error(
            HTTP_STATUS_SERVICE_UNAVAILABLE,
            ccf::errors::TransactionCommitAttemptsExceedLimit,
            fmt::format(
              "Transaction continued to conflict after {} attempts. Retry "
              "later.",
              max_attempts));
          static constexpr size_t retry_after_seconds = 3;
          ctx->set_response_header(
            http::headers::RETRY_AFTER, retry_after_seconds);
        }
      }
      catch (const std::exception& e)
      {
        ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          e.what());
        update_metrics(ctx, endpoint);
        return ctx->serialise_response();
      }

      return ctx->serialise_response();
    }

  public:
    RpcFrontend(
      kv::Store& tables_,
      endpoints::EndpointRegistry& handlers_,
      ccfapp::AbstractNodeContext& node_context_) :
      tables(tables_),
      endpoints(handlers_),
      node_context(node_context_),
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
      std::shared_ptr<AbstractForwarder> cmd_forwarder_) override
    {
      cmd_forwarder = cmd_forwarder_;
    }

    void open(std::optional<crypto::Pem*> identity = std::nullopt) override
    {
      std::lock_guard<ccf::Pal::Mutex> mguard(open_lock);
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
      std::lock_guard<ccf::Pal::Mutex> mguard(open_lock);
      if (!is_open_)
      {
        auto service = tx.ro<Service>(Tables::SERVICE);
        auto s = service->get_globally_committed();
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

    bool is_open() override
    {
      std::lock_guard<ccf::Pal::Mutex> mguard(open_lock);
      return is_open_;
    }

    void set_root_on_proposals(
      const ccf::RpcContextImpl& ctx, kv::CommittableTx& tx)
    {
      if (
        ctx.get_request_path() == "/gov/proposals" &&
        ctx.get_request_verb() == HTTP_POST)
      {
        update_history();
        if (history)
        {
          // Warning: Retrieving the current TxID and root from the history
          // should only ever be used for the proposal creation endpoint and
          // nothing else. Many bad things could happen otherwise (e.g. breaking
          // session consistency).
          const auto& [txid, root, term_of_next_version] =
            history->get_replicated_state_txid_and_root();
          tx.set_read_txid(txid, term_of_next_version);
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
      std::shared_ptr<ccf::RpcContextImpl> ctx) override
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

      // NB: If we want to re-execute on backups, the original command could be
      // propagated from here
      return process_command(ctx, tx);
    }

    /** Process a serialised input forwarded from another node
     *
     * @param ctx Context for this forwarded RPC
     *
     * @return Serialised reply to send back to forwarder node
     */
    std::vector<uint8_t> process_forwarded(
      std::shared_ptr<ccf::RpcContextImpl> ctx) override
    {
      if (!ctx->get_session_context()->is_forwarded)
      {
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");
      }

      update_consensus();
      auto tx = tables.create_tx();
      set_root_on_proposals(*ctx, tx);

      const auto endpoint = endpoints.find_endpoint(tx, *ctx);
      if (consensus->type() == ConsensusType::CFT)
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
        LOG_FAIL_FMT("Unsupported consensus type");
        return {};
      }
    }

    void tick(std::chrono::milliseconds elapsed) override
    {
      update_consensus();

      endpoints.tick(elapsed);
    }
  };
}
