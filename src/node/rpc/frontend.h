// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_registry.h"
#include "ccf/http_status.h"
#include "ccf/node_context.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_exception.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/signed_req.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "common/configuration.h"
#include "enclave/rpc_handler.h"
#include "forwarder.h"
#include "http/http_jwt.h"
#include "http/http_rpc_context.h"
#include "kv/compacted_version_conflict.h"
#include "kv/store.h"
#include "node/endpoint_context_impl.h"
#include "node/node_configuration_subsystem.h"
#include "service/internal_tables_access.h"

#define FMT_HEADER_ONLY

#include <fmt/format.h>
#include <utility>
#include <vector>

namespace ccf
{
  class RpcFrontend : public RpcHandler, public ForwardedRpcHandler
  {
  protected:
    ccf::kv::Store& tables;
    endpoints::EndpointRegistry& endpoints;
    ccf::AbstractNodeContext& node_context;

  private:
    ccf::pal::Mutex open_lock;
    bool is_open_ = false;

    ccf::kv::Consensus* consensus;
    std::shared_ptr<AbstractForwarder> cmd_forwarder;
    ccf::kv::TxHistory* history;

    size_t sig_tx_interval = 5000;
    std::chrono::milliseconds sig_ms_interval = std::chrono::milliseconds(1000);
    std::chrono::milliseconds ms_to_sig = std::chrono::milliseconds(1000);

    std::shared_ptr<NodeConfigurationSubsystem> node_configuration_subsystem =
      nullptr;

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

    endpoints::EndpointDefinitionPtr find_endpoint(
      std::shared_ptr<ccf::RpcContextImpl> ctx, ccf::kv::CommittableTx& tx)
    {
      const auto endpoint = endpoints.find_endpoint(tx, *ctx);
      if (endpoint == nullptr)
      {
        // Every path from here should populate an appropriate response error
        const auto allowed_verbs = endpoints.get_allowed_verbs(tx, *ctx);
        if (allowed_verbs.empty())
        {
          ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format("Unknown path: {}.", ctx->get_method()));
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
        }
      }

      return endpoint;
    }

    bool check_uri_allowed(
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      const endpoints::EndpointDefinitionPtr& endpoint)
    {
      auto interface_id = ctx->get_session_context()->interface_id;
      if (consensus && interface_id)
      {
        if (!node_configuration_subsystem)
        {
          node_configuration_subsystem =
            node_context.get_subsystem<NodeConfigurationSubsystem>();
          if (!node_configuration_subsystem)
          {
            ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
            return false;
          }
        }

        auto& ncs = node_configuration_subsystem->get();

        const auto& required_features = endpoint->required_operator_features;
        if (!required_features.empty())
        {
          // Check that all required opt-in features are present on this
          // interface's enabled features
          const auto& interfaces = ncs.node_config.network.rpc_interfaces;
          auto interface_it = interfaces.find(*interface_id);
          if (interface_it == interfaces.end())
          {
            throw std::runtime_error(fmt::format(
              "Could not find RPC interface named '{}' in startup config",
              *interface_id));
          }

          const auto& enabled_features =
            interface_it->second.enabled_operator_features;
          for (const auto& required_feature : required_features)
          {
            if (
              enabled_features.find(required_feature) == enabled_features.end())
            {
              LOG_INFO_FMT(
                "Incoming request {} requires opt-in feature {}, which is not "
                "enabled on interface {} where this request was received - "
                "returning error",
                endpoint->full_uri_path,
                required_feature,
                *interface_id);
              ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
              return false;
            }
          }
        }

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
            return false;
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
            return false;
          }
        }
      }
      else
      {
        // internal or forwarded: OK because they have been checked by the
        // forwarder (forward() happens further down).
      }

      return true;
    }

    std::optional<std::string> resolve_redirect_location(
      const RedirectionResolverConfig& resolver,
      ccf::kv::ReadOnlyTx& tx,
      const ccf::ListenInterfaceID& incoming_interface)
    {
      switch (resolver.kind)
      {
        case (RedirectionResolutionKind::NodeByRole):
        {
          const auto role_it = resolver.target.find("role");
          const bool seeking_primary =
            role_it == resolver.target.end() || role_it.value() == "primary";
          const bool seeking_backup =
            !seeking_primary && role_it.value() == "backup";
          if (!seeking_primary && !seeking_backup)
          {
            return std::nullopt;
          }

          const auto interface_it = resolver.target.find("interface");
          const auto target_interface =
            (interface_it == resolver.target.end()) ?
            incoming_interface :
            interface_it.value().get<std::string>();

          std::vector<std::map<NodeId, NodeInfo>::const_iterator>
            target_node_its;
          const auto nodes = InternalTablesAccess::get_trusted_nodes(tx);
          {
            const auto primary_id = consensus->primary();
            if (seeking_primary && primary_id.has_value())
            {
              target_node_its.push_back(nodes.find(primary_id.value()));
            }
            else if (seeking_backup)
            {
              for (auto it = nodes.begin(); it != nodes.end(); ++it)
              {
                if (it->first != primary_id)
                {
                  target_node_its.push_back(it);
                }
              }
            }
          }
          if (target_node_its.empty())
          {
            return std::nullopt;
          }

          const auto node_it = target_node_its[rand() % target_node_its.size()];
          if (node_it != nodes.end())
          {
            const auto& interfaces = node_it->second.rpc_interfaces;

            const auto target_interface_it = interfaces.find(target_interface);
            if (target_interface_it != interfaces.end())
            {
              return target_interface_it->second.published_address;
            }
          }
          else
          {
            return std::nullopt;
          }
          break;
        }

        case (RedirectionResolutionKind::StaticAddress):
        {
          return resolver.target["address"].get<std::string>();
          break;
        }
      }

      return std::nullopt;
    }

    bool check_redirect(
      ccf::kv::ReadOnlyTx& tx,
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      const endpoints::EndpointDefinitionPtr& endpoint,
      const ccf::NodeInfoNetwork_v2::NetInterface::Redirections& redirections)
    {
      auto rs = endpoint->properties.redirection_strategy;

      switch (rs)
      {
        case (ccf::endpoints::RedirectionStrategy::None):
        {
          return false;
        }

        case (ccf::endpoints::RedirectionStrategy::ToPrimary):
        {
          const bool is_primary =
            (consensus != nullptr) && consensus->can_replicate();

          if (!is_primary)
          {
            auto resolver = redirections.to_primary;

            const auto listen_interface =
              ctx->get_session_context()->interface_id.value_or(
                PRIMARY_RPC_INTERFACE);
            const auto location =
              resolve_redirect_location(resolver, tx, listen_interface);
            if (location.has_value())
            {
              ctx->set_response_header(
                http::headers::LOCATION,
                fmt::format(
                  "https://{}{}", location.value(), ctx->get_request_url()));
              ctx->set_response_status(HTTP_STATUS_TEMPORARY_REDIRECT);
              return true;
            }

            // Should have redirected, but don't know how to. Return an error
            ctx->set_error(
              HTTP_STATUS_SERVICE_UNAVAILABLE,
              ccf::errors::PrimaryNotFound,
              "Request should be redirected to primary, but receiving node "
              "does not know current primary address");
            return true;
          }
          return false;
        }

        case (ccf::endpoints::RedirectionStrategy::ToBackup):
        {
          const bool is_backup =
            (consensus != nullptr) && !consensus->can_replicate();

          if (!is_backup)
          {
            auto resolver = redirections.to_backup;

            const auto listen_interface =
              ctx->get_session_context()->interface_id.value_or(
                PRIMARY_RPC_INTERFACE);
            const auto location =
              resolve_redirect_location(resolver, tx, listen_interface);
            if (location.has_value())
            {
              ctx->set_response_header(
                http::headers::LOCATION,
                fmt::format(
                  "https://{}{}", location.value(), ctx->get_request_url()));
              ctx->set_response_status(HTTP_STATUS_TEMPORARY_REDIRECT);
              return true;
            }

            // Should have redirected, but don't know how to. Return an error
            ctx->set_error(
              HTTP_STATUS_SERVICE_UNAVAILABLE,
              ccf::errors::BackupNotFound,
              "Request should be redirected to backup, but receiving node "
              "does not know any current backup address");
            return true;
          }
          return false;
        }

        default:
        {
          LOG_FAIL_FMT("Unhandled redirection strategy: {}", rs);
          return false;
        }
      }
    }

    std::optional<ccf::NodeInfoNetwork_v2::NetInterface::Redirections>
    get_redirections_config(const ccf::ListenInterfaceID& incoming_interface)
    {
      if (!node_configuration_subsystem)
      {
        node_configuration_subsystem =
          node_context.get_subsystem<NodeConfigurationSubsystem>();
        if (!node_configuration_subsystem)
        {
          LOG_FAIL_FMT("Unable to access NodeConfigurationSubsystem");
          return std::nullopt;
        }
      }

      const auto& node_config_state = node_configuration_subsystem->get();
      const auto& interfaces =
        node_config_state.node_config.network.rpc_interfaces;
      const auto interface_it = interfaces.find(incoming_interface);
      if (interface_it == interfaces.end())
      {
        LOG_FAIL_FMT(
          "Could not find startup config for interface {}", incoming_interface);
        return std::nullopt;
      }

      return interface_it->second.redirections;
    }

    bool check_session_consistency(std::shared_ptr<ccf::RpcContextImpl> ctx)
    {
      if (consensus != nullptr)
      {
        auto current_view = consensus->get_view();
        auto session_ctx = ctx->get_session_context();
        if (!session_ctx->active_view.has_value())
        {
          // First request on this session - assign the active term
          session_ctx->active_view = current_view;
        }
        else if (current_view != session_ctx->active_view.value())
        {
          auto msg = fmt::format(
            "Potential loss of session consistency on session {}. Started "
            "in view {}, now in view {}. Closing session.",
            session_ctx->client_session_id,
            session_ctx->active_view.value(),
            current_view);
          LOG_INFO_FMT("{}", msg);

          ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::SessionConsistencyLost,
            std::move(msg));
          ctx->terminate_session = true;
          return false;
        }
      }

      return true;
    }

    std::unique_ptr<AuthnIdentity> get_authenticated_identity(
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      ccf::kv::CommittableTx& tx,
      const endpoints::EndpointDefinitionPtr& endpoint)
    {
      if (endpoint->authn_policies.empty())
      {
        return nullptr;
      }

      std::unique_ptr<AuthnIdentity> identity = nullptr;

      std::string auth_error_reason;
      std::vector<ODataAuthErrorDetails> error_details;
      for (const auto& policy : endpoint->authn_policies)
      {
        identity = policy->authenticate(tx, ctx, auth_error_reason);
        if (identity != nullptr)
        {
          break;
        }
        else
        {
          // Collate error details
          error_details.emplace_back(ODataAuthErrorDetails{
            policy->get_security_scheme_name(),
            ccf::errors::InvalidAuthenticationInfo,
            auth_error_reason});
        }
      }

      if (identity == nullptr)
      {
        // If none were accepted, let the last set the response header
        endpoint->authn_policies.back()->set_unauthenticated_error(
          ctx, std::move(auth_error_reason));
        // Return collated error details for the auth policies
        // declared in the request
        std::vector<nlohmann::json> json_details;
        for (auto& details : error_details)
        {
          json_details.push_back(details);
        }
        ctx->set_error(
          HTTP_STATUS_UNAUTHORIZED,
          ccf::errors::InvalidAuthenticationInfo,
          "Invalid authentication credentials.",
          std::move(json_details));
      }

      return identity;
    }

    std::chrono::milliseconds get_forwarding_timeout(
      std::shared_ptr<ccf::RpcContextImpl> ctx) const
    {
      auto r = std::chrono::milliseconds(3'000);

      auto interface_id = ctx->get_session_context()->interface_id;
      if (interface_id.has_value())
      {
        auto& ncs = node_configuration_subsystem->get();
        auto rit = ncs.node_config.network.rpc_interfaces.find(*interface_id);
        if (rit != ncs.node_config.network.rpc_interfaces.end())
        {
          if (rit->second.forwarding_timeout_ms.has_value())
          {
            r = std::chrono::milliseconds(*rit->second.forwarding_timeout_ms);
          }
        }
      }

      return r;
    }

    void forward(
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      ccf::kv::ReadOnlyTx& tx,
      const endpoints::EndpointDefinitionPtr& endpoint)
    {
      // HTTP/2 does not support forwarding
      if (ctx->get_http_version() == HttpVersion::HTTP2)
      {
        ctx->set_error(
          HTTP_STATUS_NOT_IMPLEMENTED,
          ccf::errors::NotImplemented,
          "Request cannot be forwarded to primary on HTTP/2 interface.");

        return;
      }

      if (!cmd_forwarder || !consensus)
      {
        ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "No consensus or forwarder to forward request.");

        return;
      }

      if (ctx->get_session_context()->is_forwarded)
      {
        // If the request was already forwarded, return an error to prevent
        // daisy chains.
        ctx->set_error(
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::RequestAlreadyForwarded,
          "RPC was already forwarded.");

        return;
      }

      // Before attempting to forward, make sure we're in the same View as we
      // previously thought we were.
      if (!check_session_consistency(ctx))
      {
        return;
      }

      auto primary_id = consensus->primary();
      if (!primary_id.has_value())
      {
        ctx->set_error(
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::InternalError,
          "RPC could not be forwarded to unknown primary.");

        return;
      }

      if (!cmd_forwarder->forward_command(
            ctx,
            primary_id.value(),
            ctx->get_session_context()->caller_cert,
            get_forwarding_timeout(ctx)))
      {
        ctx->set_error(
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::InternalError,
          "Unable to establish channel to forward to primary.");

        return;
      }

      LOG_TRACE_FMT("RPC forwarded to primary {}", primary_id.value());

      // Indicate that the RPC has been forwarded to primary
      ctx->response_is_pending = true;

      // Ensure future requests on this session are forwarded for session
      // consistency
      ctx->get_session_context()->is_forwarding = true;

      return;
    }

    void process_command(std::shared_ptr<ccf::RpcContextImpl> ctx)
    {
      size_t attempts = 0;
      endpoints::EndpointDefinitionPtr endpoint = nullptr;

      const auto start_time = std::chrono::high_resolution_clock::now();

      process_command_inner(ctx, endpoint, attempts);

      const auto end_time = std::chrono::high_resolution_clock::now();

      if (endpoint != nullptr)
      {
        endpoints::RequestCompletedEvent rce;
        rce.method = endpoint->dispatch.verb.c_str();
        rce.dispatch_path = endpoint->dispatch.uri_path;
        rce.status = ctx->get_response_status();
        // Although enclave time returns a microsecond value, the actual
        // precision/granularity depends on the host's TimeUpdater. By default
        // this only advances each millisecond. Avoid implying more precision
        // than that, by rounding to milliseconds
        rce.exec_time = std::chrono::duration_cast<std::chrono::milliseconds>(
          end_time - start_time);
        rce.attempts = attempts;

        endpoints.handle_event_request_completed(rce);
      }
      else
      {
        endpoints::DispatchFailedEvent dfe;
        dfe.method = ctx->get_method();
        dfe.status = ctx->get_response_status();

        endpoints.handle_event_dispatch_failed(dfe);
      }
    }

    void process_command_inner(
      std::shared_ptr<ccf::RpcContextImpl> ctx,
      endpoints::EndpointDefinitionPtr& endpoint,
      size_t& attempts)
    {
      constexpr auto max_attempts = 30;
      while (attempts < max_attempts)
      {
        if (consensus != nullptr)
        {
          if (
            endpoints.apply_uncommitted_tx_backpressure() &&
            consensus->is_at_max_capacity())
          {
            ctx->set_error(
              HTTP_STATUS_SERVICE_UNAVAILABLE,
              ccf::errors::TooManyPendingTransactions,
              "Too many transactions pending commit on the service.");
            return;
          }
        }

        std::unique_ptr<ccf::kv::CommittableTx> tx_p = tables.create_tx_ptr();
        set_root_on_proposals(*ctx, *tx_p);

        if (attempts > 0)
        {
          // If the endpoint has already been executed, the effects of its
          // execution should be dropped
          ctx->reset_response();
        }

        if (!is_open())
        {
          ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::FrontendNotOpen,
            "Frontend is not open.");
          return;
        }

        ++attempts;
        update_history();

        endpoint = find_endpoint(ctx, *tx_p);
        if (endpoint == nullptr)
        {
          return;
        }

        try
        {
          if (!check_uri_allowed(ctx, endpoint))
          {
            return;
          }

          std::optional<ccf::NodeInfoNetwork_v2::NetInterface::Redirections>
            redirections = std::nullopt;

          // If there's no interface ID, this is already forwarded or otherwise
          // special - don't try to redirect it
          if (ctx->get_session_context()->interface_id.has_value())
          {
            redirections = get_redirections_config(
              ctx->get_session_context()->interface_id.value());
          }

          // If a redirections config was specified, then redirections are used
          // and no forwarding is done
          if (redirections.has_value())
          {
            if (check_redirect(*tx_p, ctx, endpoint, redirections.value()))
            {
              return;
            }
          }
          else
          {
            bool is_primary =
              (consensus == nullptr) || consensus->can_replicate();
            const bool forwardable = (consensus != nullptr);

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
                  if (ctx->get_session_context()->is_forwarding)
                  {
                    forward(ctx, *tx_p, endpoint);
                    return;
                  }
                  break;
                }

                case endpoints::ForwardingRequired::Always:
                {
                  forward(ctx, *tx_p, endpoint);
                  return;
                }
              }
            }
          }

          std::unique_ptr<AuthnIdentity> identity =
            get_authenticated_identity(ctx, *tx_p, endpoint);

          auto args = ccf::EndpointContextImpl(ctx, std::move(tx_p));
          // NB: tx_p is no longer valid, and must be accessed from args, which
          // may change it!

          // If any auth policy was required, check that at least one is
          // accepted
          if (!endpoint->authn_policies.empty())
          {
            if (identity == nullptr)
            {
              return;
            }
            else
            {
              args.caller = std::move(identity);
            }
          }

          endpoints.execute_endpoint(endpoint, args);

          // If we've seen a View change, abandon this transaction as
          // inconsistent
          if (!check_session_consistency(ctx))
          {
            return;
          }

          if (!ctx->should_apply_writes())
          {
            return;
          }

          if (ctx->response_is_pending)
          {
            return;
          }
          else if (args.owned_tx == nullptr)
          {
            LOG_FAIL_FMT(
              "Bad endpoint: During execution of {} {}, returned a non-pending "
              "response but stole ownership of Tx object",
              ctx->get_request_verb().c_str(),
              ctx->get_request_path());

            ctx->clear_response_headers();
            ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Illegal endpoint implementation");
            return;
          }
          // else args owns a valid Tx relating to a non-pending response, which
          // should be applied
          ccf::kv::CommittableTx& tx = *args.owned_tx;
          ccf::kv::CommitResult result = tx.commit(ctx->claims);

          switch (result)
          {
            case ccf::kv::CommitResult::SUCCESS:
            {
              auto tx_id_opt = tx.get_txid();
              if (tx_id_opt.has_value() && consensus != nullptr)
              {
                ccf::TxID tx_id = tx_id_opt.value();

                try
                {
                  // Only transactions that acquired one or more map handles
                  // have a TxID, while others (e.g. unauthenticated commands)
                  // don't. Also, only report a TxID if the consensus is set, as
                  // the consensus is required to verify that a TxID is valid.
                  endpoints.execute_endpoint_locally_committed(
                    endpoint, args, tx_id);
                }
                catch (const std::exception& e)
                {
                  // run default handler to set transaction id in header
                  ctx->clear_response_headers();
                  ccf::endpoints::default_locally_committed_func(args, tx_id);
                  ctx->set_error(
                    HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    ccf::errors::InternalError,
                    fmt::format(
                      "Failed to execute local commit handler func: {}",
                      e.what()));
                }
                catch (...)
                {
                  // run default handler to set transaction id in header
                  ctx->clear_response_headers();
                  ccf::endpoints::default_locally_committed_func(args, tx_id);
                  ctx->set_error(
                    HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    ccf::errors::InternalError,
                    "Failed to execute local commit handler func");
                }

                if (ctx->respond_on_commit)
                {
                  ctx->set_respond_on_commit_txid(tx_id);
                }
              }

              if (
                consensus != nullptr && consensus->can_replicate() &&
                history != nullptr)
              {
                history->try_emit_signature();
              }

              return;
            }

            case ccf::kv::CommitResult::FAIL_CONFLICT:
            {
              break;
            }

            case ccf::kv::CommitResult::FAIL_NO_REPLICATE:
            {
              ctx->clear_response_headers();
              ctx->set_error(
                HTTP_STATUS_SERVICE_UNAVAILABLE,
                ccf::errors::TransactionReplicationFailed,
                "Transaction failed to replicate.");

              return;
            }
          }
        }
        catch (const ccf::kv::CompactedVersionConflict& e)
        {
          // The executing transaction failed because of a conflicting
          // compaction. Reset and retry
          LOG_DEBUG_FMT(
            "Transaction execution conflicted with compaction: {}", e.what());
          continue;
        }
        catch (RpcException& e)
        {
          ctx->clear_response_headers();
          ctx->set_error(std::move(e.error));

          return;
        }
        catch (const ccf::JsonParseError& e)
        {
          ctx->clear_response_headers();
          ctx->set_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, e.describe());

          return;
        }
        catch (const nlohmann::json::exception& e)
        {
          ctx->clear_response_headers();
          ctx->set_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, e.what());

          return;
        }
        catch (const ccf::kv::KvSerialiserException& e)
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
          ctx->clear_response_headers();
          ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            e.what());

          return;
        }
      } // end of while loop

      ctx->clear_response_headers();
      ctx->set_error(
        HTTP_STATUS_SERVICE_UNAVAILABLE,
        ccf::errors::TransactionCommitAttemptsExceedLimit,
        fmt::format(
          "Transaction continued to conflict after {} attempts. Retry "
          "later.",
          max_attempts));

      static constexpr size_t retry_after_seconds = 3;
      ctx->set_response_header(http::headers::RETRY_AFTER, retry_after_seconds);

      return;
    }

  public:
    RpcFrontend(
      ccf::kv::Store& tables_,
      endpoints::EndpointRegistry& handlers_,
      ccf::AbstractNodeContext& node_context_) :
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

    void open() override
    {
      std::lock_guard<ccf::pal::Mutex> mguard(open_lock);
      if (!is_open_)
      {
        LOG_INFO_FMT("Opening frontend");
        is_open_ = true;
        endpoints.init_handlers();
      }
    }

    bool is_open() override
    {
      std::lock_guard<ccf::pal::Mutex> mguard(open_lock);
      return is_open_;
    }

    void set_root_on_proposals(
      const ccf::RpcContextImpl& ctx, ccf::kv::CommittableTx& tx)
    {
      if (endpoints.request_needs_root(ctx))
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
     * @param ctx Context for this RPC. Will be populated with response details
     * before this call returns, or else response_is_pending will be set to true
     */
    void process(std::shared_ptr<ccf::RpcContextImpl> ctx) override
    {
      update_consensus();

      // NB: If we want to re-execute on backups, the original command could
      // be propagated from here
      process_command(ctx);
    }

    /** Process a serialised input forwarded from another node
     *
     * @param ctx Context for this forwarded RPC
     */
    void process_forwarded(std::shared_ptr<ccf::RpcContextImpl> ctx) override
    {
      if (!ctx->get_session_context()->is_forwarded)
      {
        throw std::logic_error(
          "Processing forwarded command with unitialised forwarded context");
      }

      update_consensus();
      process_command(ctx);
      if (ctx->response_is_pending)
      {
        // This should never be called when process_command is called with a
        // forwarded RPC context
        throw std::logic_error("Forwarded RPC cannot be forwarded");
      }
    }

    void tick(std::chrono::milliseconds elapsed) override
    {
      update_consensus();

      endpoints.tick(elapsed);
    }
  };
}
