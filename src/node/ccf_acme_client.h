// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/actors.h"
#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/ds/json.h"
#include "ccf/endpoint_registry.h"
#include "ccf/http_status.h"
#include "ccf/json_handler.h"
#include "ccf/odata_error.h"
#include "ccf/service/acme_client_config.h"
#include "ccf/service/tables/acme_certificates.h"
#include "enclave/rpc_sessions.h"
#include "node/acme_client.h"
#include "node/network_state.h"
#include "node/rpc/frontend.h"
#include "service/network_tables.h"

#include <chrono>

namespace ccf
{
  namespace
  {
    static inline ACME::ClientConfig get_client_config(
      const ACMEClientConfig& cfg)
    {
      return {
        cfg.ca_certs,
        cfg.directory_url,
        cfg.service_dns_name,
        cfg.contact,
        cfg.terms_of_service_agreed,
        cfg.challenge_type,
        cfg.not_before,
        cfg.not_after};
    }
  }

  class ACMERpcEndpoints : public CommonEndpointRegistry
  {
  public:
    ACMERpcEndpoints(
      NetworkState& network, ccfapp::AbstractNodeContext& context) :
      CommonEndpointRegistry(
        get_actor_prefix(ActorsType::acme_challenge), context)
    {
      auto handler = [this](auto& ctx) {
        try
        {
          const auto& path_params = ctx.rpc_ctx->get_request_path_params();
          const auto url_token_it = path_params.find("token");

          if (url_token_it == path_params.end())
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
            ctx.rpc_ctx->set_response_body("no token in URL");
          }

          std::string token = url_token_it->second;
          std::string response;
          auto tit = prepared_responses.find(token);
          if (tit == prepared_responses.end())
          {
            auto prit = prepared_responses.find("");
            if (prit != prepared_responses.end())
            {
              response = token + "." + prit->second;
            }
            else
            {
              ctx.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
              ctx.rpc_ctx->set_response_body(fmt::format(
                "Challenge response for token '{}' not found", token));
            }
          }
          else
          {
            response = token + "." + tit->second;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
        }
        catch (const std::exception& ex)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx.rpc_ctx->set_response_body(ex.what());
        }
      };

      make_endpoint("/token/{token}", HTTP_GET, handler, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, std::string>()
        .install();
    }

    virtual ~ACMERpcEndpoints() = default;

    void add(const std::string& token, const std::string& response)
    {
      LOG_TRACE_FMT(
        "ACME: challenge server received response for token '{}' ({})",
        token,
        response);

      prepared_responses.emplace(token, response);
    }

    void remove(const std::string& token)
    {
      LOG_TRACE_FMT(
        "ACME: challenge server removed response for token '{}'", token);

      prepared_responses.erase(token);
    }

  protected:
    std::map<std::string, std::string> prepared_responses;
  };

  class ACMERpcFrontend : public RpcFrontend
  {
  protected:
    ACMERpcEndpoints endpoints;

  public:
    ACMERpcFrontend(
      NetworkState& network, ccfapp::AbstractNodeContext& context) :
      RpcFrontend(*network.tables, endpoints),
      endpoints(network, context)
    {}

    virtual ~ACMERpcFrontend() = default;

    void add(const std::string& token, const std::string& response)
    {
      endpoints.add(token, response);
    }

    void remove(const std::string& token)
    {
      endpoints.remove(token);
    }
  };

  class ACMEClient : public ACME::Client
  {
  public:
    ACMEClient(
      const std::string& config_name,
      const ACMEClientConfig& config,
      std::shared_ptr<RPCMap> rpc_map,
      std::shared_ptr<RPCSessions> rpc_sessions,
      std::shared_ptr<ACMERpcFrontend> challenge_frontend,
      std::shared_ptr<kv::Store> store,
      std::shared_ptr<crypto::KeyPair> account_key_pair = nullptr) :
      ACME::Client(get_client_config(config), account_key_pair),
      config_name(config_name),
      rpc_map(rpc_map),
      rpc_sessions(rpc_sessions),
      challenge_frontend(challenge_frontend),
      store(store)
    {}

    virtual ~ACMEClient() {}

    virtual void set_account_key(
      std::shared_ptr<crypto::KeyPair> new_account_key_pair) override
    {
      ACME::Client::set_account_key(new_account_key_pair);
      install_wildcard_response();
    }

    virtual void check_expiry(
      std::shared_ptr<kv::Store> tables,
      std::unique_ptr<NetworkIdentity>& identity)
    {
      auto now = std::chrono::system_clock::now();
      bool renew = false;
      auto tx = tables->create_read_only_tx();
      auto certs = tx.ro<ACMECertificates>(Tables::ACME_CERTIFICATES);
      auto cert = certs->get(config_name);
      if (cert)
      {
        auto v = crypto::make_verifier(*cert);
        double rem_pct = v->remaining_percentage(now);
        LOG_TRACE_FMT(
          "ACME: remaining certificate for '{}' validity: {}%, "
          "{} "
          "seconds",
          config_name,
          100.0 * rem_pct,
          v->remaining_seconds(now));
        renew = rem_pct < 0.33;
      }

      if (renew || !cert)
      {
        get_certificate(make_key_pair(identity->priv_key));
      }
    }

  protected:
    std::string config_name;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RPCSessions> rpc_sessions;
    std::shared_ptr<ACMERpcFrontend> challenge_frontend;
    std::shared_ptr<kv::Store> store;

    void install_wildcard_response()
    {
      // Register a wildcard-response for all challenge tokens. If we use a
      // shared account key, we can use this response on all nodes without
      // further communication.
      on_challenge("", make_challenge_response());
    }

    virtual void on_http_request(
      const http::URL& url,
      std::vector<uint8_t>&& req,
      std::function<
        bool(http_status status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback) override
    {
      auto ca = std::make_shared<tls::CA>(config.ca_certs, true);
      auto ca_cert = std::make_shared<tls::Cert>(ca);
      auto client = rpc_sessions->create_client(ca_cert);

      client->connect(
        url.host,
        url.port,
        [callback](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          return callback(status, std::move(headers), std::move(data));
        });
      client->send_request(std::move(req));
    }

    virtual void on_challenge(
      const std::string& token, const std::string& response) override
    {
      challenge_frontend->add(token, response);
      start_challenge(token);
    }

    virtual void on_challenge_finished(const std::string& token) override
    {
      challenge_frontend->remove(token);
    }

    virtual void on_certificate(const std::string& certificate) override
    {
      // Write the endorsed certificate to the certificate table; all nodes
      // will install it later, in the global hook on that table.
      auto tx = store->create_tx();
      auto certs = tx.rw<ACMECertificates>(Tables::ACME_CERTIFICATES);
      certs->put(config_name, crypto::Pem(certificate));
      tx.commit();
    }
  };
}
