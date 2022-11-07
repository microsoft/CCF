// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/serdes.h"
#include "ccf/service/tables/jwt.h"
#include "http/http_builder.h"
#include "http/http_rpc_context.h"
#include "node/rpc/node_frontend.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  class JwtKeyAutoRefresh
  {
  private:
    size_t refresh_interval_s;
    NetworkState& network;
    std::shared_ptr<kv::Consensus> consensus;
    std::shared_ptr<ccf::RPCSessions> rpcsessions;
    std::shared_ptr<ccf::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    crypto::Pem node_cert;
    std::atomic_size_t attempts;

  public:
    JwtKeyAutoRefresh(
      size_t refresh_interval_s,
      NetworkState& network,
      const std::shared_ptr<kv::Consensus>& consensus,
      const std::shared_ptr<ccf::RPCSessions>& rpcsessions,
      const std::shared_ptr<ccf::RPCMap>& rpc_map,
      const crypto::KeyPairPtr& node_sign_kp,
      const crypto::Pem& node_cert) :
      refresh_interval_s(refresh_interval_s),
      network(network),
      consensus(consensus),
      rpcsessions(rpcsessions),
      rpc_map(rpc_map),
      node_sign_kp(node_sign_kp),
      node_cert(node_cert),
      attempts(0)
    {}

    struct RefreshTimeMsg
    {
      RefreshTimeMsg(JwtKeyAutoRefresh& self_) : self(self_) {}

      JwtKeyAutoRefresh& self;
    };

    void start()
    {
      auto refresh_msg = std::make_unique<threading::Tmsg<RefreshTimeMsg>>(
        [](std::unique_ptr<threading::Tmsg<RefreshTimeMsg>> msg) {
          if (!msg->data.self.consensus->can_replicate())
          {
            LOG_DEBUG_FMT(
              "JWT key auto-refresh: Node is not primary, skipping");
          }
          else
          {
            msg->data.self.refresh_jwt_keys();
          }
          LOG_DEBUG_FMT(
            "JWT key auto-refresh: Scheduling in {}s",
            msg->data.self.refresh_interval_s);
          auto delay = std::chrono::seconds(msg->data.self.refresh_interval_s);
          threading::ThreadMessaging::thread_messaging.add_task_after(
            std::move(msg), delay);
        },
        *this);

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Scheduling in {}s", refresh_interval_s);
      auto delay = std::chrono::seconds(refresh_interval_s);
      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(refresh_msg), delay);
    }

    void schedule_once()
    {
      auto refresh_msg = std::make_unique<threading::Tmsg<RefreshTimeMsg>>(
        [](std::unique_ptr<threading::Tmsg<RefreshTimeMsg>> msg) {
          if (!msg->data.self.consensus->can_replicate())
          {
            LOG_DEBUG_FMT(
              "JWT key one-off refresh: Node is not primary, skipping");
          }
          else
          {
            msg->data.self.refresh_jwt_keys();
          }
        },
        *this);

      LOG_DEBUG_FMT("JWT key one-off refresh: Scheduling without delay");
      auto delay = std::chrono::seconds(0);
      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(refresh_msg), delay);
    }

    template <typename T>
    void send_refresh_jwt_keys(T msg)
    {
      auto body = serdes::pack(msg, serdes::Pack::Text);

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "jwt_keys/refresh"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
      request.set_body(&body);

      auto packed = request.build_request();

      auto node_session = std::make_shared<ccf::SessionContext>(
        ccf::InvalidSessionId, node_cert.raw());
      auto ctx = ccf::make_rpc_context(node_session, packed);

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error("Unable to get actor");
      }

      const auto actor = rpc_map->resolve(actor_opt.value());
      auto frontend_opt = this->rpc_map->find(actor);
      if (!frontend_opt.has_value())
      {
        throw std::logic_error(
          "RpcMap::find returned invalid (empty) frontend");
      }
      auto frontend = frontend_opt.value();
      frontend->process(ctx);
    }

    void send_refresh_jwt_keys_error()
    {
      // A message that the endpoint fails to parse, leading to 500.
      // This is done purely for exposing errors as endpoint metrics.
      auto msg = false;
      send_refresh_jwt_keys(msg);
    }

    void handle_jwt_jwks_response(
      const std::string& issuer,
      http_status status,
      std::vector<uint8_t>&& data)
    {
      if (status != HTTP_STATUS_OK)
      {
        LOG_FAIL_FMT(
          "JWT key auto-refresh: Error while requesting JWKS: {} {}{}",
          status,
          http_status_str(status),
          data.empty() ?
            "" :
            fmt::format("  '{}'", std::string(data.begin(), data.end())));
        send_refresh_jwt_keys_error();
        return;
      }

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Received JWKS for issuer '{}'", issuer);

      JsonWebKeySet jwks;
      try
      {
        jwks = nlohmann::json::parse(data).get<JsonWebKeySet>();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "JWT key auto-refresh: Cannot parse JWKS for issuer '{}': {}",
          issuer,
          e.what());
        send_refresh_jwt_keys_error();
        return;
      }

      // call internal endpoint to update keys
      auto msg = SetJwtPublicSigningKeys{issuer, jwks};
      send_refresh_jwt_keys(msg);
    }

    void handle_jwt_metadata_response(
      const std::string& issuer,
      std::shared_ptr<tls::CA> ca,
      http_status status,
      std::vector<uint8_t>&& data)
    {
      if (status != HTTP_STATUS_OK)
      {
        LOG_FAIL_FMT(
          "JWT key auto-refresh: Error while requesting OpenID metadata: {} "
          "{}{}",
          status,
          http_status_str(status),
          data.empty() ?
            "" :
            fmt::format("  '{}'", std::string(data.begin(), data.end())));
        send_refresh_jwt_keys_error();
        return;
      }

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Received OpenID metadata for issuer '{}'",
        issuer);

      std::string jwks_url_str;
      try
      {
        auto metadata = nlohmann::json::parse(data);
        jwks_url_str = metadata.at("jwks_uri").get<std::string>();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "JWT key auto-refresh: Cannot parse OpenID metadata for issuer '{}': "
          "{}",
          issuer,
          e.what());
        send_refresh_jwt_keys_error();
        return;
      }
      http::URL jwks_url;
      try
      {
        jwks_url = http::parse_url_full(jwks_url_str);
      }
      catch (const std::invalid_argument& e)
      {
        LOG_FAIL_FMT(
          "JWT key auto-refresh: Cannot parse jwks_uri for issuer '{}': {}",
          issuer,
          jwks_url_str);
        send_refresh_jwt_keys_error();
        return;
      }
      auto jwks_url_port = !jwks_url.port.empty() ? jwks_url.port : "443";

      auto ca_cert = std::make_shared<tls::Cert>(
        ca, std::nullopt, std::nullopt, jwks_url.host);

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Requesting JWKS at https://{}:{}{}",
        jwks_url.host,
        jwks_url_port,
        jwks_url.path);
      auto http_client = rpcsessions->create_client(ca_cert);
      // Note: Connection errors are not signalled and hence not tracked in
      // endpoint metrics currently.
      http_client->connect(
        std::string(jwks_url.host),
        std::string(jwks_url_port),
        [this, issuer](
          http_status status, http::HeaderMap&&, std::vector<uint8_t>&& data) {
          handle_jwt_jwks_response(issuer, status, std::move(data));
          return true;
        });
      http::Request r(jwks_url.path, HTTP_GET);
      r.set_header(http::headers::HOST, std::string(jwks_url.host));
      http_client->send_request(std::move(r));
    }

    void refresh_jwt_keys()
    {
      auto tx = network.tables->create_read_only_tx();
      auto jwt_issuers = tx.ro(network.jwt_issuers);
      auto ca_cert_bundles = tx.ro(network.ca_cert_bundles);
      jwt_issuers->foreach([this, &ca_cert_bundles](
                             const JwtIssuer& issuer,
                             const JwtIssuerMetadata& metadata) {
        if (!metadata.auto_refresh)
        {
          LOG_DEBUG_FMT(
            "JWT key auto-refresh: Skipping issuer '{}', auto-refresh is "
            "disabled",
            issuer);
          return true;
        }

        // Increment attempts, only when auto-refresh is enabled.
        attempts++;

        LOG_DEBUG_FMT(
          "JWT key auto-refresh: Refreshing keys for issuer '{}'", issuer);
        auto& ca_cert_bundle_name = metadata.ca_cert_bundle_name.value();
        auto ca_cert_bundle_pem = ca_cert_bundles->get(ca_cert_bundle_name);
        if (!ca_cert_bundle_pem.has_value())
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: CA cert bundle with name '{}' for issuer "
            "'{}' not "
            "found",
            ca_cert_bundle_name,
            issuer);
          send_refresh_jwt_keys_error();
          return true;
        }

        auto metadata_url_str = issuer + "/.well-known/openid-configuration";
        auto metadata_url = http::parse_url_full(metadata_url_str);
        auto metadata_url_port =
          !metadata_url.port.empty() ? metadata_url.port : "443";

        auto ca = std::make_shared<tls::CA>(ca_cert_bundle_pem.value());
        auto ca_cert = std::make_shared<tls::Cert>(
          ca, std::nullopt, std::nullopt, metadata_url.host);

        LOG_DEBUG_FMT(
          "JWT key auto-refresh: Requesting OpenID metadata at https://{}:{}{}",
          metadata_url.host,
          metadata_url_port,
          metadata_url.path);
        auto http_client = rpcsessions->create_client(ca_cert);
        // Note: Connection errors are not signalled and hence not tracked in
        // endpoint metrics currently.
        http_client->connect(
          std::string(metadata_url.host),
          std::string(metadata_url_port),
          [this, issuer, ca](
            http_status status,
            http::HeaderMap&&,
            std::vector<uint8_t>&& data) {
            handle_jwt_metadata_response(issuer, ca, status, std::move(data));
            return true;
          });
        http::Request r(metadata_url.path, HTTP_GET);
        r.set_header(http::headers::HOST, std::string(metadata_url.host));
        http_client->send_request(std::move(r));
        return true;
      });
    }

    // Returns a copy of the current attempts
    size_t get_attempts() const
    {
      return attempts.load();
    }
  };
}
