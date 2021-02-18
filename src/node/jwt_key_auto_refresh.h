// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http/http_builder.h"
#include "http/http_rpc_context.h"
#include "kv/tx.h"
#include "node/jwt.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/serdes.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <mutex>

namespace ccf
{
  class JwtKeyAutoRefresh
  {
  private:
    size_t refresh_interval_s;
    NetworkState& network;
    std::shared_ptr<kv::Consensus> consensus;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    tls::KeyPairPtr node_sign_kp;
    tls::Pem node_cert;

  public:
    JwtKeyAutoRefresh(
      size_t refresh_interval_s,
      NetworkState& network,
      const std::shared_ptr<kv::Consensus>& consensus,
      const std::shared_ptr<enclave::RPCSessions>& rpcsessions,
      const std::shared_ptr<enclave::RPCMap>& rpc_map,
      const tls::KeyPairPtr& node_sign_kp,
      tls::Pem node_cert) :
      refresh_interval_s(refresh_interval_s),
      network(network),
      consensus(consensus),
      rpcsessions(rpcsessions),
      rpc_map(rpc_map),
      node_sign_kp(node_sign_kp),
      node_cert(node_cert)
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
          if (!msg->data.self.consensus->is_primary())
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
          if (!msg->data.self.consensus->is_primary())
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
        ccf::get_actor_prefix(ccf::ActorsType::members),
        "jwt_keys/refresh"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
      request.set_body(&body);

      const auto contents = node_cert.contents();
      crypto::Sha256Hash hash({contents.data(), contents.size()});
      const std::string key_id = fmt::format("{:02x}", fmt::join(hash.h, ""));

      http::sign_request(request, node_sign_kp, key_id);
      auto packed = request.build_request();

      auto node_session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, node_cert.raw());
      auto ctx = enclave::make_rpc_context(node_session, packed);

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
        ca,
        std::nullopt,
        std::nullopt,
        nullb,
        tls::auth_required,
        jwks_url.host);

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
      http_client->send_request(r.build_request());
    }

    void refresh_jwt_keys()
    {
      auto tx = network.tables->create_read_only_tx();
      auto jwt_issuers = tx.ro(network.jwt_issuers);
      auto ca_certs = tx.ro(network.ca_certs);
      jwt_issuers->foreach([this, &ca_certs](
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
        LOG_DEBUG_FMT(
          "JWT key auto-refresh: Refreshing keys for issuer '{}'", issuer);
        auto& ca_cert_name = metadata.ca_cert_name.value();
        auto ca_cert_der = ca_certs->get(ca_cert_name);
        if (!ca_cert_der.has_value())
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: CA cert with name '{}' for issuer '{}' not "
            "found",
            ca_cert_name,
            issuer);
          send_refresh_jwt_keys_error();
          return true;
        }

        auto metadata_url_str = issuer + "/.well-known/openid-configuration";
        auto metadata_url = http::parse_url_full(metadata_url_str);
        auto metadata_url_port =
          !metadata_url.port.empty() ? metadata_url.port : "443";

        auto ca = std::make_shared<tls::CA>(ca_cert_der.value());
        auto ca_cert = std::make_shared<tls::Cert>(
          ca,
          std::nullopt,
          std::nullopt,
          nullb,
          tls::auth_required,
          metadata_url.host);

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
        http_client->send_request(r.build_request());
        return true;
      });
    }
  };

}