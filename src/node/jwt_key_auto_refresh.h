// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/nonstd.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/jwt.h"
#include "http/curl.h"
#include "http/http_builder.h"
#include "http/http_rpc_context.h"
#include "node/rpc/node_frontend.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#define FMT_HEADER_ONLY
#include <algorithm>
#include <curl/curl.h>
#include <fmt/format.h>
#include <map>

namespace ccf
{
  class JwtKeyAutoRefresh
    : public std::enable_shared_from_this<JwtKeyAutoRefresh>
  {
  private:
    size_t refresh_interval_s;
    NetworkState& network;
    std::shared_ptr<ccf::kv::Consensus> consensus;
    std::shared_ptr<ccf::RPCMap> rpc_map;
    ccf::crypto::ECKeyPairPtr node_sign_kp;
    ccf::crypto::Pem node_cert;
    std::atomic_size_t attempts;
    std::atomic_bool stopped;
    size_t max_response_size;

    ccf::tasks::Task periodic_refresh_task;

    struct RetryState
    {
      size_t delay_s;
      size_t generation = 0;
      ccf::tasks::Task task = nullptr;
    };

    ccf::pal::Mutex retry_states_lock;
    std::map<JwtIssuer, RetryState> retry_states
      CCF_GUARDED_BY(retry_states_lock);
    size_t next_retry_generation CCF_GUARDED_BY(retry_states_lock) = 0;

    static constexpr size_t initial_retry_delay_s = 5;
    static constexpr long request_connection_timeout_s = 5;
    static constexpr long request_response_timeout_s = 5;

    bool begin_retry(const JwtIssuer& issuer, size_t generation)
    {
      ccf::pal::MutexGuard guard(retry_states_lock);
      const auto it = retry_states.find(issuer);
      if (
        it == retry_states.end() || it->second.generation != generation ||
        it->second.task == nullptr)
      {
        return false;
      }

      it->second.task = nullptr;
      return true;
    }

    void cancel_retry(const JwtIssuer& issuer)
    {
      ccf::pal::MutexGuard guard(retry_states_lock);
      const auto it = retry_states.find(issuer);
      if (it == retry_states.end())
      {
        return;
      }

      if (it->second.task != nullptr)
      {
        it->second.task->cancel_task();
      }
      retry_states.erase(it);
    }

    void cancel_retries()
    {
      ccf::pal::MutexGuard guard(retry_states_lock);
      for (auto& retry_state_entry : retry_states)
      {
        auto& retry_state = retry_state_entry.second;
        if (retry_state.task != nullptr)
        {
          retry_state.task->cancel_task();
        }
      }
      retry_states.clear();
    }

    void schedule_retry(const JwtIssuer& issuer)
    {
      ccf::tasks::Task retry_task;
      size_t delay_s = 0;
      {
        ccf::pal::MutexGuard guard(retry_states_lock);
        if (stopped.load())
        {
          return;
        }

        const auto initial_delay_s =
          std::min(initial_retry_delay_s, refresh_interval_s);
        const auto it =
          retry_states
            .try_emplace(issuer, RetryState{initial_delay_s, 0, nullptr})
            .first;
        auto& retry_state = it->second;
        if (retry_state.task != nullptr && !retry_state.task->is_cancelled())
        {
          return;
        }

        delay_s = retry_state.delay_s;
        const auto generation = ++next_retry_generation;
        retry_state.generation = generation;
        const auto self = weak_from_this();
        retry_task = ccf::tasks::make_basic_task([self, issuer, generation]() {
          const auto self_sp = self.lock();
          if (
            self_sp == nullptr || self_sp->stopped.load() ||
            !self_sp->begin_retry(issuer, generation))
          {
            return;
          }

          if (!self_sp->consensus->can_replicate())
          {
            LOG_DEBUG_FMT(
              "JWT key auto-refresh retry: Node is not primary, skipping");
            self_sp->cancel_retry(issuer);
            return;
          }

          self_sp->refresh_jwt_keys(issuer);
        });
        retry_state.task = retry_task;

        if (retry_state.delay_s < refresh_interval_s)
        {
          retry_state.delay_s = retry_state.delay_s > refresh_interval_s / 2 ?
            refresh_interval_s :
            retry_state.delay_s * 2;
        }
      }

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Scheduling retry for issuer '{}' in {}s",
        issuer,
        delay_s);
      ccf::tasks::add_delayed_task(retry_task, std::chrono::seconds(delay_s));
    }

    void send_curl_get(
      const std::string& url,
      const std::string& ca_bundle_pem,
      ccf::curl::CurlRequest::ResponseCallback callback)
    {
      ccf::curl::UniqueCURL curl_handle;
      curl_handle.set_opt(CURLOPT_HTTPGET, 1L);
      curl_handle.set_opt(CURLOPT_CONNECTTIMEOUT, request_connection_timeout_s);
      curl_handle.set_opt(CURLOPT_TIMEOUT, request_response_timeout_s);
      // 1L enables peer certificate verification. See libcurl docs:
      // https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
      curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 1L);
      // 2L requires the certificate name to match the requested host.
      // See libcurl docs:
      // https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html
      curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 2L);
      curl_handle.set_opt(CURLOPT_PROTOCOLS_STR, "https");
      curl_handle.set_blob_opt(
        CURLOPT_CAINFO_BLOB,
        reinterpret_cast<const uint8_t*>(ca_bundle_pem.data()),
        ca_bundle_pem.size());
      curl_handle.set_opt(CURLOPT_CAPATH, nullptr);

      ccf::curl::UniqueSlist headers;

      auto request = std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_GET,
        url,
        std::move(headers),
        nullptr,
        std::make_unique<ccf::curl::ResponseBody>(max_response_size),
        std::move(callback));

      ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
        std::move(request));
    }

  public:
    JwtKeyAutoRefresh(
      size_t refresh_interval_s,
      NetworkState& network,
      const std::shared_ptr<ccf::kv::Consensus>& consensus,
      const std::shared_ptr<ccf::RPCMap>& rpc_map,
      ccf::crypto::ECKeyPairPtr node_sign_kp,
      ccf::crypto::Pem node_cert,
      size_t max_response_size) :
      refresh_interval_s(refresh_interval_s),
      network(network),
      consensus(consensus),
      rpc_map(rpc_map),
      node_sign_kp(std::move(node_sign_kp)),
      node_cert(std::move(node_cert)),
      attempts(0),
      stopped(false),
      max_response_size(max_response_size)
    {}

    ~JwtKeyAutoRefresh()
    {
      stop();
    }

    void start()
    {
      stopped.store(false);
      LOG_DEBUG_FMT("JWT key initial auto-refresh");
      const auto self = weak_from_this();
      periodic_refresh_task = ccf::tasks::make_basic_task([self]() {
        const auto self_sp = self.lock();
        if (self_sp == nullptr || self_sp->stopped.load())
        {
          return;
        }

        if (!self_sp->consensus->can_replicate())
        {
          LOG_DEBUG_FMT("JWT key auto-refresh: Node is not primary, skipping");
        }
        else
        {
          self_sp->refresh_jwt_keys();
        }

        LOG_DEBUG_FMT(
          "JWT key auto-refresh: Scheduling in {}s",
          self_sp->refresh_interval_s);
      });

      const std::chrono::seconds period(refresh_interval_s);
      ccf::tasks::add_periodic_task(periodic_refresh_task, period, period);
    }

    void stop()
    {
      stopped.store(true);
      if (periodic_refresh_task != nullptr)
      {
        periodic_refresh_task->cancel_task();
      }
      cancel_retries();
    }

    void schedule_once()
    {
      LOG_DEBUG_FMT("JWT key one-off refresh: Scheduling without delay");
      const auto self = weak_from_this();
      ccf::tasks::add_task(ccf::tasks::make_basic_task([self]() {
        const auto self_sp = self.lock();
        if (self_sp == nullptr || self_sp->stopped.load())
        {
          return;
        }

        if (!self_sp->consensus->can_replicate())
        {
          LOG_DEBUG_FMT(
            "JWT key one-off refresh: Node is not primary, skipping");
        }
        else
        {
          self_sp->refresh_jwt_keys();
        }
      }));
    }

    template <typename T>
    bool send_refresh_jwt_keys(T msg)
    {
      ::http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "jwt_keys/refresh"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = nlohmann::json(msg).dump();
      request.set_body(body);

      auto packed = request.build_request();

      auto node_session = std::make_shared<ccf::SessionContext>(
        ccf::InvalidSessionId, node_cert.raw());
      auto ctx = ccf::make_rpc_context(node_session, packed);

      std::shared_ptr<ccf::RpcHandler> search =
        ::http::fetch_rpc_handler(ctx, this->rpc_map);

      search->process(ctx);
      return ::http::status_success(
        static_cast<ccf::http_status>(ctx->get_response_status()));
    }

    void send_refresh_jwt_keys_error(const JwtIssuer& issuer)
    {
      // A message that the endpoint fails to parse, leading to 500.
      // This is done purely for exposing errors as endpoint metrics.
      auto msg = false;
      send_refresh_jwt_keys(msg);
      schedule_retry(issuer);
    }

    void handle_jwt_jwks_response(
      const std::string& issuer,
      const std::optional<std::string>& issuer_constraint,
      ccf::http_status status,
      std::vector<uint8_t>&& data)
    {
      if (status != HTTP_STATUS_OK)
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: Error while requesting JWKS: {} {}{}",
          status,
          ccf::http_status_str(status),
          data.empty() ?
            "" :
            fmt::format("  '{}'", std::string(data.begin(), data.end())));
        send_refresh_jwt_keys_error(issuer);
        return;
      }

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Received JWKS for issuer '{}'", issuer);

      JsonWebKeySet jwks;
      try
      {
        jwks = ccf::parse_json_safe(data).get<JsonWebKeySet>();
      }
      catch (const std::exception& e)
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: Cannot parse JWKS for issuer '{}': {}",
          issuer,
          e.what());
        send_refresh_jwt_keys_error(issuer);
        return;
      }

      // For each key we leave the specified issuer constraint or set a common
      // one otherwise (if present).
      if (issuer_constraint.has_value())
      {
        for (auto& key : jwks.keys)
        {
          if (!key.issuer.has_value())
          {
            key.issuer = issuer_constraint;
          }
        }
      }

      // call internal endpoint to update keys
      auto msg = SetJwtPublicSigningKeys{issuer, jwks};

      if (send_refresh_jwt_keys(msg))
      {
        cancel_retry(issuer);
      }
      else
      {
        schedule_retry(issuer);
      }
    }

    void handle_jwt_metadata_response(
      const std::string& issuer,
      std::string ca_bundle_pem,
      ccf::http_status status,
      std::vector<uint8_t>&& data)
    {
      if (status != HTTP_STATUS_OK)
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: Error while requesting OpenID metadata: {} "
          "{}{}",
          status,
          ccf::http_status_str(status),
          data.empty() ?
            "" :
            fmt::format("  '{}'", std::string(data.begin(), data.end())));
        send_refresh_jwt_keys_error(issuer);
        return;
      }

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Received OpenID metadata for issuer '{}'",
        issuer);

      std::string jwks_url_str;
      nlohmann::json metadata;
      std::optional<std::string> issuer_constraint{std::nullopt};
      try
      {
        metadata = ccf::parse_json_safe(data);
        jwks_url_str = metadata.at("jwks_uri").get<std::string>();
        const auto constraint = metadata.find("issuer");
        if (constraint != metadata.end())
        {
          issuer_constraint = constraint->get<std::string>();
        }
      }
      catch (const std::exception& e)
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: Cannot parse OpenID metadata for issuer '{}': "
          "{}",
          issuer,
          e.what());
        send_refresh_jwt_keys_error(issuer);
        return;
      }
      // Validate jwks_uri before handing it to libcurl; the parsed result is
      // not used directly since the full URL string is passed to curl. The
      // JWKS host/port may differ from the issuer authority; OIDC Discovery
      // requires HTTPS here, but does not require matching authorities.
      ::http::URL jwks_url;
      try
      {
        jwks_url = ::http::parse_url_full(jwks_url_str);
      }
      catch (const std::invalid_argument& e)
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: Cannot parse jwks_uri for issuer '{}': {} "
          "({})",
          issuer,
          jwks_url_str,
          e.what());
        send_refresh_jwt_keys_error(issuer);
        return;
      }

      ccf::nonstd::to_lower(jwks_url.scheme);
      if (jwks_url.scheme != "https")
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: jwks_uri for issuer '{}' must use https: {}",
          issuer,
          jwks_url_str);
        send_refresh_jwt_keys_error(issuer);
        return;
      }

      LOG_DEBUG_FMT(
        "JWT key auto-refresh: Requesting JWKS at {}", jwks_url_str);

      const auto self = weak_from_this();
      auto response_callback =
        [self, issuer, issuer_constraint](
          std::unique_ptr<ccf::curl::CurlRequest>&& request,
          CURLcode curl_response,
          long status_code) {
          auto http_status = static_cast<ccf::http_status>(status_code);
          auto response_body_sp = std::make_shared<std::vector<uint8_t>>(
            request->get_response_body() != nullptr ?
              std::move(request->get_response_body()->buffer) :
              std::vector<uint8_t>{});
          ccf::tasks::add_task(
            ccf::tasks::make_basic_task([self,
                                         issuer,
                                         issuer_constraint,
                                         curl_response,
                                         http_status,
                                         response_body_sp]() {
              const auto self_sp = self.lock();
              if (self_sp == nullptr || self_sp->stopped.load())
              {
                return;
              }

              if (curl_response != CURLE_OK)
              {
                LOG_INFO_FMT(
                  "JWT key auto-refresh: Failed to fetch JWKS for issuer '{}': "
                  "{} ({})",
                  issuer,
                  curl_easy_strerror(curl_response),
                  curl_response);
                self_sp->send_refresh_jwt_keys_error(issuer);
                return;
              }
              self_sp->handle_jwt_jwks_response(
                issuer,
                issuer_constraint,
                http_status,
                std::move(*response_body_sp));
            }));
        };

      send_curl_get(jwks_url_str, ca_bundle_pem, std::move(response_callback));
    }

    void refresh_jwt_keys(
      const std::optional<JwtIssuer>& issuer_filter = std::nullopt)
    {
      if (stopped.load())
      {
        return;
      }

      auto tx = network.tables->create_read_only_tx();
      auto* jwt_issuers = tx.ro(network.jwt_issuers);
      auto* ca_cert_bundles = tx.ro(network.ca_cert_bundles);
      bool issuer_found = !issuer_filter.has_value();
      jwt_issuers->foreach([this,
                            &ca_cert_bundles,
                            &issuer_filter,
                            &issuer_found](
                             const JwtIssuer& issuer,
                             const JwtIssuerMetadata& metadata) {
        if (stopped.load())
        {
          return false;
        }

        if (issuer_filter.has_value() && issuer != issuer_filter.value())
        {
          return true;
        }
        issuer_found = true;

        if (!metadata.auto_refresh)
        {
          LOG_DEBUG_FMT(
            "JWT key auto-refresh: Skipping issuer '{}', auto-refresh is "
            "disabled",
            issuer);
          cancel_retry(issuer);
          return true;
        }

        // Increment attempts, only when auto-refresh is enabled.
        attempts++;

        LOG_DEBUG_FMT(
          "JWT key auto-refresh: Refreshing keys for issuer '{}'", issuer);
        const auto& ca_cert_bundle_name = metadata.ca_cert_bundle_name.value();
        auto ca_cert_bundle_pem = ca_cert_bundles->get(ca_cert_bundle_name);
        if (!ca_cert_bundle_pem.has_value())
        {
          LOG_INFO_FMT(
            "JWT key auto-refresh: CA cert bundle with name '{}' for issuer "
            "'{}' not "
            "found",
            ca_cert_bundle_name,
            issuer);
          send_refresh_jwt_keys_error(issuer);
          return true;
        }

        auto metadata_url = issuer + "/.well-known/openid-configuration";

        LOG_DEBUG_FMT(
          "JWT key auto-refresh: Requesting OpenID metadata at {}",
          metadata_url);

        auto ca_bundle_pem = ca_cert_bundle_pem.value();

        const auto self = weak_from_this();
        auto response_callback =
          [self, issuer, ca_bundle_pem](
            std::unique_ptr<ccf::curl::CurlRequest>&& request,
            CURLcode curl_response,
            long status_code) {
            auto http_status = static_cast<ccf::http_status>(status_code);
            auto response_body_sp = std::make_shared<std::vector<uint8_t>>(
              request->get_response_body() != nullptr ?
                std::move(request->get_response_body()->buffer) :
                std::vector<uint8_t>{});
            ccf::tasks::add_task(
              ccf::tasks::make_basic_task([self,
                                           issuer,
                                           ca_bundle_pem,
                                           curl_response,
                                           http_status,
                                           response_body_sp]() {
                const auto self_sp = self.lock();
                if (self_sp == nullptr || self_sp->stopped.load())
                {
                  return;
                }

                if (curl_response != CURLE_OK)
                {
                  LOG_INFO_FMT(
                    "JWT key auto-refresh: Failed to fetch OpenID metadata for "
                    "issuer '{}': {} ({})",
                    issuer,
                    curl_easy_strerror(curl_response),
                    curl_response);
                  self_sp->send_refresh_jwt_keys_error(issuer);
                  return;
                }
                self_sp->handle_jwt_metadata_response(
                  issuer,
                  ca_bundle_pem,
                  http_status,
                  std::move(*response_body_sp));
              }));
          };

        send_curl_get(
          metadata_url, ca_bundle_pem, std::move(response_callback));
        return true;
      });

      if (!issuer_found)
      {
        cancel_retry(issuer_filter.value());
      }
    }

    // Returns a copy of the current attempts
    [[nodiscard]] size_t get_attempts() const
    {
      return attempts.load();
    }
  };
}
