// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/crypto/hash_bytes.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/san.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/http_consts.h"
#include "ccf/http_status.h"
#include "ccf/pal/locking.h"
#include "ds/messaging.h"
#include "ds/thread_messaging.h"
#include "http/http_parser.h"

#include <cctype>
#include <chrono>
#include <cstddef>
#include <list>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace ACME
{
  struct ClientConfig
  {
    // Root certificate(s) of the CA to connect to in PEM format (for TLS
    // connections to the CA, e.g. Let's Encrypt's ISRG Root X1)
    std::vector<std::string> ca_certs;

    // URL of the ACME server's directory
    std::string directory_url;

    // DNS name of the service we represent
    std::string service_dns_name;

    // Alternative DNS names of the service we represent
    std::vector<std::string> alternative_names;

    // Contact addresses (see RFC8555 7.3, e.g. mailto:john@example.com)
    std::vector<std::string> contact;

    // Indication that the user/operator is aware of the latest terms and
    // conditions for the CA
    bool terms_of_service_agreed = false;

    // Type of the ACME challenge
    std::string challenge_type = "http-01";

    // Validity range (Note: not supported by Let's Encrypt)
    std::optional<std::string> not_before;
    std::optional<std::string> not_after;

    bool operator==(const ClientConfig& other) const = default;
  };

  class Client
  {
  public:
    Client(
      const ClientConfig& config,
      std::shared_ptr<crypto::KeyPair> account_key_pair = nullptr) :
      config(config)
    {
      set_account_key(account_key_pair);
    }

    virtual ~Client() {}

    void get_certificate(
      std::shared_ptr<crypto::KeyPair> service_key, bool override_time = false)
    {
      using namespace std::chrono_literals;
      using namespace std::chrono;

      bool ok = true;
      system_clock::duration delta(0);

      if (last_request && !override_time)
      {
        // Let's encrypt recommends this retry strategy in their integration
        // guide, see https://letsencrypt.org/docs/integration-guide/

        delta = system_clock::now() - *last_request;
        ok = false;
        switch (num_failed_attempts)
        {
          case 0:
            ok = true;
            break;
          case 1:
            ok = delta >= 1min;
            break;
          case 2:
            ok = delta >= 10min;
            break;
          case 3:
            ok = delta >= 100min;
            break;
          default:
            ok = delta >= 24h;
            break;
        }
      }

      if (ok)
      {
        this->service_key = service_key;
        last_request = system_clock::now();
        num_failed_attempts++;
        request_directory();
      }
      else
      {
        LOG_INFO_FMT(
          "ACME: Ignoring certificate request due to {} recent failed "
          "attempt(s) within {} seconds",
          num_failed_attempts,
          duration_cast<seconds>(delta).count());
      }
    }

    void start_challenge(const std::string& token)
    {
      for (auto& order : active_orders)
      {
        auto cit = order.challenges.find(token);
        if (cit != order.challenges.end())
        {
          post_as_get_json(
            order.account_url,
            cit->second.challenge_url,
            [this, order_url = order.order_url, &challenge = cit->second](
              const http::HeaderMap& headers, const nlohmann::json& j) {
              threading::ThreadMessaging::thread_messaging.add_task_after(
                schedule_check_challenge(order_url, challenge),
                std::chrono::milliseconds(0));
              return true;
            });
        }
      }
    }

    virtual void set_account_key(
      std::shared_ptr<crypto::KeyPair> new_account_key_pair)
    {
      account_key_pair = new_account_key_pair != nullptr ?
        new_account_key_pair :
        crypto::make_key_pair();
      LOG_DEBUG_FMT(
        "ACME: new account public key: {}",
        ds::to_hex(account_key_pair->public_key_der()));
    }

    bool has_active_orders() const
    {
      return !active_orders.empty();
    }

  protected:
    virtual void on_challenge(
      const std::string& token, const std::string& response) = 0;
    virtual void on_challenge_finished(const std::string& token) = 0;
    virtual void on_certificate(const std::string& certificate) = 0;
    virtual void on_http_request(
      const http::URL& url,
      http::Request&& req,
      std::function<
        bool(http_status status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback) = 0;

    void make_request(
      llhttp_method method,
      const http::URL& url,
      const std::vector<uint8_t>& body,
      http_status expected_status,
      std::function<bool(const http::HeaderMap&, const std::vector<uint8_t>&)>
        ok_callback)
    {
      std::unique_lock<ccf::pal::Mutex> guard(req_lock);

      try
      {
        auto port = url.port.empty() ? "443" : url.port;
        LOG_INFO_FMT(
          "ACME: Requesting https://{}:{}{}", url.host, port, url.path);

        http::Request r(url.path, method);
        r.set_header(http::headers::ACCEPT, "*/*");
        r.set_header(
          http::headers::HOST, fmt::format("{}:{}", url.host, url.port));
        if (!body.empty())
        {
          r.set_header(http::headers::CONTENT_TYPE, "application/jose+json");
          r.set_body(&body);
        }
        auto req = r.build_request();
        std::string reqs(req.begin(), req.end());
        LOG_TRACE_FMT("ACME: request:\n{}", reqs);

        on_http_request(
          url,
          std::move(r),
          [this, expected_status, ok_callback](
            http_status status,
            http::HeaderMap&& headers,
            std::vector<uint8_t>&& data) {
            for (auto& [k, v] : headers)
            {
              LOG_TRACE_FMT("ACME: H: {}: {}", k, v);
            }

            if (status != expected_status && status != HTTP_STATUS_OK)
            {
              LOG_INFO_FMT(
                "ACME: request failed with status={} and body={}",
                (int)status,
                std::string(data.begin(), data.end()));
              return false;
            }
            else
            {
              LOG_TRACE_FMT(
                "ACME: data: {}", std::string(data.begin(), data.end()));
            }

            auto nonce_opt = get_header_value(headers, "replay-nonce");
            if (nonce_opt)
            {
              nonces.push_back(*nonce_opt);
            }

            try
            {
              ok_callback(headers, data);
            }
            catch (const std::exception& ex)
            {
              LOG_FAIL_FMT("ACME: response callback failed: {}", ex.what());
              return false;
            }
            return true;
          });
      }
      catch (const std::exception& ex)
      {
        LOG_FAIL_FMT("ACME: failed to connect to ACME server: {}", ex.what());
      }
    }

    void make_json_request(
      llhttp_method method,
      const http::URL& url,
      const std::vector<uint8_t>& body,
      http_status expected_status,
      std::function<void(const http::HeaderMap& headers, const nlohmann::json&)>
        ok_callback)
    {
      make_request(
        method,
        url,
        body,
        expected_status,
        [ok_callback](
          const http::HeaderMap& headers, const std::vector<uint8_t>& data) {
          nlohmann::json jr;

          if (!data.empty())
          {
            try
            {
              jr = nlohmann::json::parse(data);
              LOG_TRACE_FMT("ACME: json response: {}", jr.dump());
            }
            catch (const std::exception& ex)
            {
              LOG_FAIL_FMT("ACME: response parser failed: {}", ex.what());
              return false;
            }
          }

          ok_callback(headers, jr);
          return true;
        });
    }

    void post_as_get(
      const std::string& account_url,
      const std::string& resource_url,
      std::function<bool(const http::HeaderMap&, const std::vector<uint8_t>&)>
        ok_callback)
    {
      if (nonces.empty())
      {
        request_new_nonce(
          [=]() { post_as_get(account_url, resource_url, ok_callback); });
      }
      else
      {
        auto nonce = nonces.front();
        nonces.pop_front();
        auto header = mk_kid_header(account_url, nonce, resource_url);
        JWS jws(header, *account_key_pair);
        http::URL url = with_default_port(resource_url);
        make_request(
          HTTP_POST, url, json_to_bytes(jws), HTTP_STATUS_OK, ok_callback);
      }
    }

    void post_as_get_json(
      const std::string& account_url,
      const std::string& resource_url,
      std::function<bool(const http::HeaderMap&, const nlohmann::json&)>
        ok_callback,
      bool empty_payload = false)
    {
      if (nonces.empty())
      {
        request_new_nonce([=]() {
          post_as_get_json(
            account_url, resource_url, ok_callback, empty_payload);
        });
      }
      else
      {
        auto nonce = nonces.front();
        nonces.pop_front();

        auto header = mk_kid_header(account_url, nonce, resource_url);
        JWS jws(
          header, nlohmann::json::object_t(), *account_key_pair, empty_payload);
        http::URL url = with_default_port(resource_url);
        make_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_OK,
          [ok_callback](
            const http::HeaderMap& headers, const std::vector<uint8_t>& data) {
            try
            {
              ok_callback(headers, nlohmann::json::parse(data));
              return true;
            }
            catch (const std::exception& ex)
            {
              LOG_FATAL_FMT("ACME: request callback failed: {}", ex.what());
              return false;
            }
          });
      }
    }

    ClientConfig config;
    std::shared_ptr<crypto::KeyPair> service_key;
    std::shared_ptr<crypto::KeyPair> account_key_pair;

    nlohmann::json directory;
    nlohmann::json account;
    std::list<std::string> nonces;

    ccf::pal::Mutex req_lock;
    ccf::pal::Mutex orders_lock;

    std::optional<std::chrono::system_clock::time_point> last_request =
      std::nullopt;
    size_t num_failed_attempts = 0;

    struct Challenge
    {
      std::string token;
      std::string authorization_url;
      std::string challenge_url;
    };

    enum OrderStatus
    {
      ACTIVE,
      FINISHED,
      FAILED
    };

    struct Order
    {
      OrderStatus status = ACTIVE;
      std::string account_url;
      std::string order_url;
      std::string finalize_url;
      std::string certificate_url;
      std::unordered_set<std::string> authorizations;
      std::map<std::string, Challenge> challenges;
    };

    std::list<Order> active_orders;

    static http::URL with_default_port(
      const std::string& url, const std::string& default_port = "443")
    {
      http::URL r = http::parse_url_full(url);
      if (r.port.empty())
      {
        r.port = default_port;
      }
      return r;
    }

    static std::vector<uint8_t> s2v(const std::string& s)
    {
      return std::vector<uint8_t>(s.data(), s.data() + s.size());
    }

    static std::vector<uint8_t> json_to_bytes(const nlohmann::json& j)
    {
      return s2v(j.dump());
    }

    static std::string json_to_b64url(
      const nlohmann::json& j, bool with_padding = true)
    {
      return crypto::b64url_from_raw(json_to_bytes(j), with_padding);
    }

    static void convert_signature_to_ieee_p1363(
      std::vector<uint8_t>& sig, const crypto::KeyPair& signer)
    {
      // Convert signature from ASN.1 format to IEEE P1363
      const unsigned char* pp = sig.data();
      ECDSA_SIG* sig_r_s = d2i_ECDSA_SIG(NULL, &pp, sig.size());
      const BIGNUM* r = ECDSA_SIG_get0_r(sig_r_s);
      const BIGNUM* s = ECDSA_SIG_get0_s(sig_r_s);
      size_t sz = signer.coordinates().x.size();
      sig = std::vector<uint8_t>(2 * sz, 0);
      BN_bn2binpad(r, sig.data(), sz);
      BN_bn2binpad(s, sig.data() + sz, sz);
      ECDSA_SIG_free(sig_r_s);
    }

    class JWS : public nlohmann::json::object_t
    {
    public:
      JWS(
        const nlohmann::json& header_,
        const nlohmann::json& payload_,
        crypto::KeyPair& signer_,
        bool empty_payload = false)
      {
        LOG_TRACE_FMT("ACME: JWS header: {}", header_.dump());
        LOG_TRACE_FMT("ACME: JWS payload: {}", payload_.dump());
        auto header_b64 = json_to_b64url(header_, false);
        auto payload_b64 = empty_payload ? "" : json_to_b64url(payload_, false);
        set(header_b64, payload_b64, signer_);
      }

      JWS(const nlohmann::json& header_, crypto::KeyPair& signer_) :
        JWS(header_, nlohmann::json::object_t(), signer_, true)
      {}

      virtual ~JWS() {}

    protected:
      void set(
        const std::string& header_b64,
        const std::string& payload_b64,
        crypto::KeyPair& signer)
      {
        auto msg = header_b64 + "." + payload_b64;
        auto sig = signer.sign(s2v(msg));
        convert_signature_to_ieee_p1363(sig, signer);
        auto sig_b64 = crypto::b64url_from_raw(sig);

        (*this)["protected"] = header_b64;
        (*this)["payload"] = payload_b64;
        (*this)["signature"] = sig_b64;
      }
    };

    class JWK : public nlohmann::json::object_t
    {
    public:
      JWK(
        const std::string& kty,
        const std::string& crv,
        const std::string& x,
        const std::string& y,
        const std::optional<std::string>& alg = std::nullopt,
        const std::optional<std::string>& use = std::nullopt,
        const std::optional<std::string>& kid = std::nullopt)
      {
        (*this)["kty"] = kty;
        (*this)["crv"] = crv;
        (*this)["x"] = x;
        (*this)["y"] = y;
        if (alg)
          (*this)["alg"] = *alg;
        if (use)
          (*this)["use"] = *use;
        if (kid)
          (*this)["kid"] = *kid;
      }
      virtual ~JWK() = default;
    };

    static std::optional<std::string> get_header_value(
      const http::HeaderMap& headers, const std::string& name)
    {
      for (const auto& [k, v] : headers)
      {
        if (k == name)
        {
          return v;
        }
      }

      return std::nullopt;
    }

    static void expect(const nlohmann::json& j, const std::string& key)
    {
      if (!j.contains(key))
      {
        throw std::runtime_error(fmt::format("Missing key '{}'", key));
      }
    }

    static void expect_string(
      const nlohmann::json& j, const std::string& key, const std::string& value)
    {
      expect(j, key);

      if (j[key] != value)
      {
        throw std::runtime_error(fmt::format(
          "Unexpected value for '{}': '{}' while expecting '{}'",
          key,
          j[key],
          value));
      }
    }

    static std::pair<std::string, std::string> get_crv_alg(
      const std::shared_ptr<crypto::KeyPair>& key_pair)
    {
      std::string crv, alg;
      if (key_pair->get_curve_id() == crypto::CurveID::SECP256R1)
      {
        crv = "P-256";
        alg = "ES256";
      }
      else if (key_pair->get_curve_id() == crypto::CurveID::SECP384R1)
      {
        crv = "P-384";
        alg = "ES384";
      }
      else
        throw std::runtime_error("Unsupported curve");

      return std::make_pair(crv, alg);
    }

    Order* get_order(const std::string& order_url)
    {
      auto oit = std::find_if(
        active_orders.begin(),
        active_orders.end(),
        [&order_url](const Order& other) {
          return order_url == other.order_url;
        });

      if (oit != active_orders.end())
      {
        return &(*oit);
      }

      LOG_DEBUG_FMT("ACME: no such order {}", order_url);

      return nullptr;
    }

    void remove_order(const std::string& order_url)
    {
      LOG_TRACE_FMT("ACME: removing order {}", order_url);

      std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
      for (auto it = active_orders.begin(); it != active_orders.end();)
      {
        if (it->order_url == order_url)
        {
          for (const auto& [_, challenge] : it->challenges)
          {
            on_challenge_finished(challenge.token);
          }
          it = active_orders.erase(it);
          break;
        }
        else
        {
          it++;
        }
      }
    }

    nlohmann::json mk_kid_header(
      const std::string& account_url,
      const std::string& nonce,
      const std::string& resource_url)
    {
      //  For all other requests, the request is signed using an existing
      //  account, and there MUST be a "kid" field.  This field MUST contain the
      //  account URL received by POSTing to the newAccount resource.

      auto crv_alg = get_crv_alg(account_key_pair);

      nlohmann::json r = {
        {"alg", crv_alg.second},
        {"kid", account_url},
        {"nonce", nonce},
        {"url", resource_url}};

      return r;
    }

    void request_directory()
    {
      http::URL url = with_default_port(config.directory_url);
      make_json_request(
        HTTP_GET,
        url,
        {},
        HTTP_STATUS_OK,
        [this](const http::HeaderMap&, const nlohmann::json& j) {
          directory = j;
          request_new_account();
        });
    }

    void request_new_nonce(std::function<void()> ok_callback)
    {
      http::URL url = with_default_port(directory.at("newNonce"));
      make_json_request(
        HTTP_GET,
        url,
        {},
        HTTP_STATUS_NO_CONTENT,
        [this,
         ok_callback](const http::HeaderMap& headers, const nlohmann::json& j) {
          ok_callback();
          return true;
        });
    }

    void request_new_account()
    {
      std::string new_account_url =
        directory.at("newAccount").get<std::string>();

      if (nonces.empty())
      {
        request_new_nonce([this]() { request_new_account(); });
      }
      else
      {
        auto nonce = nonces.front();
        nonces.pop_front();

        auto crv_alg = get_crv_alg(account_key_pair);
        auto key_coords = account_key_pair->coordinates();

        JWK jwk(
          "EC",
          crv_alg.first,
          crypto::b64url_from_raw(key_coords.x, false),
          crypto::b64url_from_raw(key_coords.y, false));

        nlohmann::json header = {
          {"alg", crv_alg.second},
          {"jwk", jwk},
          {"nonce", nonce},
          {"url", new_account_url}};

        nlohmann::json payload = {
          {"termsOfServiceAgreed", config.terms_of_service_agreed},
          {"contact", config.contact}};

        JWS jws(header, payload, *account_key_pair);

        http::URL url = with_default_port(new_account_url);
        make_json_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_CREATED,
          [this](const http::HeaderMap& headers, const nlohmann::json& j) {
            expect_string(j, "status", "valid");
            account = j;
            auto loc_opt = get_header_value(headers, "location");
            request_new_order(loc_opt.value_or(""));
          });
      }
    }

    void authorize_next_challenge(const std::string& order_url)
    {
      std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
      auto order = get_order(order_url);

      if (!order)
      {
        return;
      }

      if (!order->authorizations.empty())
      {
        request_authorization(*order, *order->authorizations.begin());
      }
    }

    void request_new_order(const std::string& account_url)
    {
      if (nonces.empty())
      {
        request_new_nonce(
          [this, account_url]() { request_new_order(account_url); });
      }
      else
      {
        auto nonce = nonces.front();
        nonces.pop_front();

        auto header =
          mk_kid_header(account_url, nonce, directory.at("newOrder"));

        nlohmann::json payload = {
          {"identifiers",
           nlohmann::json::array(
             {{{"type", "dns"}, {"value", config.service_dns_name}}})}};

        for (const auto& n : config.alternative_names)
          payload["identifiers"] += {{"type", "dns"}, {"value", n}};

        if (config.not_before)
        {
          payload["notBefore"] = *config.not_before;
        }
        if (config.not_after)
        {
          payload["notAfter"] = *config.not_after;
        }

        JWS jws(header, payload, *account_key_pair);

        http::URL url = with_default_port(directory.at("newOrder"));
        make_json_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_CREATED,
          [this, account_url](
            const http::HeaderMap& headers, const nlohmann::json& j) {
            expect(j, "status");
            expect(j, "finalize");

            auto order_url_opt = get_header_value(headers, "location");
            if (!order_url_opt)
            {
              throw std::runtime_error("Missing order location");
            }

            std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
            active_orders.emplace_back(Order{
              ACTIVE, account_url, *order_url_opt, j["finalize"], "", {}, {}});

            Order& order = active_orders.back();

            if (j["status"] == "pending" && j.contains("authorizations"))
            {
              expect(j, "authorizations");
              order.authorizations =
                j["authorizations"].get<std::unordered_set<std::string>>();
              guard.unlock();
              authorize_next_challenge(*order_url_opt);
            }
            else if (j["status"] == "ready")
            {
              expect(j, "finalize");
              guard.unlock();
              request_finalization(*order_url_opt);
            }
            else if (j["status"] == "valid")
            {
              expect(j, "certificate");
              order.certificate_url = j["certificate"];
              guard.unlock();
              request_certificate(*order_url_opt);
            }
            else
            {
              LOG_FATAL_FMT(
                "ACME: unknown order status '{}', aborting", j["status"]);
              guard.unlock();
              remove_order(*order_url_opt);
            }
          });
      }
    }

    void request_authorization(Order& order, const std::string& authz_url)
    {
      post_as_get_json(
        order.account_url,
        authz_url,
        [this, order_url = order.order_url, authz_url](
          const http::HeaderMap& headers, const nlohmann::json& j) {
          LOG_TRACE_FMT("ACME: authorization reply: {}", j.dump());
          expect_string(j, "status", "pending");
          expect(j, "challenges");

          {
            std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
            auto order = get_order(order_url);

            if (!order)
            {
              return false;
            }

            bool found_match = false;
            for (const auto& challenge : j["challenges"])
            {
              if (
                challenge.contains("type") &&
                challenge["type"] == config.challenge_type)
              {
                expect_string(challenge, "status", "pending");
                expect(challenge, "token");
                expect(challenge, "url");

                std::string token = challenge["token"];
                std::string challenge_url = challenge["url"];

                add_challenge(*order, token, authz_url, challenge_url);
                found_match = true;
                break;
              }
            }

            order->authorizations.erase(authz_url);

            if (!found_match)
            {
              throw std::runtime_error(fmt::format(
                "Challenge type '{}' not offered", config.challenge_type));
            }
          }

          authorize_next_challenge(order_url);

          return true;
        },
        true);
    }

    std::string make_challenge_response() const
    {
      auto crv_alg = get_crv_alg(account_key_pair);
      auto key_coords = account_key_pair->coordinates();

      JWK jwk(
        "EC",
        crv_alg.first,
        crypto::b64url_from_raw(key_coords.x, false),
        crypto::b64url_from_raw(key_coords.y, false));

      auto thumbprint = crypto::sha256(s2v(nlohmann::json(jwk).dump()));
      return crypto::b64url_from_raw(thumbprint, false);
    }

    void add_challenge(
      Order& order,
      const std::string& token,
      const std::string& authorization_url,
      const std::string& challenge_url)
    {
      auto response = make_challenge_response();

      order.challenges.emplace(
        token, Challenge{token, authorization_url, challenge_url});

      on_challenge(token, response);
    }

    struct ChallengeWaitMsg
    {
      ChallengeWaitMsg(
        const std::string& order_url, Challenge challenge, Client* client) :
        order_url(order_url),
        challenge(challenge),
        client(client)
      {}
      std::string order_url;
      Challenge challenge;
      Client* client;
    };

    std::unique_ptr<threading::Tmsg<ChallengeWaitMsg>> schedule_check_challenge(
      const std::string& order_url, Challenge& challenge)
    {
      return std::make_unique<threading::Tmsg<ChallengeWaitMsg>>(
        [](std::unique_ptr<threading::Tmsg<ChallengeWaitMsg>> msg) {
          std::string& order_url = msg->data.order_url;
          Challenge& challenge = msg->data.challenge;
          Client* client = msg->data.client;

          if (client->check_challenge(order_url, challenge))
          {
            LOG_TRACE_FMT("ACME: scheduling next challenge check");
            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), std::chrono::seconds(5));
          }
        },
        order_url,
        challenge,
        this);
    }

    bool check_challenge(
      const std::string& order_url, const Challenge& challenge)
    {
      std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
      auto order = get_order(order_url);

      if (
        !order ||
        order->challenges.find(challenge.token) == order->challenges.end())
      {
        return false;
      }

      LOG_TRACE_FMT(
        "ACME: requesting challenge status for token '{}' ...",
        challenge.token);

      // This post-as-get with empty body ("", not "{}"), but json response.
      post_as_get(
        order->account_url,
        challenge.authorization_url,
        [this, order_url, challenge_token = challenge.token](
          const http::HeaderMap& headers, const std::vector<uint8_t>& body) {
          auto j = nlohmann::json::parse(body);
          LOG_TRACE_FMT("ACME: authorization status: {}", j.dump());
          expect(j, "status");

          if (j["status"] == "valid")
          {
            finish_challenge(order_url, challenge_token);
          }
          else if (j["status"] == "pending" || j["status"] == "processing")
          {
            if (j.contains("error"))
            {
              LOG_FAIL_FMT(
                "ACME: challenge for token '{}' failed with the following "
                "error: {}",
                challenge_token,
                j["error"].dump());
              finish_challenge(order_url, challenge_token);
            }
            else
            {
              return true;
            }
          }
          else
          {
            LOG_FAIL_FMT(
              "ACME: challenge for token '{}' failed with status '{}' ",
              challenge_token,
              j["status"]);
            finish_challenge(order_url, challenge_token);
          }

          return false;
        });

      return true;
    }

    void finish_challenge(
      const std::string& order_url, const std::string& challenge_token)
    {
      bool order_done = false;

      {
        std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
        auto order = get_order(order_url);

        if (!order)
        {
          return;
        }

        auto cit = order->challenges.find(challenge_token);
        if (cit == order->challenges.end())
        {
          throw std::runtime_error(
            fmt::format("No active challenge for token '{}'", challenge_token));
        }

        on_challenge_finished(cit->first);
        order->challenges.erase(cit);
        order_done = order->challenges.empty();
      }

      if (order_done)
      {
        request_finalization(order_url);
      }
    }

    bool check_finalization(const std::string& order_url)
    {
      std::unique_lock<ccf::pal::Mutex> guard2(orders_lock);
      auto order = get_order(order_url);

      if (!order)
      {
        return false;
      }

      LOG_TRACE_FMT("ACME: checking finalization of {}", order_url);

      // This post-as-get with empty body ("", not "{}"), but json response.
      post_as_get(
        order->account_url,
        order->order_url,
        [this, order_url](
          const http::HeaderMap& headers, const std::vector<uint8_t>& body) {
          auto j = nlohmann::json::parse(body);
          LOG_TRACE_FMT("ACME: finalization status: {}", j.dump());
          expect(j, "status");
          if (j["status"] == "valid")
          {
            expect(j, "certificate");
            {
              std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
              auto order = get_order(order_url);
              if (order)
              {
                order->certificate_url = j["certificate"];
              }
            }
            request_certificate(order_url);
          }
          else if (j["status"] == "invalid")
          {
            LOG_TRACE_FMT("ACME: removing failed order");
            remove_order(order_url);
          }
          else if (j["status"] != "pending" && j["status"] != "processing")
          {
            LOG_DEBUG_FMT(
              "ACME: unknown order status '{}'; aborting order", j["status"]);
            remove_order(order_url);
          }
          return true;
        });

      return true;
    }

    struct FinalizationWaitMsg
    {
      FinalizationWaitMsg(const std::string& order_url, Client* client) :
        order_url(order_url),
        client(client)
      {}
      std::string order_url;
      Client* client;
    };

    std::unique_ptr<threading::Tmsg<FinalizationWaitMsg>>
    schedule_check_finalization(const std::string& order_url)
    {
      return std::make_unique<threading::Tmsg<FinalizationWaitMsg>>(
        [](std::unique_ptr<threading::Tmsg<FinalizationWaitMsg>> msg) {
          Client* client = msg->data.client;
          const std::string& order_url = msg->data.order_url;

          if (client->check_finalization(order_url))
          {
            LOG_TRACE_FMT("ACME: scheduling next finalization check");
            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), std::chrono::seconds(5));
          }
        },
        order_url,
        this);
    }

    virtual std::vector<uint8_t> get_service_csr()
    {
      std::vector<crypto::SubjectAltName> alt_names;
      alt_names.push_back({config.service_dns_name, false});
      for (const auto& an : config.alternative_names)
        alt_names.push_back({an, false});
      return service_key->create_csr_der(
        "CN=" + config.service_dns_name, alt_names);
    }

    void request_finalization(const std::string& order_url)
    {
      if (nonces.empty())
      {
        request_new_nonce(
          [this, &order_url]() { request_finalization(order_url); });
      }
      else
      {
        std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
        auto order = get_order(order_url);

        if (!order)
        {
          return;
        }

        auto nonce = nonces.front();
        nonces.pop_front();

        auto header =
          mk_kid_header(order->account_url, nonce, order->finalize_url);

        auto csr = get_service_csr();

        nlohmann::json payload = {{"csr", crypto::b64url_from_raw(csr, false)}};

        JWS jws(header, payload, *account_key_pair);

        http::URL url = with_default_port(order->finalize_url);
        make_json_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_OK,
          [this, order_url = order->order_url](
            const http::HeaderMap& headers, const nlohmann::json& j) {
            LOG_TRACE_FMT("ACME: finalization status: {}", j.dump());
            expect(j, "status");
            if (j["status"] == "valid")
            {
              expect(j, "certificate");

              {
                std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
                auto order = get_order(order_url);
                if (order)
                {
                  order->certificate_url = j["certificate"];
                }
              }
              request_certificate(order_url);
            }
            else
            {
              LOG_TRACE_FMT("ACME: scheduling finalization check");
              threading::ThreadMessaging::thread_messaging.add_task_after(
                schedule_check_finalization(order_url),
                std::chrono::milliseconds(0));
            }
          });
      }
    }

    void request_certificate(const std::string& order_url)
    {
      if (nonces.empty())
      {
        request_new_nonce(
          [this, &order_url]() { request_certificate(order_url); });
      }
      else
      {
        std::unique_lock<ccf::pal::Mutex> guard(orders_lock);
        auto order = get_order(order_url);

        if (!order)
        {
          return;
        }

        http::URL url = with_default_port(order->certificate_url);
        post_as_get(
          order->account_url,
          order->certificate_url,
          [this, order_url](
            const http::HeaderMap& headers, const std::vector<uint8_t>& data) {
            std::string c(data.data(), data.data() + data.size());
            LOG_TRACE_FMT("ACME: obtained certificate (chain): {}", c);

            on_certificate(c);

            remove_order(order_url);

            last_request = std::chrono::system_clock::now();
            num_failed_attempts = 0;

            return true;
          });
      }
    }
  };
}
