// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/http_consts.h"
#include "ccf/http_status.h"
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

    // Contact addresses (see RFC8555 7.3, e.g. mailto:john@example.com)
    std::vector<std::string> contact;

    // Indication that the user/operator is aware of the latest terms and
    // conditions for the CA
    bool terms_of_service_agreed = false;

    // Type of the ACME challenge (currently only http-01 supported)
    std::string challenge_type = "http-01";

    // Interface for the (http) challenge server to listen on
    std::string challenge_server_interface = "0.0.0.0:80";

    bool operator==(const ClientConfig& other) const = default;
  };

  class Client
  {
  public:
    Client(const ClientConfig& config) : config(config)
    {
      account_key_pair = crypto::make_key_pair();

      identifiers = nlohmann::json::array({
        {{"type", "dns"}, {"value", config.service_dns_name}},
      });
    }

    virtual ~Client() {}

    void get_certificate(std::shared_ptr<crypto::KeyPair> service_key)
    {
      this->service_key = service_key;
      request_directory();
    }

    void start_challenge(const std::string& token)
    {
      auto cit = active_challenges.find(token);
      if (cit != active_challenges.end())
      {
        threading::ThreadMessaging::thread_messaging.add_task_after(
          schedule_check_challenge(cit->second), std::chrono::milliseconds(0));
      }
    }

  protected:
    virtual void on_challenge(const std::string& key_authorization) = 0;
    virtual void on_certificate(const std::string& certificate) = 0;
    virtual void make_http_request(
      const http::URL& url,
      std::vector<uint8_t>&& req,
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
      std::unique_lock<std::mutex> guard(req_lock);

      try
      {
        auto port = url.port.empty() ? "443" : url.port;
        LOG_INFO_FMT(
          "ACME: Requesting https://{}:{}{}", url.host, port, url.path);

        http::Request r(url.path, method);
        r.set_header(http::headers::ACCEPT, "*/*");
        r.set_header(http::headers::HOST, url.host);
        if (!body.empty())
        {
          r.set_header(http::headers::CONTENT_TYPE, "application/jose+json");
          r.set_body(&body);
        }
        auto req = r.build_request();
        std::string reqs(req.begin(), req.end());
        LOG_TRACE_FMT("ACME: Request:\n{}", reqs);

        make_http_request(
          url,
          std::move(req),
          [this, expected_status, ok_callback](
            http_status status,
            http::HeaderMap&& headers,
            std::vector<uint8_t>&& data) {
            for (auto& [k, v] : headers)
            {
              LOG_TRACE_FMT("ACME: H: {}: {}", k, v);
            }

            LOG_TRACE_FMT(
              "ACME: data: {}", std::string(data.begin(), data.end()));

            if (status != expected_status && status != HTTP_STATUS_OK)
            {
              LOG_DEBUG_FMT("ACME: request failed with status={}", (int)status);
              return false;
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
        LOG_FAIL_FMT("Failed to connect to ACME server: {}", ex.what());
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
        JWS jws(header, true, *account_key_pair);
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
          header,
          true,
          nlohmann::json::object_t(),
          *account_key_pair,
          empty_payload);
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

    const ClientConfig& config;
    std::shared_ptr<crypto::KeyPair> service_key;
    std::shared_ptr<crypto::KeyPair> account_key_pair;

    nlohmann::json identifiers;
    nlohmann::json directory;
    nlohmann::json account;
    std::list<std::string> nonces;
    std::unordered_set<std::string> pending_authorizations;

    std::mutex req_lock;
    std::mutex finalize_lock;

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

    static void convert_signature_to_ieee_p1363(std::vector<uint8_t>& sig)
    {
      // Convert signature from ASN.1 format to IEEE P1363
      const unsigned char* pp = sig.data();
      ECDSA_SIG* sig_r_s = d2i_ECDSA_SIG(NULL, &pp, sig.size());
      const BIGNUM* r = ECDSA_SIG_get0_r(sig_r_s);
      const BIGNUM* s = ECDSA_SIG_get0_s(sig_r_s);
      int r_n = BN_num_bytes(r);
      int s_n = BN_num_bytes(s);
      assert(r_n <= 48 && s_n <= 48);
      sig = std::vector<uint8_t>(96, 0);
      BN_bn2bin(r, sig.data() + 48 - r_n);
      BN_bn2bin(s, sig.data() + 96 - s_n);
    }

    class JWS : public nlohmann::json::object_t
    {
    public:
      JWS(
        const nlohmann::json& header_,
        bool header_is_protected_,
        const nlohmann::json& payload_,
        crypto::KeyPair& signer_,
        bool empty_payload = false) :
        header_is_protected(header_is_protected_)
      {
        LOG_TRACE_FMT("JWS header: {}", header_.dump());
        LOG_TRACE_FMT("JWS payload: {}", payload_.dump());
        auto header_b64 = json_to_b64url(header_, false);
        auto payload_b64 = empty_payload ? "" : json_to_b64url(payload_, false);
        set(header_b64, payload_b64, signer_);
      }

      JWS(
        const nlohmann::json& header_,
        bool header_is_protected_,
        crypto::KeyPair& signer_) :
        JWS(
          header_,
          header_is_protected_,
          nlohmann::json::object_t(),
          signer_,
          true)
      {}

      virtual ~JWS() {}

    protected:
      bool header_is_protected = true;

      void set(
        const std::string& header_b64,
        const std::string& payload_b64,
        crypto::KeyPair& signer)
      {
        auto msg = header_b64 + "." + payload_b64;
        auto sig = signer.sign(s2v(msg));
        convert_signature_to_ieee_p1363(sig);
        auto sig_b64 = crypto::b64url_from_raw(sig);

        (*this)[header_is_protected ? "protected" : "header"] = header_b64;
        (*this)["payload"] = payload_b64;
        (*this)["signature"] = sig_b64;

        // LOG_TRACE_FMT("ACME: private key: {}:",
        // signer.private_key_pem().str()); LOG_TRACE_FMT("ACME: public key:
        // {}:", signer.public_key_pem().str());
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
      virtual ~JWK() {}
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

        if (key_coords.x.size() != key_coords.y.size())
        {
          throw std::runtime_error(fmt::format(
            "invalid EC coordinate sizes in new account request {}!={}",
            key_coords.x.size(),
            key_coords.y.size()));
        }

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

        JWS jws(header, true, payload, *account_key_pair);

        http::URL url = with_default_port(new_account_url);
        make_json_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_CREATED,
          [this](const http::HeaderMap& headers, const nlohmann::json& j) {
            expect_string(j, "status", "valid");
            // expect(j, "orders"); // CHECK: Isn't this mandatory?
            account = j;
            auto loc_opt = get_header_value(headers, "location");
            submit_new_order(loc_opt.value_or(""));
          });
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

    void authorize_next_challenge(
      const std::string& account_url, std::string finalize_url)
    {
      if (!pending_authorizations.empty())
      {
        submit_authorization(
          account_url, *pending_authorizations.begin(), finalize_url);
      }
    }

    void submit_new_order(const std::string& account_url)
    {
      if (nonces.empty())
      {
        request_new_nonce(
          [this, account_url]() { submit_new_order(account_url); });
      }
      else
      {
        auto nonce = nonces.front();
        nonces.pop_front();

        auto header =
          mk_kid_header(account_url, nonce, directory.at("newOrder"));

        nlohmann::json payload = {{"identifiers", identifiers}};

        // Let's encrypt does not support custom dates
        // payload["notBefore"] = *config.not_before;
        // payload["notAfter"] = *config.not_after;

        JWS jws(header, true, payload, *account_key_pair);

        http::URL url = with_default_port(directory.at("newOrder"));
        make_json_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_CREATED,
          [this, account_url](
            const http::HeaderMap& headers, const nlohmann::json& j) {
            expect(j, "status");

            if (j["status"] == "pending" && j.contains("authorizations"))
            {
              expect(j, "authorizations");
              pending_authorizations =
                j["authorizations"].get<std::unordered_set<std::string>>();
              authorize_next_challenge(account_url, j["finalize"]);
            }
            else if (j["status"] == "ready")
            {
              expect(j, "finalize");
              submit_finalize(account_url, j["finalize"]);
            }
            else if (j["status"] == "valid")
            {
              expect(j, "certificate");
              download_certificate(account_url, j["certificate"]);
            }
          });
      }
    }

    void submit_authorization(
      const std::string& account_url,
      const std::string& authz_url,
      const std::string& finalize_url)
    {
      post_as_get_json(
        account_url,
        authz_url,
        [this, account_url, authz_url, finalize_url](
          const http::HeaderMap& headers, const nlohmann::json& j) {
          LOG_TRACE_FMT("ACME: authorization reply: {}", j.dump());
          expect_string(j, "status", "pending");
          expect(j, "challenges");

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
              std::string url = challenge["url"];

              add_challenge(account_url, token, url, finalize_url);
              found_match = true;
              break;
            }
          }

          pending_authorizations.erase(authz_url);

          if (!found_match)
          {
            throw std::runtime_error(fmt::format(
              "challenge type '{}' not offered", config.challenge_type));
          }

          authorize_next_challenge(account_url, finalize_url);

          return true;
        },
        true);
    }

    struct Challenge
    {
      std::string account_url;
      std::string token;
      std::string challenge_url;
      std::string finalize_url;
    };

    std::map<std::string, Challenge> active_challenges;

    void add_challenge(
      const std::string& account_url,
      const std::string& token,
      const std::string& challenge_url,
      const std::string& finalize_url)
    {
      auto crv_alg = get_crv_alg(account_key_pair);
      auto key_coords = account_key_pair->coordinates();

      if (key_coords.x.size() != key_coords.y.size())
      {
        throw std::runtime_error(fmt::format(
          "invalid EC coordinate sizes in add_challenge {}!={}",
          key_coords.x.size(),
          key_coords.y.size()));
      }

      JWK jwk(
        "EC",
        crv_alg.first,
        crypto::b64url_from_raw(key_coords.x, false),
        crypto::b64url_from_raw(key_coords.y, false));

      active_challenges.emplace(
        token, Challenge{account_url, token, challenge_url, finalize_url});

      auto thumbprint = crypto::sha256(s2v(nlohmann::json(jwk).dump()));
      std::string key_authorization =
        token + "." + crypto::b64url_from_raw(thumbprint, false);
      on_challenge(key_authorization);
    }

    struct ChallengeWaitMsg
    {
      ChallengeWaitMsg(Challenge challenge, Client* client) :
        challenge(challenge),
        client(client)
      {}
      Challenge challenge;
      Client* client;
    };

    bool is_challenge_in_progress(const std::string& token) const
    {
      return active_challenges.find(token) != active_challenges.end();
    }

    std::unique_ptr<threading::Tmsg<ChallengeWaitMsg>> schedule_check_challenge(
      const Challenge& challenge)
    {
      return std::make_unique<threading::Tmsg<ChallengeWaitMsg>>(
        [](std::unique_ptr<threading::Tmsg<ChallengeWaitMsg>> msg) {
          const Challenge& challenge = msg->data.challenge;
          Client* client = msg->data.client;

          if (client->check_challenge(challenge))
          {
            LOG_TRACE_FMT("ACME: scheduling next challenge check");
            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), std::chrono::seconds(5));
          }
        },
        challenge,
        this);
    }

    bool check_challenge(const Challenge& challenge)
    {
      if (is_challenge_in_progress(challenge.token))
      {
        LOG_TRACE_FMT(
          "ACME: Requesting challenge status for token '{}' ...",
          challenge.token);

        post_as_get_json(
          challenge.account_url,
          challenge.challenge_url,
          [this, token = challenge.token](
            const http::HeaderMap& headers, const nlohmann::json& j) {
            LOG_TRACE_FMT("ACME: challenge result: {}", j.dump());
            expect(j, "status");

            if (j["status"] == "valid")
            {
              finalize_challenge(token);
            }
            else if (j["status"] == "pending")
            {
              if (j.contains("error"))
              {
                LOG_FAIL_FMT(
                  "ACME: Challenge for token '{}' failed with the "
                  "following error: {}",
                  token,
                  j["error"].dump());
              }
              else
              {
                return true;
              }
            }
            else
            {
              LOG_FAIL_FMT(
                "ACME: Challenge for token '{}' failed with status '{}' ",
                token,
                j["status"]);
            }

            return false;
          });

        return true;
      }

      return false;
    }

    void finalize_challenge(const std::string& token)
    {
      std::unique_lock<std::mutex> guard(finalize_lock);

      auto cit = active_challenges.find(token);
      if (cit == active_challenges.end())
      {
        throw std::runtime_error(
          fmt::format("No active challenge for token '{}'", token));
      }

      Challenge challenge = cit->second;

      active_challenges.erase(cit);

      if (active_challenges.empty())
      {
        submit_finalize(challenge.account_url, challenge.finalize_url);
      }
    }

    void submit_finalize(
      const std::string& account_url, const std::string& finalize_url)
    {
      if (!active_challenges.empty())
      {
        return;
      }

      if (nonces.empty())
      {
        request_new_nonce(
          [=]() { submit_finalize(account_url, finalize_url); });
      }
      else
      {
        auto nonce = nonces.front();
        nonces.pop_front();

        auto header = mk_kid_header(account_url, nonce, finalize_url);

        auto csr = service_key->create_csr_der(
          "CN=" + config.service_dns_name, {{config.service_dns_name, false}});

        nlohmann::json payload = {{"csr", crypto::b64url_from_raw(csr, false)}};

        JWS jws(header, true, payload, *account_key_pair);

        http::URL url = with_default_port(finalize_url);
        make_json_request(
          HTTP_POST,
          url,
          json_to_bytes(jws),
          HTTP_STATUS_OK,
          [this, account_url](
            const http::HeaderMap& headers, const nlohmann::json& j) {
            expect(j, "certificate");
            LOG_TRACE_FMT("ACME: finalize successful");
            download_certificate(account_url, j["certificate"]);
          });
      }
    }

    void download_certificate(
      const std::string& account_url, const std::string& certificate_url)
    {
      http::URL url = with_default_port(certificate_url);
      post_as_get(
        account_url,
        certificate_url,
        [this](
          const http::HeaderMap& headers, const std::vector<uint8_t>& data) {
          std::string c(data.data(), data.data() + data.size());
          LOG_TRACE_FMT("Obtained certificate (chain): {}", c);
          on_certificate(c);
          return true;
        });
    }
  };

}
