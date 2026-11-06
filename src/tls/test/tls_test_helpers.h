// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/certs.h"

#include <chrono>
#include <condition_variable>
#include <doctest/doctest.h>
#include <memory>
#include <mutex>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <string>
#include <thread>
#include <utility>
#include <uv.h>

namespace ccf::tls::test
{
  inline std::pair<std::string, std::string> make_server_cert()
  {
    using namespace std::chrono_literals;
    auto key = ccf::crypto::make_ec_key_pair();
    auto cert = ccf::crypto::create_self_signed_cert(
      key,
      "CN=localhost",
      {},
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h),
      365);
    return {cert.str(), key->private_key_pem().str()};
  }

  inline std::shared_ptr<SSL_CTX> make_server_context(
    const std::string& cert, const std::string& key)
  {
    std::shared_ptr<SSL_CTX> context(
      SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    REQUIRE(context != nullptr);
    ccf::crypto::OpenSSL::Unique_BIO cert_bio(
      cert.data(), static_cast<int>(cert.size()));
    ccf::crypto::OpenSSL::Unique_X509 x509(cert_bio, true);
    REQUIRE(x509 != nullptr);
    ccf::crypto::OpenSSL::Unique_BIO key_bio(
      key.data(), static_cast<int>(key.size()));
    ccf::crypto::OpenSSL::Unique_PKEY pkey(
      PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr),
      EVP_PKEY_free);
    REQUIRE(SSL_CTX_use_certificate(context.get(), x509) == 1);
    REQUIRE(SSL_CTX_use_PrivateKey(context.get(), pkey) == 1);
    return context;
  }

  inline std::shared_ptr<SSL_CTX> make_client_context(
    const std::string& trusted_cert = {})
  {
    std::shared_ptr<SSL_CTX> context(
      SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    REQUIRE(context != nullptr);
    if (!trusted_cert.empty())
    {
      ccf::crypto::OpenSSL::Unique_BIO bio(
        trusted_cert.data(), static_cast<int>(trusted_cert.size()));
      ccf::crypto::OpenSSL::Unique_X509 root(bio, true);
      REQUIRE(root != nullptr);
      REQUIRE(
        X509_STORE_add_cert(SSL_CTX_get_cert_store(context.get()), root) == 1);
      SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    }
    return context;
  }

  struct AsyncTest
  {
    std::mutex mutex;
    std::condition_variable cv;

    template <typename Predicate>
    bool wait(Predicate predicate)
    {
      std::unique_lock lock(mutex);
      return cv.wait_for(lock, std::chrono::seconds(5), predicate);
    }
  };

  struct UVLoopRunner
  {
    std::thread thread;

    void start(uv_loop_t* loop = uv_default_loop())
    {
      thread = std::thread([loop]() { uv_run(loop, UV_RUN_DEFAULT); });
    }

    void join()
    {
      if (thread.joinable())
      {
        thread.join();
      }
    }

    ~UVLoopRunner()
    {
      join();
    }
  };
}
