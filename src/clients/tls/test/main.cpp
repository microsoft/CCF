// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Unit tests for the certificate helpers used by the C++ test clients, which
// configure an OpenSSL context and connection with a trusted root and an owned
// identity. The TLS transport itself is tested in
// src/host/test/openssl_server_test.cpp.

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/x509_time_fmt.h"
#include "clients/tls/ca.h"
#include "clients/tls/cert.h"
#include "crypto/certs.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <doctest/doctest.h>
#include <memory>
#include <optional>
#include <string>

namespace
{
  constexpr size_t certificate_validity_period_days = 365;

  std::string valid_from_yesterday()
  {
    using namespace std::literals;
    return ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
  }

  ccf::crypto::Pem generate_self_signed_cert(
    const ccf::crypto::ECKeyPairPtr& kp, const std::string& name)
  {
    return ccf::crypto::create_self_signed_cert(
      kp, name, {}, valid_from_yesterday(), certificate_validity_period_days);
  }

  struct NetworkCA
  {
    ccf::crypto::ECKeyPairPtr kp;
    ccf::crypto::Pem cert;
  };

  /// Get self-signed CA certificate.
  NetworkCA get_ca()
  {
    auto kp = ccf::crypto::make_ec_key_pair();
    return {kp, generate_self_signed_cert(kp, "CN=issuer")};
  }

  /// Creates a ::tls::Cert endorsed by the given CA.
  std::unique_ptr<::tls::Cert> get_dummy_cert(
    NetworkCA& net_ca, const std::string& name, bool auth_required = true)
  {
    auto ca = std::make_unique<::tls::CA>(net_ca.cert.str());

    // Create a signing request and sign with the CA
    auto kp = ccf::crypto::make_ec_key_pair();
    auto crt = ccf::crypto::create_endorsed_cert(
      kp,
      "CN=" + name,
      {},
      valid_from_yesterday(),
      certificate_validity_period_days,
      net_ca.kp->private_key_pem(),
      net_ca.cert);

    // Verify node certificate with the CA's certificate
    auto v = ccf::crypto::make_verifier(crt);
    REQUIRE(v->verify_certificate({&net_ca.cert}));

    return std::make_unique<::tls::Cert>(
      std::move(ca), crt, kp->private_key_pem(), std::nullopt, auth_required);
  }
}

TEST_CASE("CA configures trusted certificate store")
{
  auto ca = get_ca();
  ::tls::CA trusted_ca(ca.cert.str(), true);
  ccf::crypto::OpenSSL::Unique_SSL_CTX ctx(TLS_method());

  trusted_ca.configure_trusted_cert_store(ctx);

  auto* store = SSL_CTX_get_cert_store(ctx);
  REQUIRE(store != nullptr);
  auto* params = X509_STORE_get0_param(store);
  REQUIRE(params != nullptr);
  REQUIRE(
    (X509_VERIFY_PARAM_get_flags(params) & X509_V_FLAG_PARTIAL_CHAIN) != 0);
}

TEST_CASE("Cert configures TLS verification and own certificate")
{
  auto ca = get_ca();

  SUBCASE("auth_required requires a peer certificate")
  {
    auto cert = get_dummy_cert(ca, "server");
    ccf::crypto::OpenSSL::Unique_SSL_CTX ctx(TLS_method());

    cert->configure_context(ctx);
    ccf::crypto::OpenSSL::Unique_SSL ssl(ctx);
    cert->configure_connection(ssl);

    constexpr auto expected_verify_mode =
      SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    REQUIRE(SSL_CTX_get_verify_mode(ctx) == expected_verify_mode);
    REQUIRE(SSL_get_verify_mode(ssl) == expected_verify_mode);
    REQUIRE(SSL_CTX_get0_certificate(ctx) != nullptr);
    REQUIRE(SSL_get_certificate(ssl) != nullptr);
  }

  SUBCASE("without auth_required a peer certificate is requested, not required")
  {
    auto cert = get_dummy_cert(ca, "server", false);
    ccf::crypto::OpenSSL::Unique_SSL_CTX ctx(TLS_method());

    cert->configure_context(ctx);
    ccf::crypto::OpenSSL::Unique_SSL ssl(ctx);
    cert->configure_connection(ssl);

    // The connection inherits the context's verification mode
    REQUIRE((SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) != 0);
    REQUIRE((SSL_get_verify_mode(ssl) & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) == 0);
  }
}
