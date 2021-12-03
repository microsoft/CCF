// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/mbedtls/error_string.h"
#include "crypto/mbedtls/mbedtls_wrappers.h"
#include "crypto/pem.h"
#include "ds/buffer.h"

#include <exception>

// This is a copy of src/tls/ca.h
// Moving tls to OpenSSL means this different client implementation needs
// to be isolated while we change tls_endpoint. Once that's done, we can
// come back here and refactor this too.

namespace client::tls
{
  enum TlsAuth
  {
    tls_auth_default,
    tls_auth_none,
    tls_auth_optional,
    tls_auth_required
  };

  class TlsCA
  {
  private:
    crypto::mbedtls::X509Crt ca = nullptr;
    crypto::mbedtls::X509Crl crl = nullptr;

  public:
    TlsCA(CBuffer ca_ = nullb, CBuffer crl_ = nullb)
    {
      auto tmp_ca = crypto::mbedtls::make_unique<crypto::mbedtls::X509Crt>();
      auto tmp_crl = crypto::mbedtls::make_unique<crypto::mbedtls::X509Crl>();

      if (ca_.n > 0)
      {
        crypto::Pem pem_ca(ca_);
        auto ret =
          mbedtls_x509_crt_parse(tmp_ca.get(), pem_ca.data(), pem_ca.size());
        if (ret != 0)
          throw std::logic_error(
            "Could not parse TlsCA: " + crypto::error_string(ret));
      }

      if (crl_.n > 0)
      {
        crypto::Pem pem_crl(crl_);
        auto ret =
          mbedtls_x509_crl_parse(tmp_crl.get(), pem_crl.data(), pem_crl.size());
        if (ret != 0)
          throw std::logic_error(
            "Could not parse CRL: " + crypto::error_string(ret));
      }

      ca = std::move(tmp_ca);
      crl = std::move(tmp_crl);
    }

    ~TlsCA() {}

    void use(mbedtls_ssl_config* cfg)
    {
      mbedtls_ssl_conf_ca_chain(cfg, ca.get(), crl.get());
    }
  };
}
