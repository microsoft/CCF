// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../crypto/mbedtls/mbedtls_wrappers.h"
#include "../crypto/pem.h"
#include "../ds/buffer.h"

#include <exception>

namespace tls
{
  class CA
  {
  private:
    crypto::mbedtls::X509Crt ca = nullptr;
    crypto::mbedtls::X509Crl crl = nullptr;

  public:
    CA(CBuffer ca_ = nullb, CBuffer crl_ = nullb)
    {
      auto tmp_ca = crypto::mbedtls::make_unique<crypto::mbedtls::X509Crt>();
      auto tmp_crl = crypto::mbedtls::make_unique<crypto::mbedtls::X509Crl>();

      if (ca_.n > 0)
      {
        crypto::Pem pem_ca(ca_);
        if (
          mbedtls_x509_crt_parse(tmp_ca.get(), pem_ca.data(), pem_ca.size()) !=
          0)
          throw std::logic_error("Could not parse CA");
      }

      if (crl_.n > 0)
      {
        crypto::Pem pem_crl(crl_);
        if (
          mbedtls_x509_crl_parse(
            tmp_crl.get(), pem_crl.data(), pem_crl.size()) != 0)
          throw std::logic_error("Could not parse CRL");
      }

      ca = std::move(tmp_ca);
      crl = std::move(tmp_crl);
    }

    ~CA() {}

    void use(mbedtls_ssl_config* cfg)
    {
      mbedtls_ssl_conf_ca_chain(cfg, ca.get(), crl.get());
    }
  };
}
