// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/buffer.h"
#include "mbedtls_wrappers.h"
#include "pem.h"

#include <exception>

namespace tls
{
  class CA
  {
  private:
    mbedtls::X509Crt ca = nullptr;
    mbedtls::X509Crl crl = nullptr;

  public:
    CA(CBuffer ca_ = nullb, CBuffer crl_ = nullb)
    {
      auto tmp_ca = mbedtls::make_unique<mbedtls::X509Crt>();
      auto tmp_crl = mbedtls::make_unique<mbedtls::X509Crl>();

      if (ca_.n > 0)
      {
        Pem pem_ca(ca_);
        if (
          mbedtls_x509_crt_parse(tmp_ca.get(), pem_ca.data(), pem_ca.size()) !=
          0)
          throw std::logic_error("Could not parse CA");
      }

      if (crl_.n > 0)
      {
        Pem pem_crl(crl_);
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
