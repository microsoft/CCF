// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/buffer.h"
#include "pem.h"

#include <exception>

namespace tls
{
  class CA
  {
  private:
    mbedtls_x509_crt ca;
    mbedtls_x509_crl crl;

  public:
    CA(CBuffer ca_ = nullb, CBuffer crl_ = nullb)
    {
      mbedtls_x509_crt_init(&ca);
      mbedtls_x509_crl_init(&crl);

      if (ca_.n > 0)
      {
        Pem pem_ca(ca_);
        if (mbedtls_x509_crt_parse(&ca, pem_ca.data(), pem_ca.size()) != 0)
          throw std::logic_error("Could not parse CA");
      }

      if (crl_.n > 0)
      {
        Pem pem_crl(crl_);
        if (mbedtls_x509_crl_parse(&crl, pem_crl.data(), pem_crl.size()) != 0)
          throw std::logic_error("Could not parse CRL");
      }
    }

    ~CA()
    {
      mbedtls_x509_crt_free(&ca);
      mbedtls_x509_crl_free(&crl);
    }

    void use(mbedtls_ssl_config* cfg)
    {
      mbedtls_ssl_conf_ca_chain(cfg, &ca, &crl);
    }
  };
}
