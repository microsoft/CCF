// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/pem.h"
#include "ds/buffer.h"
#include "ds/logger.h"

#include <exception>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace tls
{
  class CA
  {
  private:
    mutable crypto::OpenSSL::Unique_X509 ca;
    mutable crypto::OpenSSL::Unique_X509_CRL crl;

  public:
    CA(CBuffer ca_ = nullb, CBuffer crl_ = nullb)
    {
      crypto::OpenSSL::Unique_X509 tmp_ca;
      crypto::OpenSSL::Unique_X509_CRL tmp_crl;

      if (ca_.n > 0)
      {
        crypto::Pem pem_ca(ca_);
        LOG_TRACE_FMT("CA::ctor: PEM: {}", pem_ca.str());
        BIO* certBio = BIO_new(BIO_s_mem());
        BIO_write(certBio, pem_ca.data(), pem_ca.size());
        X509* res = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
        BIO_free(certBio);
        if (!res)
        {
          auto err_str = crypto::OpenSSL::error_string(ERR_get_error());
          LOG_FAIL_FMT("CA::ctor: Could not parse CA: {}", err_str);
          throw std::logic_error("Could not parse CA: " + err_str);
        }
        // The PEM_read function above checks the validity of the certificate,
        // but not if it's a CA or can be used as such. This is what MbedTLS
        // checks, so we keep it simple here. Some code uses this as a
        // "certificate check" not necessarily a CA check, so we need to keep it
        // compatible.
        // To cater to that usage, we should create a generic helper in crypto
        // to do the certificate check and add X509_check_ca() here to be more
        // robust on our verification.
        tmp_ca.reset(res);
      }

      if (crl_.n > 0)
      {
        // We don't seem to be using CRL anywhere in CCF, so we should
        // really remove this option once MbedTLS is gone.
        LOG_FAIL_FMT("CA::ctor: Using CRL in OpenSSL CA");
        throw std::logic_error("Using CRL in OpenSSL CA");
      }

      ca = std::move(tmp_ca);
      crl = std::move(tmp_crl);
    }

    ~CA() = default;

    void use(SSL* ssl, SSL_CTX* cfg)
    {
      SSL_CTX_use_certificate(cfg, ca);
      SSL_use_certificate(ssl, ca);
    }
  };
}
