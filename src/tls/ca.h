// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/buffer.h"
#include "crypto/openssl/openssl_wrappers.h"

#include <exception>

using namespace crypto;
using namespace crypto::OpenSSL;

namespace tls
{
  class CA
  {
  private:
    Unique_X509 ca;

  public:
    CA(CBuffer ca_ = nullb)
    {
      if (ca_.n > 0)
      {
        Unique_BIO bio(ca_.p, ca_.n);
        if (!(ca = Unique_X509(bio, true)))
        {
          throw std::logic_error(
            "Could not parse CA: " + error_string(ERR_get_error()));
        }
      }
    }

    ~CA() = default;

    void use(SSL_CTX* ssl_ctx)
    {
      X509_STORE* store = X509_STORE_new();
      CHECK1(X509_STORE_add_cert(store, ca));
      SSL_CTX_set_cert_store(ssl_ctx, store);
    }
  };
}
