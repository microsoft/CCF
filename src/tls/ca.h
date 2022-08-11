// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "crypto/openssl/openssl_wrappers.h"

#include <exception>

using namespace crypto::OpenSSL;

namespace tls
{
  class CA
  {
  private:
    std::vector<Unique_X509> cas;
    bool partial_ok = false;

  public:
    CA(const std::string& ca_ = "", bool partial_ok = false) :
      CA(std::vector<std::string>({ca_}), partial_ok)
    {}

    CA(
      const std::vector<std::string>& ca_strings = {},
      bool partial_ok = false) :
      partial_ok(partial_ok)
    {
      for (const auto& ca_string : ca_strings)
      {
        if (!ca_string.empty())
        {
          Unique_BIO bio(ca_string.data(), ca_string.size());
          Unique_X509 ca;
          if (!(ca = Unique_X509(bio, true)))
          {
            throw std::logic_error(
              "Could not parse CA: " + error_string(ERR_get_error()));
          }
          cas.push_back(std::move(ca));
        }
      }
    }

    ~CA() = default;

    void use(SSL_CTX* ssl_ctx)
    {
      X509_STORE* store = X509_STORE_new();
      if (partial_ok)
      {
        CHECK1(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN));
      }
      for (const auto& ca : cas)
      {
        CHECK1(X509_STORE_add_cert(store, ca));
      }
      SSL_CTX_set_cert_store(ssl_ctx, store);
    }
  };
}
