// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/pem.h"

#include <exception>

using namespace ccf::crypto::OpenSSL;

namespace tls
{
  class CA
  {
  private:
    std::vector<Unique_X509> cas;
    bool partial_ok = false;

    void append_cert(const std::string& ca_string)
    {
      if (!ca_string.empty())
      {
        Unique_BIO bio(ca_string.data(), ca_string.size());
        Unique_X509 ca;
        if (!(ca = Unique_X509(bio, true)))
        {
          throw std::runtime_error(
            "Could not parse CA: " + error_string(ERR_get_error()));
        }
        cas.push_back(std::move(ca));
      }
    }

  public:
    CA(const std::string& ca, bool partial_ok_ = false) :
      partial_ok(partial_ok_)
    {
      append_cert(ca);
    }

    CA(const std::vector<std::string>& ca_strings, bool partial_ok_ = false) :
      partial_ok(partial_ok_)
    {
      for (const auto& ca_string : ca_strings)
      {
        append_cert(ca_string);
      }
    }

    CA(const std::vector<ccf::crypto::Pem>& ca_pems, bool partial_ok_ = false) :
      partial_ok(partial_ok_)
    {
      for (const auto& ca_pem : ca_pems)
      {
        append_cert(ca_pem.str());
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
