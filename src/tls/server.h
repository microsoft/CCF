// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "context.h"

#include <string>

namespace tls
{
  class Server : public Context
  {
  private:
    std::vector<std::shared_ptr<Cert>> certs;
    std::shared_ptr<Cert> cert;

    void initCallbacks()
    {
      mbedtls_ssl_conf_sni(&cfg, sni_callback, this);
    }

  public:
    Server(std::shared_ptr<Cert> cert, bool dtls = false) : Context(false, dtls)
    {
      certs.push_back(cert);
      initCallbacks();
    }

    Server(std::vector<std::shared_ptr<Cert>> certs_, bool dtls = false) :
      Context(false, dtls),
      certs(certs_)
    {
      initCallbacks();
    }

    std::string host() override
    {
      if (cert)
        return cert->host();

      return {};
    }

  private:
    bool handle_sni(
      mbedtls_ssl_context* ssl, const unsigned char* name, size_t len)
    {
      for (auto& c : certs)
      {
        if (c->sni(ssl, name, len))
        {
          cert = c;
          return true;
        }
      }

      return false;
    }

    static int sni_callback(
      void* ctx,
      mbedtls_ssl_context* ssl,
      const unsigned char* name,
      size_t len)
    {
      auto s = reinterpret_cast<Server*>(ctx);
      return s->handle_sni(ssl, name, len) ? 0 : -1;
    }
  };
}
