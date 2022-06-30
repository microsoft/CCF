// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "context.h"

namespace tls
{
  struct AlpnProtocols
  {
    const unsigned char* data;
    unsigned int size;
  };

  static int alpn_select_cb(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg)
  {
    auto protos = (AlpnProtocols*)arg;

    if (
      SSL_select_next_proto(
        (unsigned char**)out, outlen, protos->data, protos->size, in, inlen) !=
      OPENSSL_NPN_NEGOTIATED)
    {
      return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
  }

  class Server : public Context
  {
  private:
    std::shared_ptr<Cert> cert;

  public:
    Server(std::shared_ptr<Cert> cert_) : Context(false), cert(cert_)
    {
      cert->use(ssl, cfg);

      // Configure protocols negotiated by ALPN
      // TODO: h2 only for http2 interface
      static unsigned char alpn_protos_data[] = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
      static AlpnProtocols alpn_protos{
        alpn_protos_data, sizeof(alpn_protos_data)};
      SSL_CTX_set_alpn_select_cb(cfg, alpn_select_cb, &alpn_protos);
    }
  };
}
