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
    SSL* /*ssl*/,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg)
  {
    auto* protos = static_cast<AlpnProtocols*>(arg);

    if (
      SSL_select_next_proto(
        const_cast<unsigned char**>(out),
        outlen,
        protos->data,
        protos->size,
        in,
        inlen) != OPENSSL_NPN_NEGOTIATED)
    {
      return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
  }

  class Server : public ccf::tls::Context
  {
  private:
    std::shared_ptr<Cert> cert;

  public:
    Server(const std::shared_ptr<Cert>& cert_, bool http2 = false) :
      Context(false),
      cert(cert_)
    {
      cert->use(ssl, cfg);

      // Configure protocols negotiated by ALPN
      // See https://nghttp2.org/documentation/tutorial-server.html and use of
      // nghttp2_select_next_protocol for better example
      if (http2)
      {
        static unsigned char alpn_protos_data[] = {2, 'h', '2'};
        static AlpnProtocols alpn_protos{
          alpn_protos_data, sizeof(alpn_protos_data)};
        SSL_CTX_set_alpn_select_cb(cfg, alpn_select_cb, &alpn_protos);
      }
      else
      {
        static unsigned char alpn_protos_data[] = {
          8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        static AlpnProtocols alpn_protos{
          alpn_protos_data, sizeof(alpn_protos_data)};
        SSL_CTX_set_alpn_select_cb(cfg, alpn_select_cb, &alpn_protos);
      }
    }
  };
}
