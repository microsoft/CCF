// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ds/internal_logger.h"
#include "tls/ca.h"
#include "tls/cert.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <string>
#include <vector>

using namespace ccf::crypto::OpenSSL;

#ifdef _DEBUG
static BIO* bio_err = NULL;

static void apps_ssl_info_callback(const SSL* s, int where, int ret)
{
  const char* str;
  int w = where & ~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT)
    str = "SSL_connect";
  else if (w & SSL_ST_ACCEPT)
    str = "SSL_accept";
  else
    str = "undefined";

  if (where & SSL_CB_LOOP)
  {
    BIO_printf(bio_err, "%s:%s\n", str, SSL_state_string_long(s));
  }
  else if (where & SSL_CB_ALERT)
  {
    str = (where & SSL_CB_READ) ? "read" : "write";
    BIO_printf(
      bio_err,
      "SSL3 alert %s:%s:%s\n",
      str,
      SSL_alert_type_string_long(ret),
      SSL_alert_desc_string_long(ret));
  }
  else if (where & SSL_CB_EXIT)
  {
    if (ret == 0)
    {
      BIO_printf(bio_err, "%s:failed in %s\n", str, SSL_state_string_long(s));
    }
    else if (ret < 0)
    {
      BIO_printf(bio_err, "%s:error in %s\n", str, SSL_state_string_long(s));
    }
  }
}
#endif

namespace client
{
  class TlsClient
  {
  protected:
    std::string host;
    std::string port;
    std::shared_ptr<::tls::CA> node_ca;
    std::shared_ptr<::tls::Cert> cert;
    bool connected = false;

    Unique_SSL_CTX ctx;
    Unique_BIO bio;

    void init()
    {
      SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);

      SSL* ssl;
      BIO_get_ssl(bio, &ssl);
      if (!ssl)
      {
        throw std::runtime_error("Couldn't locate SSL pointer");
      }
      SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);

#ifdef _DEBUG
      bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);
      SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
      SSL_set_info_callback(ssl, apps_ssl_info_callback);
#endif

      BIO_set_conn_hostname(bio, host.c_str());
      BIO_set_conn_port(bio, port.c_str());
      BIO_set_nbio(bio, 1);

      if (cert)
        cert->use(ssl, ctx);
      if (node_ca)
        node_ca->use(ctx);

      do
      {
        BIO_do_connect(bio);
      } while (BIO_should_retry(bio));

      do
      {
        BIO_do_handshake(bio);
      } while (BIO_should_retry(bio));

      connected = true;
    }

  public:
    TlsClient(
      const std::string& host,
      const std::string& port,
      std::shared_ptr<::tls::CA> node_ca = nullptr,
      std::shared_ptr<::tls::Cert> cert = nullptr) :
      host(host),
      port(port),
      node_ca(node_ca),
      cert(cert),
      ctx(TLS_client_method()),
      bio(ctx)
    {
      init();
    }

    TlsClient(const TlsClient& c) :
      host(c.host),
      port(c.port),
      node_ca(c.node_ca),
      cert(c.cert),
      ctx(TLS_client_method()),
      bio(ctx)
    {
      init();
    }

    virtual ~TlsClient()
    {
      SSL* ssl;
      BIO_get_ssl(bio, &ssl);
      SSL_shutdown(ssl);
    }

    auto get_ciphersuite_name()
    {
      SSL* ssl;
      BIO_get_ssl(bio, &ssl);
      return SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
    }

    void write(std::span<const uint8_t> b)
    {
      for (size_t written = 0; written < b.size();)
      {
        auto ret = 0;
        do
        {
          ret = BIO_write(bio, b.data() + written, b.size() - written);
        } while (ret < 0 && BIO_should_retry(bio));

        if (ret >= 0)
        {
          written += ret;
        }
        else
        {
          throw std::logic_error(error_string(ERR_get_error()));
        }
      }
    }

    std::vector<uint8_t> read(size_t read_size)
    {
      std::vector<uint8_t> buf(read_size);

      auto ret = 0;
      do
      {
        ret = BIO_read(bio, buf.data(), buf.size());
      } while (ret < 0 && BIO_should_retry(bio));

      if (ret > 0)
      {
        buf.resize(ret);
      }
      else if (ret == 0)
      {
        connected = false;
        throw std::logic_error("Underlying transport closed");
      }
      else
      {
        throw std::logic_error(error_string(ERR_get_error()));
      }

      return buf;
    }

    bool bytes_available()
    {
      return BIO_pending(bio) > 0;
    }

    std::vector<uint8_t> read_all()
    {
      constexpr auto read_size = 4096;
      return read(read_size);
    }

    void set_tcp_nodelay(bool on)
    {
      int option = on ? 1 : 0;
      int fd = -1;
      BIO_get_fd(bio, &fd);
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&option, sizeof(int));
    }
  };
}
