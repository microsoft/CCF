// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "cert.h"
#include "ds/framework_logger.h"
#include "tls/tls.h"

#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace ccf::tls
{
  class Context
  {
  protected:
    ccf::crypto::OpenSSL::Unique_SSL_CTX cfg;
    ccf::crypto::OpenSSL::Unique_SSL ssl;

  public:
    Context(bool client) :
      cfg(client ? TLS_client_method() : TLS_server_method()),
      ssl(cfg)
    {
      // Require at least TLS 1.2, support up to 1.3
      SSL_CTX_set_min_proto_version(cfg, TLS1_2_VERSION);
      SSL_set_min_proto_version(ssl, TLS1_2_VERSION);

      // Disable renegotiation to avoid DoS
      SSL_CTX_set_options(
        cfg,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
          SSL_OP_NO_RENEGOTIATION);
      SSL_set_options(
        ssl,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
          SSL_OP_NO_RENEGOTIATION);

      // Set cipher for TLS 1.2
      const auto cipher_list =
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256";
      SSL_CTX_set_cipher_list(cfg, cipher_list);
      SSL_set_cipher_list(ssl, cipher_list);

      // Set cipher for TLS 1.3
      const auto ciphersuites =
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256";
      SSL_CTX_set_ciphersuites(cfg, ciphersuites);
      SSL_set_ciphersuites(ssl, ciphersuites);

      // Restrict the curves to approved ones
      SSL_CTX_set1_curves_list(cfg, "P-521:P-384:P-256");
      SSL_set1_curves_list(ssl, "P-521:P-384:P-256");

      // Allow buffer to be relocated between WANT_WRITE retries, and do partial
      // writes if possible
      SSL_CTX_set_mode(
        cfg,
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
      SSL_set_mode(
        ssl,
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

      // Initialise connection
      if (client)
        SSL_set_connect_state(ssl);
      else
        SSL_set_accept_state(ssl);
    }

    virtual ~Context() = default;

    virtual void set_bio(
      void* cb_obj, BIO_callback_fn_ex send, BIO_callback_fn_ex recv)
    {
      // Read/Write BIOs will be used by TLS
      BIO* rbio = BIO_new(BIO_s_mem());
      BIO_set_mem_eof_return(rbio, -1);
      BIO_set_callback_arg(rbio, (char*)cb_obj);
      BIO_set_callback_ex(rbio, recv);
      SSL_set0_rbio(ssl, rbio);

      BIO* wbio = BIO_new(BIO_s_mem());
      BIO_set_mem_eof_return(wbio, -1);
      BIO_set_callback_arg(wbio, (char*)cb_obj);
      BIO_set_callback_ex(wbio, send);
      SSL_set0_wbio(ssl, wbio);
    }

    virtual int handshake()
    {
      if (SSL_is_init_finished(ssl))
        return 0;

      int rc = SSL_do_handshake(ssl);
      // Success in OpenSSL is 1, MBed is 0
      if (rc > 0)
      {
        LOG_TRACE_FMT("Context::handshake() : Success");
        return 0;
      }

      // Want read/write needs special return
      if (SSL_want_read(ssl))
      {
        return TLS_ERR_WANT_READ;
      }
      else if (SSL_want_write(ssl))
      {
        return TLS_ERR_WANT_WRITE;
      }

      // So does x509 validation
      if (!peer_cert_ok())
      {
        return TLS_ERR_X509_VERIFY;
      }

      // Everything else falls here.
      LOG_TRACE_FMT("Context::handshake() : Error code {}", rc);

      // As an MBedTLS emulation, we return negative for errors.
      return -SSL_get_error(ssl, rc);
    }

    virtual int read(uint8_t* buf, size_t len)
    {
      if (len == 0)
        return 0;
      size_t readbytes = 0;
      int rc = SSL_read_ex(ssl, buf, len, &readbytes);
      if (rc > 0)
      {
        return readbytes;
      }
      if (SSL_want_read(ssl))
      {
        return TLS_ERR_WANT_READ;
      }

      // Everything else falls here.
      LOG_TRACE_FMT("Context::read() : Error code {}", rc);

      // As an MBedTLS emulation, we return negative for errors.
      return -SSL_get_error(ssl, rc);
    }

    virtual int write(const uint8_t* buf, size_t len)
    {
      if (len == 0)
        return 0;
      size_t written = 0;
      int rc = SSL_write_ex(ssl, buf, len, &written);
      if (rc > 0)
      {
        return written;
      }
      if (SSL_want_write(ssl))
      {
        return TLS_ERR_WANT_WRITE;
      }

      // Everything else falls here.
      LOG_TRACE_FMT("Context::write() : Error code {}", rc);

      // As an MBedTLS emulation, we return negative for errors.
      return -SSL_get_error(ssl, rc);
    }

    virtual int close()
    {
      LOG_TRACE_FMT("Context::close() : Shutdown");
      return SSL_shutdown(ssl);
    }

    virtual bool peer_cert_ok()
    {
      return SSL_get_verify_result(ssl) == X509_V_OK;
    }

    virtual std::string get_verify_error()
    {
      return X509_verify_cert_error_string(SSL_get_verify_result(ssl));
    }

    virtual std::string host()
    {
      return {};
    }

    virtual std::vector<uint8_t> peer_cert()
    {
      // CodeQL complains that we don't verify the peer certificate. We don't
      // need to do that because it's been verified before and we use
      // SSL_get_peer_certificate just to extract it from the context.

      ccf::crypto::OpenSSL::Unique_X509 cert(
        SSL_get_peer_certificate(ssl), /*check_null=*/false);
      if (!cert)
      {
        LOG_TRACE_FMT("Empty peer cert");
        return {};
      }
      ccf::crypto::OpenSSL::Unique_BIO bio;
      if (!i2d_X509_bio(bio, cert))
      {
        LOG_TRACE_FMT("Can't convert X509 to DER");
        return {};
      }

      // Get the total length of the DER representation
      auto len = BIO_get_mem_data(bio, nullptr);
      if (!len)
      {
        LOG_TRACE_FMT("Null X509 peer cert");
        return {};
      }

      // Get the BIO memory pointer
      BUF_MEM* ptr = nullptr;
      if (!BIO_get_mem_ptr(bio, &ptr))
      {
        LOG_TRACE_FMT("Invalid X509 peer cert");
        return {};
      }

      // Return its contents as a vector
      auto ret = std::vector<uint8_t>(ptr->data, ptr->data + len);
      return ret;
    }
  };
}
