// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "context.h"

namespace nontls
{
  class PlaintextServer : public ccf::tls::Context
  {
  public:
    PlaintextServer() : Context(false) {}

  protected:
    Unique_BIO read_bio;
    Unique_BIO write_bio;

  public:
    void set_bio() override
    {
      // Plaintext passthrough: the read/write BIOs hold the unencrypted bytes
      // exchanged with the peer directly.
      BIO_set_mem_eof_return(read_bio, -1);
      BIO_set_mem_eof_return(write_bio, -1);
    }

    void recv(const uint8_t* buf, size_t len) override
    {
      BIO_write(read_bio, buf, len);
    }

    size_t pending_write() override
    {
      return BIO_pending(write_bio);
    }

    size_t send(uint8_t* buf, size_t len) override
    {
      int rc = BIO_read(write_bio, buf, len);
      return rc < 0 ? 0 : static_cast<size_t>(rc);
    }

    int handshake() override
    {
      return 0;
    }

    int read(uint8_t* buf, size_t len, size_t& readbytes) override
    {
      readbytes = 0;
      if (len == 0)
      {
        return 0;
      }
      int rc = BIO_read_ex(read_bio, buf, len, &readbytes);
      if (rc > 0)
      {
        return 0;
      }
      return SSL_ERROR_WANT_READ;
    }

    int write(const uint8_t* buf, size_t len, size_t& written) override
    {
      written = 0;
      if (len == 0)
      {
        return 0;
      }
      int rc = BIO_write_ex(write_bio, buf, len, &written);
      if (rc > 0)
      {
        return 0;
      }
      return SSL_ERROR_WANT_WRITE;
    }

    int close() override
    {
      return 0;
    }

    bool peer_cert_ok() override
    {
      return true;
    }

    std::string get_verify_error() override
    {
      return "no error";
    }

    std::vector<uint8_t> peer_cert() override
    {
      return {};
    }
  };
}