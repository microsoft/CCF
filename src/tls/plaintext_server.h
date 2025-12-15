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
    void set_bio(
      void* cb_obj, BIO_callback_fn_ex send, BIO_callback_fn_ex recv) override
    {
      // Read/Write BIOs will be used by TLS
      BIO_set_mem_eof_return(read_bio, -1);
      BIO_set_callback_arg(read_bio, static_cast<char*>(cb_obj));
      BIO_set_callback_ex(read_bio, recv);

      BIO_set_mem_eof_return(write_bio, -1);
      BIO_set_callback_arg(write_bio, static_cast<char*>(cb_obj));
      BIO_set_callback_ex(write_bio, send);
    }

    int handshake() override
    {
      return 0;
    }

    int read(uint8_t* buf, size_t len) override
    {
      if (len == 0)
      {
        return 0;
      }
      size_t readbytes = 0;
      int rc = BIO_read_ex(read_bio, buf, len, &readbytes);
      if (rc > 0)
      {
        return readbytes;
      }
      return -rc;
    }

    int write(const uint8_t* buf, size_t len) override
    {
      if (len == 0)
      {
        return 0;
      }
      size_t written = 0;
      int rc = BIO_write_ex(write_bio, buf, len, &written);
      if (rc > 0)
      {
        return written;
      }
      return -rc;
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