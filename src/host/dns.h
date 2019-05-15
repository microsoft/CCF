// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/logger.h"

#include <uv.h>

namespace asynchost
{
  class DNS
  {
  public:
    static bool resolve(
      const std::string& host,
      const std::string& service,
      void* ud,
      uv_getaddrinfo_cb cb,
      bool async)
    {
      struct addrinfo hints;
      hints.ai_family = PF_INET;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_flags = 0;

      auto resolver = new uv_getaddrinfo_t;
      resolver->data = ud;

      int rc;

      if (async)
      {
        if (
          (rc = uv_getaddrinfo(
             uv_default_loop(),
             resolver,
             cb,
             host.c_str(),
             service.c_str(),
             &hints)) < 0)
        {
          LOG_FAIL << "uv_getaddrinfo failed: " << uv_strerror(rc) << std::endl;
          delete resolver;
          return false;
        }
      }
      else
      {
        if (
          (rc = uv_getaddrinfo(
             uv_default_loop(),
             resolver,
             nullptr,
             host.c_str(),
             service.c_str(),
             &hints)) < 0)
        {
          LOG_FAIL << "uv_getaddrinfo failed: " << uv_strerror(rc) << std::endl;
          delete resolver;
          return false;
        }

        cb(resolver, rc, &hints);
      }

      return true;
    }
  };
}
