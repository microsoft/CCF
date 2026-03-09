// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"

#include <unordered_set>
#include <uv.h>

namespace asynchost
{
  static std::unordered_set<uv_getaddrinfo_t*> pending_resolve_requests;
  static ccf::pal::Mutex pending_resolve_requests_mtx;

  class DNS
  {
  public:
    static bool resolve(
      const std::string& host_,
      const std::string& service,
      void* ud,
      uv_getaddrinfo_cb cb,
      bool async)
    {
      struct addrinfo hints;
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_flags = 0;

      auto resolver = new uv_getaddrinfo_t;
      resolver->data = ud;

      std::string host =
        (host_.starts_with("[") && host_.ends_with("]") ?
           host_.substr(1, host_.size() - 2) :
           host_);

      int rc;

      if (async)
      {
        {
          std::unique_lock<ccf::pal::Mutex> guard(pending_resolve_requests_mtx);
          pending_resolve_requests.insert(resolver);
        }

        if (
          (rc = uv_getaddrinfo(
             uv_default_loop(),
             resolver,
             cb,
             host.c_str(),
             service.c_str(),
             &hints)) < 0)
        {
          LOG_FAIL_FMT(
            "uv_getaddrinfo for host:service [{}:{}] failed (async) with error "
            "{}",
            host,
            service,
            uv_strerror(rc));
          {
            std::unique_lock<ccf::pal::Mutex> guard(
              pending_resolve_requests_mtx);
            pending_resolve_requests.erase(resolver);
          }
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
          LOG_FAIL_FMT(
            "uv_getaddrinfo for host:service [{}:{}] failed with error {}",
            host,
            service,
            uv_strerror(rc));
          delete resolver;
          return false;
        }

        cb(resolver, rc, &hints);
      }

      return true;
    }
  };
}
