// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstring>
#include <utility>

/**
 * @brief Pending TCP writes with a request and its byte length.
 *
 * @tparam T `uv_write_t` for TCP send.
 *
 * The free_cb is called on destruction to free the request.
 */
template <class T>
struct PendingIO
{
  using free_cb_t = void (*)(T*);
  T* req;
  size_t len;
  free_cb_t free_cb;

  PendingIO(T* req_, size_t len_, free_cb_t free_cb_ = nullptr) :
    req(req_),
    len(len_),
    free_cb(free_cb_)
  {
    if (free_cb == nullptr)
    {
      // Assume we take ownership
      auto orig = req;
      req = new T[len]; // NOLINT(cppcoreguidelines-owning-memory)
      memcpy(req, orig, len);
    }
  }

  PendingIO(PendingIO&& that) noexcept :
    req(that.req),
    len(that.len),
    free_cb(that.free_cb)
  {
    that.req = nullptr;
  }

  PendingIO<T>& operator=(PendingIO&& that) noexcept
  {
    req = std::move(that.req);
    len = std::move(that.len);
    free_cb = std::move(that.free_cb);
    that.req = nullptr;
    return *this;
  }

  ~PendingIO()
  {
    if (free_cb)
    {
      free_cb(req);
    }
    else
    {
      delete[] req;
    }
  }
};
