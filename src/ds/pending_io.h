// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

/**
 * @brief Pending writes on both host and enclave, with data, length and
 * destination address.
 *
 * @tparam T `uv_write_t` for TCP and `uv_udp_send_t` for UDP send,
 * `uint8_t` for receive.
 *
 * The free_cb is called on destruction to free the request.
 */
template <class T>
struct PendingIO
{
  using free_cb_t = void (*)(T*);
  T* req;
  size_t len;
  sockaddr addr;
  free_cb_t free_cb;
  bool clear;

  PendingIO(
    T* req_, size_t len_, sockaddr addr_, free_cb_t free_cb_ = nullptr) :
    req(req_),
    len(len_),
    addr(addr_),
    free_cb(free_cb_),
    clear(false)
  {
    if (free_cb == nullptr)
    {
      // Assume we take ownership
      auto orig = req;
      req = new T[len];
      memcpy(req, orig, len);
    }
  }

  PendingIO(PendingIO&& that) :
    req(that.req),
    len(that.len),
    addr(that.addr),
    free_cb(that.free_cb),
    clear(that.clear)
  {
    that.req = nullptr;
  }

  PendingIO<T>& operator=(PendingIO&& that)
  {
    req = std::move(that.req);
    len = std::move(that.len);
    addr = std::move(that.addr);
    free_cb = std::move(that.free_cb);
    clear = std::move(that.clear);
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

  /**
   * @brief Clears a list of PendingIO<T> of all elements that were marked
   * to remove (clear flag == true).
   */
  static void clear_empty(std::vector<PendingIO<T>>& list)
  {
    std::remove_if(
      list.begin(), list.end(), [](PendingIO<T>& p) { return p.clear; });
  }
};
