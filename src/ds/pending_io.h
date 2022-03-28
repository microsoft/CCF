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

  PendingIO(T* req, size_t len, sockaddr addr, free_cb_t free_cb = nullptr) :
    req(req),
    len(len),
    addr(addr),
    free_cb(free_cb),
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
      free(req);
    }
  }

  /**
   * @brief Erases part or all of the buffer stored. Used after the buffer was
   * partially extracted.
   *
   * Only works for pointers to array of objects (ex. uint8_t*). If the object
   * stored has its own buffer (ex. uv_write_t and uv_udp_send_t), then the
   * erase has to be done elsewhere.
   *
   * @param amount The amount, from the begining, to remove.
   */
  void erase(size_t amount)
  {
    // Erase all, just mark for deletion
    if (amount >= len)
    {
      clear = true;
      return;
    }

    // Erase part of, realloc
    clear = false;
    auto orig = req;
    req = new T[len - amount];
    memcpy(req, orig + amount, len - amount);
    free(orig);
  }

  /**
   * @brief Clears a list of PendingIO<T> of all elements that were marked
   * to remove (clear flag == true).
   */
  static auto clear_empty(std::vector<PendingIO<T>>& list)
  {
    auto begin = list.begin();
    auto end = list.end();
    auto it = begin;

    while (it != end)
    {
      if (it->clear)
      {
        *it = std::move(*begin);
        ++it;
      }
      ++begin;
    }
    return it;
  }
};
