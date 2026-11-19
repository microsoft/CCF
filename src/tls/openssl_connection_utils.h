// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/socket_utils.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <system_error>
#include <uv.h>

namespace ccf::tls::details
{
  struct SocketOptionError
  {
    const char* option = nullptr;
    int error = 0;
  };

  inline std::string get_negotiated_group(SSL* ssl)
  {
    if (SSL_is_init_finished(ssl) != 1)
    {
      throw std::logic_error(
        "Cannot query negotiated TLS group before handshake completion");
    }

    const auto* group_name = SSL_get0_group_name(ssl);
    if (group_name == nullptr)
    {
      throw std::runtime_error("Failed to get negotiated TLS group name");
    }

    return group_name;
  }

  inline std::optional<SocketOptionError> configure_tcp_connection(int fd)
  {
    const auto set_option = [fd](
                              int level,
                              int option,
                              const char* option_name,
                              int value) -> std::optional<SocketOptionError> {
      if (setsockopt(fd, level, option, &value, sizeof(value)) != 0)
      {
        return SocketOptionError{option_name, errno};
      }
      return std::nullopt;
    };

    const int one = 1;
    if (auto error = set_option(IPPROTO_TCP, TCP_NODELAY, "TCP_NODELAY", one))
    {
      return error;
    }
    if (auto error = set_option(SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE", one))
    {
      return error;
    }
    if (auto error = set_option(IPPROTO_TCP, TCP_KEEPIDLE, "TCP_KEEPIDLE", 30))
    {
      return error;
    }
    if (auto error = set_option(IPPROTO_TCP, TCP_KEEPINTVL, "TCP_KEEPINTVL", 1))
    {
      return error;
    }
    return set_option(IPPROTO_TCP, TCP_KEEPCNT, "TCP_KEEPCNT", 10);
  }

  inline std::optional<SocketOptionError> request_tcp_quickack(int fd)
  {
    const int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one)) != 0)
    {
      return SocketOptionError{"TCP_QUICKACK", errno};
    }
    return std::nullopt;
  }

  // Heap-allocate a libuv handle whose lifetime is independent of this
  // server, and close it so that it frees itself.
  //
  // uv_close() is asynchronous: the close callback only runs when the loop
  // next runs, which may be long after the server has been destroyed - or
  // never, if node startup failed before the event loop was entered. If
  // handles were members, destruction would have to block until the loop had
  // drained them, which in turn would force the server to drive the loop
  // itself. Owning each handle separately means shutdown is fire-and-forget:
  // request the close, drop the handle, and let the loop reclaim it whenever
  // it next runs.
  //
  // Nothing dereferences handle->data after uv_close(), because libuv
  // guarantees no further callbacks for a handle beyond its close callback,
  // and that callback does nothing but free the handle.
  template <typename THandle>
  inline THandle* new_handle()
  {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    return new THandle{};
  }

  template <typename THandle>
  inline void close_handle(THandle*& handle)
  {
    if (handle == nullptr)
    {
      return;
    }
    auto* as_handle = reinterpret_cast<uv_handle_t*>(handle);
    handle = nullptr;
    if (uv_is_closing(as_handle) != 0)
    {
      return;
    }
    uv_close(as_handle, [](uv_handle_t* h) {
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      delete reinterpret_cast<THandle*>(h);
    });
  }

  inline bool set_user_timeout(
    int fd, std::optional<std::chrono::milliseconds> timeout)
  {
    if (!timeout.has_value())
    {
      return true;
    }

    const auto value = static_cast<unsigned int>(timeout->count());
    if (
      setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, sizeof(value)) == 0)
    {
      return true;
    }
    LOG_FAIL_FMT(
      "setsockopt(TCP_USER_TIMEOUT) failed: {}",
      std::generic_category().message(errno));
    return false;
  }

  inline void validate_user_timeout(
    std::optional<std::chrono::milliseconds> timeout)
  {
    if (
      timeout &&
      (timeout->count() <= 0 ||
       static_cast<uint64_t>(timeout->count()) >
         std::numeric_limits<unsigned int>::max()))
    {
      throw std::invalid_argument(
        "TCP user timeout must fit a positive uint32");
    }
  }

}
