// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/buffer.h"
#include "../tls/ca.h"
#include "../tls/cert.h"
#include "../tls/error_string.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <vector>

class TlsClient
{
private:
  std::string host;
  std::string port;
  std::shared_ptr<tls::CA> node_ca;
  std::shared_ptr<tls::Cert> cert;
  bool connected = false;

  mbedtls::NetContext server_fd;
  mbedtls::Entropy entropy;
  mbedtls::CtrDrbg ctr_drbg;
  mbedtls::SSLContext ssl;
  mbedtls::SSLConfig conf;

  void init()
  {
    auto tmp_server_fd = mbedtls::make_unique<mbedtls::NetContext>();
    auto tmp_entropy = mbedtls::make_unique<mbedtls::Entropy>();
    auto tmp_ctr_drbg = mbedtls::make_unique<mbedtls::CtrDrbg>();
    auto tmp_ssl = mbedtls::make_unique<mbedtls::SSLContext>();
    auto tmp_conf = mbedtls::make_unique<mbedtls::SSLConfig>();

    auto err = mbedtls_ctr_drbg_seed(
      tmp_ctr_drbg.get(), mbedtls_entropy_func, tmp_entropy.get(), nullptr, 0);
    if (err)
      throw std::logic_error(tls::error_string(err));

    err = mbedtls_net_connect(
      tmp_server_fd.get(), host.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP);
    if (err)
      throw std::logic_error(tls::error_string(err));

    err = mbedtls_ssl_config_defaults(
      tmp_conf.get(),
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT);
    if (err)
      throw std::logic_error(tls::error_string(err));

    if (cert != nullptr)
      cert->use(tmp_ssl.get(), tmp_conf.get());
    if (node_ca != nullptr)
      node_ca->use(tmp_conf.get());

    mbedtls_ssl_conf_rng(
      tmp_conf.get(), mbedtls_ctr_drbg_random, tmp_ctr_drbg.get());
    mbedtls_ssl_conf_authmode(tmp_conf.get(), MBEDTLS_SSL_VERIFY_REQUIRED);

    err = mbedtls_ssl_setup(tmp_ssl.get(), tmp_conf.get());
    if (err)
      throw std::logic_error(tls::error_string(err));

    if (err)
      throw std::logic_error(tls::error_string(err));

    mbedtls_ssl_set_bio(
      tmp_ssl.get(),
      tmp_server_fd.get(),
      mbedtls_net_send,
      mbedtls_net_recv,
      nullptr);

    while (true)
    {
      err = mbedtls_ssl_handshake(tmp_ssl.get());
      if (err == 0)
        break;
      if (
        (err != MBEDTLS_ERR_SSL_WANT_READ) &&
        (err != MBEDTLS_ERR_SSL_WANT_WRITE))
        throw std::logic_error(tls::error_string(err));
    }
    connected = true;

    server_fd = std::move(tmp_server_fd);
    entropy = std::move(tmp_entropy);
    ctr_drbg = std::move(tmp_ctr_drbg);
    ssl = std::move(tmp_ssl);
    conf = std::move(tmp_conf);
  }

public:
  TlsClient(
    const std::string& host,
    const std::string& port,
    std::shared_ptr<tls::CA> node_ca = nullptr,
    std::shared_ptr<tls::Cert> cert = nullptr) :
    host(host),
    port(port),
    node_ca(node_ca),
    cert(cert)
  {
    init();
  }

  TlsClient(const TlsClient& c) :
    host(c.host),
    port(c.port),
    node_ca(c.node_ca),
    cert(c.cert)
  {
    init();
  }

  virtual ~TlsClient()
  {
    // Signal the end of the connection
    if (connected)
      mbedtls_ssl_close_notify(ssl.get());
  }

  auto get_ciphersuite_name()
  {
    return mbedtls_ssl_get_ciphersuite(ssl.get());
  }

  void write(CBuffer b)
  {
    for (size_t written = 0; written < b.n;)
    {
      auto ret = mbedtls_ssl_write(ssl.get(), b.p + written, b.n - written);
      if (ret > 0)
        written += ret;
      else
        throw std::logic_error(tls::error_string(ret));
    }
  }

  std::vector<uint8_t> read(size_t read_size)
  {
    std::vector<uint8_t> buf(read_size);
    auto ret = mbedtls_ssl_read(ssl.get(), buf.data(), buf.size());
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
      throw std::logic_error(tls::error_string(ret));
    }

    return buf;
  }

  bool bytes_available()
  {
    return mbedtls_ssl_get_bytes_avail(ssl.get()) > 0;
  }

  std::vector<uint8_t> read_all()
  {
    constexpr auto read_size = 4096;
    std::vector<uint8_t> buf(read_size);
    auto ret = mbedtls_ssl_read(ssl.get(), buf.data(), buf.size());
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
      throw std::logic_error(tls::error_string(ret));
    }

    return buf;
  }

  void set_tcp_nodelay(bool on)
  {
    int option = on ? 1 : 0;
    setsockopt(
      server_fd->fd, IPPROTO_TCP, TCP_NODELAY, (char*)&option, sizeof(int));
  }
};
