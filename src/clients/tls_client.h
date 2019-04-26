// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/buffer.h"
#include "../tls/ca.h"
#include "../tls/cert.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <string>
#include <vector>

class TlsClient
{
private:
  std::string host;
  std::string port;
  std::string sni;
  std::shared_ptr<tls::CA> node_ca;
  std::shared_ptr<tls::Cert> cert;

  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;

public:
  TlsClient(
    const std::string& host,
    const std::string& port,
    const std::string& sni = "users",
    std::shared_ptr<tls::CA> node_ca = nullptr,
    std::shared_ptr<tls::Cert> cert = nullptr) :
    host(host),
    port(port),
    sni(sni),
    node_ca(node_ca),
    cert(cert)
  {
    connect();
  }

  virtual ~TlsClient()
  {
    disconnect();
  }

  void connect()
  {
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    auto err = mbedtls_ctr_drbg_seed(
      &ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    if (err)
      throw str_err(err);

    err = mbedtls_net_connect(
      &server_fd, host.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP);
    if (err)
      throw str_err(err);

    err = mbedtls_ssl_config_defaults(
      &conf,
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT);
    if (err)
      throw str_err(err);

    if (cert != nullptr)
      cert->use(&ssl, &conf);
    if (node_ca != nullptr)
      node_ca->use(&conf);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    err = mbedtls_ssl_setup(&ssl, &conf);
    if (err)
      throw str_err(err);

    err = mbedtls_ssl_set_hostname(&ssl, sni.c_str());
    if (err)
      throw str_err(err);

    mbedtls_ssl_set_bio(
      &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    while (true)
    {
      err = mbedtls_ssl_handshake(&ssl);
      if (err == 0)
        break;
      if (
        (err != MBEDTLS_ERR_SSL_WANT_READ) &&
        (err != MBEDTLS_ERR_SSL_WANT_WRITE))
        throw str_err(err);
    }
  }

  void disconnect()
  {
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
  }

  auto get_ciphersuite_name()
  {
    return mbedtls_ssl_get_ciphersuite(&ssl);
  }

  void write(CBuffer b)
  {
    for (size_t written = 0; written < b.n;)
    {
      auto ret = mbedtls_ssl_write(&ssl, b.p + written, b.n - written);
      if (ret > 0)
        written += ret;
      else
        throw str_err(ret);
    }
  }

  void read(Buffer b)
  {
    for (size_t read = 0; read < b.n;)
    {
      auto ret = mbedtls_ssl_read(&ssl, b.p + read, b.n - read);
      if (ret > 0)
        read += ret;
      else if (ret == 0)
        throw std::logic_error("Underlying transport closed");
      else
        throw str_err(ret);
    }
  }

  bool read_non_blocking(Buffer b)
  {
    if (mbedtls_ssl_get_bytes_avail(&ssl) < b.n)
      return false;
    read(b);
    return true;
  }

private:
  std::logic_error str_err(int err)
  {
    constexpr auto buf_len = 100;
    char buf[buf_len];
    mbedtls_strerror(err, buf, buf_len);
    return std::logic_error(buf);
  }
};
