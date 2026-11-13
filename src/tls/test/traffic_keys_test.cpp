// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tls/traffic_keys.h"

#include <array>
#include <doctest/doctest.h>

namespace
{
  TEST_CASE("Sending traffic keys count encrypted records, not messages")
  {
    ccf::tls::TrafficKeys keys({.record_budget = 4});
    const uint8_t application = SSL3_RT_APPLICATION_DATA;
    const auto record = [&](int writing) {
      ccf::tls::TrafficKeys::observe(
        writing,
        TLS1_3_VERSION,
        SSL3_RT_INNER_CONTENT_TYPE,
        &application,
        1,
        nullptr,
        &keys);
    };
    for (size_t handshake = 0; handshake < 10; ++handshake)
    {
      record(1);
    }
    keys.start();
    for (size_t incoming = 0; incoming < 10; ++incoming)
    {
      record(0);
    }
    for (size_t message = 0; message < 10; ++message)
    {
      ccf::tls::TrafficKeys::observe(
        1, TLS1_3_VERSION, SSL3_RT_HANDSHAKE, &application, 1, nullptr, &keys);
    }
    CHECK_FALSE(keys.update_due());
    record(1);
    record(1);
    CHECK_FALSE(keys.update_due());
    record(1);
    CHECK(keys.update_due());
    CHECK_FALSE(keys.failed());
  }

  TEST_CASE("Sending traffic keys charge KeyUpdate to the old key")
  {
    ccf::tls::TrafficKeys keys({.record_budget = 4});
    keys.start();
    const uint8_t type = SSL3_RT_HANDSHAKE;
    const std::array<uint8_t, 5> update{
      SSL3_MT_KEY_UPDATE, 0, 0, 1, SSL_KEY_UPDATE_NOT_REQUESTED};
    for (size_t epoch = 0; epoch < 3; ++epoch)
    {
      for (size_t record = 0; record < 4; ++record)
      {
        ccf::tls::TrafficKeys::observe(
          1,
          TLS1_3_VERSION,
          SSL3_RT_INNER_CONTENT_TYPE,
          &type,
          1,
          nullptr,
          &keys);
      }
      CHECK(keys.update_due());
      CHECK_FALSE(keys.failed());
      ccf::tls::TrafficKeys::observe(
        1,
        TLS1_3_VERSION,
        SSL3_RT_HANDSHAKE,
        update.data(),
        update.size(),
        nullptr,
        &keys);
      CHECK_FALSE(keys.update_due());
    }
    for (size_t record = 0; record < 5; ++record)
    {
      ccf::tls::TrafficKeys::observe(
        1,
        TLS1_3_VERSION,
        SSL3_RT_INNER_CONTENT_TYPE,
        &type,
        1,
        nullptr,
        &keys);
    }
    ccf::tls::TrafficKeys::observe(
      1,
      TLS1_3_VERSION,
      SSL3_RT_HANDSHAKE,
      update.data(),
      update.size(),
      nullptr,
      &keys);
    CHECK(keys.failed());
  }
}
