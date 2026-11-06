// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tls/traffic_keys.h"

#include <array>
#include <doctest/doctest.h>

namespace
{
  using namespace ccf::tls;

  struct Accounting
  {
    TrafficKeys keys{TrafficKeyPolicy{.record_budget = 4}};

    void record(bool writing, uint8_t type = SSL3_RT_APPLICATION_DATA)
    {
      TrafficKeys::observe(
        static_cast<int>(writing),
        TLS1_3_VERSION,
        SSL3_RT_INNER_CONTENT_TYPE,
        &type,
        1,
        nullptr,
        &keys);
    }

    void update(bool writing)
    {
      record(writing, SSL3_RT_HANDSHAKE);
      const std::array<uint8_t, 5> message{
        SSL3_MT_KEY_UPDATE, 0, 0, 1, SSL_KEY_UPDATE_NOT_REQUESTED};
      TrafficKeys::observe(
        static_cast<int>(writing),
        TLS1_3_VERSION,
        SSL3_RT_HANDSHAKE,
        message.data(),
        message.size(),
        nullptr,
        &keys);
    }
  };

  TEST_CASE("Traffic-key accounting starts after the initial handshake")
  {
    Accounting accounting;
    for (size_t record = 0; record < 10; ++record)
    {
      accounting.record(true, SSL3_RT_HANDSHAKE);
      accounting.record(false, SSL3_RT_HANDSHAKE);
    }
    CHECK_FALSE(accounting.keys.failed());
    CHECK_FALSE(accounting.keys.update_due());
    accounting.keys.start();
    accounting.record(true);
    accounting.record(true);
    CHECK_FALSE(accounting.keys.update_due());
    accounting.record(true);
    CHECK(accounting.keys.update_due());
  }

  TEST_CASE(
    "Traffic-key accounting treats directions and key epochs separately")
  {
    Accounting accounting;
    accounting.keys.start();
    for (size_t epoch = 0; epoch < 3; ++epoch)
    {
      accounting.record(true);
      accounting.record(true, SSL3_RT_HANDSHAKE);
      accounting.record(true, SSL3_RT_ALERT);
      CHECK(accounting.keys.update_due());
      accounting.update(false);
      CHECK(accounting.keys.update_due());
      accounting.update(true);
      CHECK_FALSE(accounting.keys.update_due());
      CHECK_FALSE(accounting.keys.failed());
    }
  }

  TEST_CASE("Traffic-key accounting charges KeyUpdate to the old key")
  {
    for (const bool writing : {false, true})
    {
      Accounting accounting;
      accounting.keys.start();
      for (size_t record = 0; record < 4; ++record)
      {
        accounting.record(writing);
      }
      CHECK_FALSE(accounting.keys.failed());
      accounting.update(writing);
      CHECK(accounting.keys.failed());
      accounting.update(writing);
      CHECK(accounting.keys.failed());
    }
  }

  TEST_CASE(
    "Traffic-key accounting ignores message and record-header callbacks")
  {
    Accounting accounting;
    accounting.keys.start();
    const uint8_t byte = 0;
    for (size_t message = 0; message < 10; ++message)
    {
      TrafficKeys::observe(
        1, TLS1_3_VERSION, SSL3_RT_HEADER, &byte, 1, nullptr, &accounting.keys);
      TrafficKeys::observe(
        1,
        TLS1_3_VERSION,
        SSL3_RT_HANDSHAKE,
        &byte,
        1,
        nullptr,
        &accounting.keys);
    }
    CHECK_FALSE(accounting.keys.update_due());
    CHECK_FALSE(accounting.keys.failed());
  }

  TEST_CASE("Traffic-key accounting counts received handshake messages")
  {
    Accounting accounting;
    const std::array<uint8_t, 8> ticket{SSL3_MT_NEWSESSION_TICKET, 0, 0, 4};
    const auto message = [&](bool writing) {
      TrafficKeys::observe(
        static_cast<int>(writing),
        TLS1_3_VERSION,
        SSL3_RT_HANDSHAKE,
        ticket.data(),
        ticket.size(),
        nullptr,
        &accounting.keys);
    };
    message(false);
    CHECK(accounting.keys.handshake_messages_received() == 0);
    accounting.keys.start();
    message(true);
    accounting.record(false, SSL3_RT_HANDSHAKE);
    accounting.record(false);
    CHECK(accounting.keys.handshake_messages_received() == 0);
    message(false);
    accounting.update(false);
    CHECK(accounting.keys.handshake_messages_received() == 2);
  }
}
