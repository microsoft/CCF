// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/nonstd.h"

#include <atomic>
#include <charconv>
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <memory>
#include <random>
#include <string>
#include <vector>

using SerialisedAction = std::string;
using SerialisedResponse = std::string;

size_t id_from_string(const std::string_view& sv)
{
  size_t n_id;
  const auto [p, ec] = std::from_chars(sv.begin(), sv.end(), n_id);
  REQUIRE(ec == std::errc());
  return n_id;
}

struct IAction
{
  virtual ~IAction() = default;

  virtual SerialisedAction serialise() const = 0;
  virtual void verify_serialised_response(
    SerialisedResponse& response) const = 0;

  virtual SerialisedResponse do_action() const = 0;
};

using ActionPtr = std::unique_ptr<IAction>;

static std::atomic<size_t> action_id_generator = 0;
struct OrderedAction : public IAction
{
  const size_t id;

  OrderedAction() : id(++action_id_generator) {}
  OrderedAction(size_t _id) : id(_id) {}

  SerialisedAction serialise() const override
  {
    return fmt::format("{}|", id);
  }

  void verify_serialised_response(SerialisedResponse& response) const override
  {
    auto [s_id, remainder] = ccf::nonstd::split_1(response, "|");
    size_t n_id = id_from_string(s_id);
    REQUIRE(id == n_id);

    response = remainder;
  }

  SerialisedResponse do_action() const override
  {
    return fmt::format("{}|", id);
  }
};

struct SignAction : public OrderedAction
{
  const std::vector<uint8_t> tbs;

  static std::vector<uint8_t> generate_random_data()
  {
    auto len = rand() % 100;
    std::vector<uint8_t> data(len);
    for (auto& n : data)
    {
      n = rand();
    }
    return data;
  }

  SignAction() : OrderedAction(), tbs(generate_random_data())
  {
    LOG_DEBUG_FMT("Created a new SignAction id={}", id);
  }
  SignAction(size_t _id, const std::vector<uint8_t>& _tbs) :
    OrderedAction(_id),
    tbs(_tbs)
  {}

  SerialisedAction serialise() const override
  {
    return fmt::format(
      "{}SIGN|{}", OrderedAction::serialise(), ccf::ds::to_hex(tbs));
  }

  void verify_serialised_response(SerialisedResponse& response) const override
  {
    LOG_DEBUG_FMT("Verifying a signature, for action id={}", id);
    OrderedAction::verify_serialised_response(response);

    auto [a, b] = ccf::nonstd::split_1(response, "|");

    if (a == "FAILED")
    {
      // auto reason = b;
    }
    else
    {
      auto key_s = a;
      auto signature_s = b;

      ccf::crypto::Pem pem{std::string(key_s)};
      auto pubk = ccf::crypto::make_public_key(pem);

      auto signature = ccf::ds::from_hex(std::string(signature_s));
      REQUIRE(pubk->verify(tbs, signature));
    }
  }

  SerialisedResponse do_action() const override
  {
    LOG_DEBUG_FMT("Signing something a client gave me, id={}", id);

    // Randomly fail some small fraction of requests
    if (rand() % 50 == 0)
    {
      return fmt::format(
        "{}FAILED|Randomly unlucky", OrderedAction::do_action());
    }
    else
    {
      auto key_pair = ccf::crypto::make_key_pair();
      auto signature = key_pair->sign(tbs);
      return fmt::format(
        "{}{}|{}",
        OrderedAction::do_action(),
        key_pair->public_key_pem().str(),
        ccf::ds::to_hex(signature));
    }
  }
};

ActionPtr deserialise_action(const SerialisedAction& ser)
{
  const auto components = ccf::nonstd::split(ser, "|");

  REQUIRE(components.size() >= 1);

  const auto id = id_from_string(components[0]);

  if (components.size() == 3)
  {
    if (components[1] == "SIGN")
    {
      const auto tbs = ccf::ds::from_hex(std::string(components[2]));
      return std::make_unique<SignAction>(id, tbs);
    }
  }

  throw std::logic_error(fmt::format("Unknown action: {}", ser));
}