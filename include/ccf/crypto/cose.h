// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <variant>
#include <vector>

namespace ccf::cose::edit
{
  namespace pos
  {
    struct InArray
    {};

    struct AtKey
    {
      ssize_t key;
    };

    using Type = std::variant<InArray, AtKey>;
  }

  /**
   * Set the unprotected header of a COSE_Sign1 message, to a map containing
   * \key and depending on the value of \position, either an array containing
   * \value, or a map with key \subkey and value \value.
   *
   * Useful to add a proof to a signature to turn it into a receipt, or to
   * add a receipt to a signed statement to turn it into a transparent
   * statement.
   */
  std::vector<uint8_t> set_unprotected_header(
    const std::span<const uint8_t>& buf_,
    ssize_t key,
    pos::Type position,
    const std::vector<uint8_t> value);
}