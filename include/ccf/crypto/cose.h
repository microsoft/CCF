// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
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
      /// @brief  The key at which to insert the value.
      int64_t key;
    };

    using Type = std::variant<InArray, AtKey>;
  }

  namespace desc
  {
    struct Empty
    {};

    struct Value
    {
      pos::Type position;
      int64_t key;
      const std::vector<uint8_t>& value;
    };

    using Type = std::variant<Empty, Value>;
  }

  /**
   * Set the unprotected header of a COSE_Sign1 message, according to a
   * descriptor.
   *
   * Useful to add a proof to a signature to turn it into a receipt, to
   * add a receipt to a signed statement to turn it into a transparent
   * statement, or simply to strip the unprotected header from a COSE Sign1.
   *
   * @param cose_input The COSE_Sign1 message to edit.
   * @param descriptor An object describing whether and how to set the
   * unprotected header.
   */
  std::vector<uint8_t> set_unprotected_header(
    const std::span<const uint8_t>& cose_input, const desc::Type& descriptor);
}