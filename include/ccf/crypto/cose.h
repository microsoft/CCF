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

  /**
   * Set the unprotected header of a COSE_Sign1 message, to a map containing
   * @p key and depending on the value of @p position, either an array
   * containing
   * @p value, or a map with key @p subkey and value @p value.
   *
   * Useful to add a proof to a signature to turn it into a receipt, or to
   * add a receipt to a signed statement to turn it into a transparent
   * statement.
   *
   * @param cose_input The COSE_Sign1 message to edit.
   * @param key The key at which to insert either an array or a map.
   * @param position Either InArray or AtKey, to determine whether to insert an
   *                 array or a map.
   * @param value The value to insert either in the array or the map.
   *
   * @return The COSE_Sign1 message with the new unprotected header.
   */
  std::vector<uint8_t> set_unprotected_header(
    const std::span<const uint8_t>& cose_input,
    int64_t key,
    pos::Type position,
    const std::vector<uint8_t> value);
}