// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <msgpack.hpp>

namespace ccf
{
  enum class CodeStatus
  {
    ACCEPTED = 0,
    RETIRED = 1,
    // not to be used
    UNKNOWN
  };
}

MSGPACK_ADD_ENUM(ccf::CodeStatus);

namespace ccf
{
  using CodeIDs = Store::Map<CodeDigest, CodeStatus>;

#ifdef GET_QUOTE

  CodeDigest get_digest_from_parsed_quote(oe_report_t& parsed_quote)
  {
    CodeDigest ret;
    std::copy(
      std::begin(parsed_quote.identity.unique_id),
      std::end(parsed_quote.identity.unique_id),
      ret.begin());
    return ret;
  }
#endif
}
