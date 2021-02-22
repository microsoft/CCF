// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <msgpack/msgpack.hpp>
#include <string>

namespace crypto
{
  struct SubjectAltName
  {
    std::string san;
    bool is_ip;

    MSGPACK_DEFINE(san, is_ip);
  };
}
