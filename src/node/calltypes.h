// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "enclave/interface.h"

namespace ccf
{
  struct CreateNew
  {
    struct In
    {
      StartType start_type;
      CCFConfig config;
    };
    struct Out
    {
      std::vector<uint8_t> node_cert;
      std::vector<uint8_t> network_cert;
      std::vector<uint8_t> network_enc_pubk;
    };
  };

  struct Join
  {
    struct In
    {
      CCFConfig config;
    };
  };
}
