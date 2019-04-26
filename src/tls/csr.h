// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls.h"

#include <stdint.h>
#include <string>
#include <vector>

namespace tls
{
  struct Csr
  {
    mbedtls_x509write_csr req;

    Csr()
    {
      mbedtls_x509write_csr_init(&req);
      mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA512);
    }

    ~Csr()
    {
      mbedtls_x509write_csr_free(&req);
    }
  };
}
