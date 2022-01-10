// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef TLS_PROVIDER_IS_MBEDTLS
#  include "mbedtls/ca.h"
#else
#  include "openssl/ca.h"
#endif
