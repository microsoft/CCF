// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef TLS_PROVIDER_IS_MBEDTLS
#  include "mbedtls/cert.h"
#else
#  include "openssl/cert.h"
#endif
