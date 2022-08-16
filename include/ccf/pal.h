// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"

#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include "ccf/crypto/pem.h"
#  include "ccf/crypto/verifier.h"
#  include "ccf/pal/attestation_sev_snp.h"
#  include "crypto/ecdsa.h"

#  include <cstring>
#else
#  include "ccf/ds/ccf_exception.h"
#  include "ccf/pal/attestation_sgx.h"

#  include <openenclave/advanced/mallinfo.h>
#  include <openenclave/bits/defs.h>
#  include <pthread.h>
#endif

/**
 * This file implements a platform abstraction layer to enable platforms, such
 * as OpenEnclave to offer custom implementations for certain functionalities.
 * By centralizing the platform-specific code to one file, we can avoid exposing
 * platform-specific types to the rest of the code and have a good overview of
 * all the functionality that is custom to a given platform. The platform
 * abstraction layer can also be used in code shared between the host and the
 * enclave as there is a host implementation for it as well.
 */
namespace ccf::pal
{
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

#else
#endif

}