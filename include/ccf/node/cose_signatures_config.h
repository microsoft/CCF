// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#warning \
  "ccf/node/cose_signatures_config.h is deprecated and will be removed in 8.0; use ccf/cose_signatures_config.h instead"

// This header is kept for source compatibility only. COSESignaturesConfig is
// unchanged and remains in namespace ccf, but is now declared in
// ccf/cose_signatures_config.h, so that it can be used without depending on
// node configuration.
#include "ccf/cose_signatures_config.h"
