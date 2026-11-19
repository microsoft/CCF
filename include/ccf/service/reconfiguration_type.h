// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#warning \
  "ccf/service/reconfiguration_type.h is deprecated and will be removed in 8.0; use ccf/reconfiguration_type.h instead"

// This header is kept for source compatibility only. ReconfigurationType is
// unchanged and remains in namespace ccf, but is now declared in
// ccf/reconfiguration_type.h, so that it can be used without depending on
// service definitions.
#include "ccf/reconfiguration_type.h"
