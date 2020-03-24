// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#ifdef USE_NLJSON_KV_SERIALISER
#  include "kv/nljson_serialise.h"
#else
#  include "kv/msg_pack_serialise.h"
#endif
