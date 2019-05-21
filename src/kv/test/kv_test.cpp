// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../../ds/logger.h"
#include "../../enclave/appinterface.h"
#include "../../node/encryptor.h"
#include "../kv.h"
#include "../kvserialiser.h"
#include "../node/history.h"
#include "../replicator.h"

#include <doctest/doctest.h>
#include <msgpack-c/msgpack.hpp>
#include <string>
#include <vector>

